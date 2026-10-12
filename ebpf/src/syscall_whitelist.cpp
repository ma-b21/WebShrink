#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "generated_syscall_profiles.hpp"

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <grp.h>
#include <pwd.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <dirent.h>

namespace {

struct Config {
    std::string bpf_obj_path;
    std::vector<char *> child_argv;
    double duration_sec = 0.0;
    bool verbose = false;
    std::optional<uint32_t> activate_profile;
    std::optional<std::string> pid_file;
    std::optional<std::string> run_as_user;
    uid_t target_uid = 1000;
    gid_t target_gid = 1000;
    std::optional<std::string> target_home;
};

std::atomic<bool> g_running{true};
std::atomic<bool> g_activate_requested{false};
pid_t g_child_pid = -1;

void handle_signal(int)
{
    g_running.store(false, std::memory_order_relaxed);
    if (g_child_pid > 0) {
        kill(g_child_pid, SIGKILL);
    }
}

void handle_activate_signal(int)
{
    g_activate_requested.store(true, std::memory_order_relaxed);
}

int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

std::optional<Config> parse_args(int argc, char **argv)
{
    Config cfg;
    int i;
    try {
        for (i = 1; i < argc; ++i) {
            const std::string arg(argv[i]);
            if (arg == "--bpf-obj" && i + 1 < argc) {
                cfg.bpf_obj_path = argv[++i];
            } else if (arg == "--duration" && i + 1 < argc) {
                cfg.duration_sec = std::stod(argv[++i]);
            } else if (arg == "--verbose") {
                cfg.verbose = true;
            } else if (arg == "--activate-profile" && i + 1 < argc) {
                unsigned long value = std::stoul(argv[++i]);
                if (value > std::numeric_limits<uint32_t>::max()) {
                    std::cerr << "--activate-profile 超出范围。" << '\n';
                    return std::nullopt;
                }
                cfg.activate_profile = static_cast<uint32_t>(value);
            } else if (arg == "--activate-profile") {
                std::cerr << "--activate-profile 需要紧跟 profile id。" << '\n';
                return std::nullopt;
            } else if (arg == "--pid-file" && i + 1 < argc) {
                cfg.pid_file = argv[++i];
            } else if (arg == "--pid-file") {
                std::cerr << "--pid-file 需要紧跟输出路径。" << '\n';
                return std::nullopt;
            } else if (arg == "--run-as" && i + 1 < argc) {
                cfg.run_as_user = argv[++i];
            } else if (arg == "--run-as") {
                std::cerr << "--run-as 需要紧跟用户名。" << '\n';
                return std::nullopt;
            } else if (arg == "-h" || arg == "--help") {
                std::cout << "用法: syscall_monitor --bpf-obj <path> [--duration 秒] [--verbose] "
                             "[--activate-profile id] [--pid-file path] [--run-as 用户名] -- <命令...>\n";
                return std::nullopt;
            } else if (arg == "--") {
                i++;
                break;
            } else if (arg.rfind('-', 0) == 0) {
                std::cerr << "未知参数: " << arg << '\n';
                return std::nullopt;
            } else {
                // First non-arg is start of command
                break;
            }
        }

        if (i < argc) {
            for (int j = i; j < argc; ++j) {
                cfg.child_argv.push_back(argv[j]);
            }
        }

    } catch (const std::exception &ex) {
        std::cerr << "参数解析失败: " << ex.what() << '\n';
        return std::nullopt;
    }

    if (cfg.bpf_obj_path.empty()) {
        std::cerr << "必须指定 --bpf-obj。\n";
        return std::nullopt;
    }

    if (cfg.child_argv.empty()) {
        std::cerr << "必须指定要执行的命令。\n";
        return std::nullopt;
    }

    if (cfg.run_as_user.has_value()) {
        errno = 0;
        if (passwd *pwd = getpwnam(cfg.run_as_user->c_str()); pwd) {
            cfg.target_uid = pwd->pw_uid;
            cfg.target_gid = pwd->pw_gid;
            if (pwd->pw_dir)
                cfg.target_home = pwd->pw_dir;
        } else {
            std::cerr << "无法解析用户 '" << *cfg.run_as_user << "': " << strerror(errno) << '\n';
            return std::nullopt;
        }
    }

    return cfg;
}

struct profile_key {
    uint32_t profile_id;
    uint32_t syscall_nr;
};

constexpr uint8_t kEnabled = 1;

bool process_alive(pid_t pid)
{
    if (kill(pid, 0) == 0)
        return true;
    if (errno == EPERM)
        return true;
    return false;
}

std::string make_shmem_path(pid_t pid)
{
    // The loader and child use this shared path to locate the same context file.
    return "/tmp/wshrink_" + std::to_string(pid);
}

int decode_bpf_syscall_errno(int ret)
{
    if (ret == -1)
        return errno != 0 ? errno : EIO;
    if (ret < -1)
        return -ret;
    return 0;
}

bool write_pid_file(const std::string &path, pid_t loader_pid)
{
    std::ofstream out(path, std::ios::trunc);
    if (!out)
        return false;
    out << loader_pid << '\n';
    return static_cast<bool>(out);
}

std::optional<uint64_t> read_shmem_array_base_from_maps(pid_t tgid, const std::string &shmem_path)
{
    std::ifstream maps("/proc/" + std::to_string(tgid) + "/maps");
    if (!maps)
        return std::nullopt;

    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(shmem_path) == std::string::npos)
            continue;

        const size_t dash = line.find('-');
        if (dash == std::string::npos)
            continue;

        const std::string start_hex = line.substr(0, dash);
        char *end = nullptr;
        errno = 0;
        const unsigned long long mapping_start = std::strtoull(start_hex.c_str(), &end, 16);
        if (errno != 0 || end == start_hex.c_str())
            continue;

        return static_cast<uint64_t>(mapping_start) + 8;
    }

    return std::nullopt;
}

bool sync_shmem_bases(
    int managed_tgids_fd,
    int shmem_base_fd,
    const std::string &shmem_path,
    bool verbose)
{
    uint32_t current_key = 0;
    uint32_t next_key = 0;
    bool has_key = bpf_map_get_next_key(managed_tgids_fd, nullptr, &next_key) == 0;

    while (has_key) {
        if (const auto base = read_shmem_array_base_from_maps(static_cast<pid_t>(next_key), shmem_path);
            base.has_value()) {
            uint64_t existing = 0;
            const bool had_existing = bpf_map_lookup_elem(shmem_base_fd, &next_key, &existing) == 0;
            if (!had_existing || existing != *base) {
                if (int err = bpf_map_update_elem(shmem_base_fd, &next_key, &*base, BPF_ANY); err) {
                    const int err_no = decode_bpf_syscall_errno(err);
                    std::cerr << "设置 shmem_base 失败 (tgid=" << next_key << "): "
                              << strerror(err_no) << " (errno=" << err_no << ")\n";
                    return false;
                }
                if (verbose) {
                    std::cout << "已同步共享内存地址 tgid=" << next_key
                              << " base=0x" << std::hex << *base << std::dec << std::endl;
                }
            }
        } else {
            bpf_map_delete_elem(shmem_base_fd, &next_key);
        }

        current_key = next_key;
        has_key = bpf_map_get_next_key(managed_tgids_fd, &current_key, &next_key) == 0;
    }

    return true;
}

bool wait_for_shmem_base(
    int managed_tgids_fd,
    int shmem_base_fd,
    uint32_t tgid,
    const std::string &shmem_path,
    bool verbose)
{
    const int max_poll_attempts = 500; // 500 * 10ms = 5 seconds max
    for (int attempt = 0; attempt < max_poll_attempts; ++attempt) {
        if (!sync_shmem_bases(managed_tgids_fd, shmem_base_fd, shmem_path, verbose))
            return false;

        uint64_t base = 0;
        if (bpf_map_lookup_elem(shmem_base_fd, &tgid, &base) == 0 && base != 0)
            return true;

        if (!process_alive(static_cast<pid_t>(tgid)))
            break;

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return false;
}

void clear_u32_keyed_map(int fd)
{
    uint32_t current_key = 0;
    uint32_t next_key = 0;
    bool has_key = bpf_map_get_next_key(fd, nullptr, &next_key) == 0;
    while (has_key) {
        const uint32_t key_to_delete = next_key;
        current_key = next_key;
        has_key = bpf_map_get_next_key(fd, &current_key, &next_key) == 0;
        bpf_map_delete_elem(fd, &key_to_delete);
    }
}

bool activate_profile_floor(
    int managed_tgids_fd,
    int profile_floor_fd,
    uint32_t activation_profile,
    bool verbose)
{
    uint32_t current_key = 0;
    uint32_t next_key = 0;
    bool has_key = bpf_map_get_next_key(managed_tgids_fd, nullptr, &next_key) == 0;
    size_t updated = 0;

    while (has_key) {
        if (int err = bpf_map_update_elem(profile_floor_fd, &next_key, &activation_profile, BPF_ANY); err) {
            const int err_no = decode_bpf_syscall_errno(err);
            std::cerr << "延迟激活 profile floor 失败 (tgid=" << next_key << "): "
                      << strerror(err_no) << " (errno=" << err_no << ")\n";
            return false;
        }
        updated++;
        current_key = next_key;
        has_key = bpf_map_get_next_key(managed_tgids_fd, &current_key, &next_key) == 0;
    }

    if (verbose) {
        std::cout << "已延迟激活 profile floor=" << activation_profile
                  << "，覆盖 " << updated << " 个 managed TGID。" << std::endl;
    }
    return true;
}

} // namespace

int main(int argc, char **argv)
{
    // 增加文件描述符限制，防止因 attach 大量 kprobe 导致 EMFILE
    struct rlimit rlim;
    rlim.rlim_cur = 8192;
    rlim.rlim_max = 8192;
    if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
        // 尝试使用系统最大值
        if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
            rlim.rlim_cur = rlim.rlim_max;
            setrlimit(RLIMIT_NOFILE, &rlim);
        }
    }

    auto cfg_opt = parse_args(argc, argv);
    if (!cfg_opt.has_value())
        return 1;
    const Config cfg = cfg_opt.value();
    int result = 0;

    libbpf_set_print(libbpf_print_fn);
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    std::signal(SIGUSR1, handle_activate_signal);

    pid_t child_pid = fork();
    if (child_pid == -1) {
        std::cerr << "fork 失败: " << strerror(errno) << '\n';
        return 1;
    }

    if (child_pid == 0) { // 子进程
        auto drop_privileges = [&](uid_t uid, gid_t gid) {
            if (cfg.run_as_user.has_value()) {
                if (initgroups(cfg.run_as_user->c_str(), gid) == -1) {
                    std::cerr << "初始化附加用户组失败: " << strerror(errno) << '\n';
                    return false;
                }
            } else {
                if (setgroups(0, nullptr) == -1) {
                    std::cerr << "清空附加用户组失败: " << strerror(errno) << '\n';
                    return false;
                }
            }

            if (setresgid(gid, gid, gid) == -1) {
                std::cerr << "切换 GID 失败: " << strerror(errno) << '\n';
                return false;
            }

            // 仅在子进程中降低权限，保证被监控程序不是 root。
            if (setresuid(uid, uid, uid) == -1) {
                std::cerr << "切换 UID 失败: " << strerror(errno) << '\n';
                return false;
            }
            return true;
        };

        if (!drop_privileges(cfg.target_uid, cfg.target_gid))
            exit(126);

        if (cfg.target_home.has_value()) {
            if (setenv("HOME", cfg.target_home->c_str(), 1) == -1) {
                std::cerr << "设置 HOME 失败: " << strerror(errno) << '\n';
                exit(126);
            }
        }

        if (cfg.verbose) {
            std::cout << "子进程降权: uid=" << getuid()
                      << " euid=" << geteuid()
                      << " gid=" << getgid()
                      << " egid=" << getegid() << std::endl;
            std::cout << "环境变量 HOME="
                      << (getenv("HOME") ? getenv("HOME") : "<unset>")
                      << std::endl;
        }

        // Set shared memory path for fast whitelist switching.
        // The Go runtime will create and mmap this file, then write
        // the array base address to the first 8 bytes.
        {
            std::string shmem_path = make_shmem_path(getpid());
            setenv("WSHRINK_SHMEM_PATH", shmem_path.c_str(), 1);
        }

        raise(SIGSTOP);

        std::vector<char *> child_argv = cfg.child_argv;
        child_argv.push_back(nullptr);
        execvp(child_argv[0], child_argv.data());
        // execvp 只有在出错时才会返回
        std::cerr << "执行 " << child_argv[0] << " 失败: " << strerror(errno) << '\n';
        exit(127);
    }

    // 父进程
    g_child_pid = child_pid;
    if (cfg.verbose) {
        std::cout << "已创建子进程，PID: " << child_pid << std::endl;
    }
    if (cfg.pid_file.has_value() && !write_pid_file(*cfg.pid_file, getpid())) {
        std::cerr << "写入 pid 文件失败: " << *cfg.pid_file << '\n';
        kill(child_pid, SIGKILL);
        return 1;
    }

    bpf_object *obj = bpf_object__open_file(cfg.bpf_obj_path.c_str(), nullptr);
    if (!obj) {
        std::cerr << "无法打开 BPF 对象文件: " << cfg.bpf_obj_path << '\n';
        kill(child_pid, SIGKILL);
        return 1;
    }

    if (int err = bpf_object__load(obj); err) {
        std::cerr << "加载 BPF 对象失败: " << strerror(-err) << '\n';
        bpf_object__close(obj);
        kill(child_pid, SIGKILL);
        return 1;
    }

    std::vector<bpf_link *> links;
    bpf_program *prog = nullptr;
    bpf_object__for_each_program(prog, obj) {
        const char *sec = bpf_program__section_name(prog);
        if (!sec)
            continue;

        bpf_link *link = nullptr;
        if (std::strncmp(sec, "kprobe/", 7) == 0 || std::strncmp(sec, "kretprobe/", 10) == 0) {
            link = bpf_program__attach(prog);
        } else if (std::strncmp(sec, "tracepoint/", 11) == 0) {
            const char *category = sec + 11;
            const char *name = std::strchr(category, '/');
            if (!name || name == category)
                continue;
            std::string cat(category, static_cast<size_t>(name - category));
            const char *event = name + 1;
            link = bpf_program__attach_tracepoint(prog, cat.c_str(), event);
        } else {
            continue;
        }

        if (libbpf_get_error(link)) {
            long err = libbpf_get_error(link);
            // 如果是 ENOENT (2)，说明内核没有该符号，可能是因为生成器包含了 headers 中有但内核未实现的 syscall。
            // 如果是 EINVAL (22)，可能是该函数不可被 kprobe (例如被内核列入黑名单) 或参数无效。
            // 这种情况下我们选择忽略并继续，而不是直接退出。
            if (err == -ENOENT || err == -EINVAL) {
                if (cfg.verbose) {
                    std::cerr << "警告: 无法附加 " << bpf_program__name(prog)
                              << ": " << strerror(-err) << "，已忽略。\n";
                }
                continue;
            }

            std::cerr << "附加程序失败: " << bpf_program__name(prog)
                      << " 错误: " << strerror(-err) << '\n';
            for (auto *attached : links)
                bpf_link__destroy(attached);
            bpf_object__close(obj);
            return 1;
        }
        links.push_back(link);
    }

    const int managed_tgids_fd = bpf_object__find_map_fd_by_name(obj, "managed_tgids");
    const int managed_tids_fd = bpf_object__find_map_fd_by_name(obj, "managed_tids");
    const int profile_fd = bpf_object__find_map_fd_by_name(obj, "active_profiles");
    const int profile_floor_fd = bpf_object__find_map_fd_by_name(obj, "profile_floor");
    const int whitelist_fd = bpf_object__find_map_fd_by_name(obj, "profile_whitelist");

    const uint32_t tgid = static_cast<uint32_t>(child_pid);
    bool managed_added = false;
    std::vector<uint32_t> tids_added;
    tids_added.reserve(8);

    size_t total_syscalls = 0;
    for (size_t i = 0; i < kGeneratedProfileCount; ++i)
        total_syscalls += kGeneratedProfiles[i].syscall_count;

    std::vector<profile_key> inserted_keys;
    inserted_keys.reserve(total_syscalls);
    bool delayed_activation_done = false;

    do {
        if (managed_tgids_fd < 0 || managed_tids_fd < 0 || profile_fd < 0 || profile_floor_fd < 0 || whitelist_fd < 0) {
            std::cerr << "定位 BPF map 失败。" << '\n';
            result = 1;
            break;
        }

        if (int err = bpf_map_update_elem(managed_tgids_fd, &tgid, &kEnabled, BPF_ANY); err) {
            const int err_no = decode_bpf_syscall_errno(err);
            std::cerr << "更新 managed_tgids 失败: " << strerror(err_no)
                      << " (errno=" << err_no << ")\n";
            result = 1;
            break;
        }
        managed_added = true;

        const uint32_t default_profile = kGeneratedDefaultProfile;

        // 在进程启动初期，只有一个主线程
        const uint32_t tid = tgid;
        if (int err = bpf_map_update_elem(managed_tids_fd, &tid, &kEnabled, BPF_ANY); err) {
            const int err_no = decode_bpf_syscall_errno(err);
            std::cerr << "更新 managed_tids 失败 (tid=" << tid << "): " << strerror(err_no)
                      << " (errno=" << err_no << ")\n";
            result = 1;
            break;
        }
        tids_added.push_back(tid);
        if (cfg.verbose) {
            std::cout << "已登记主线程 tid=" << tid << "" << std::endl;
        }

        if (int err = bpf_map_update_elem(profile_fd, &tid, &default_profile, BPF_ANY); err) {
            const int err_no = decode_bpf_syscall_errno(err);
            std::cerr << "初始化线程 profile 失败 (tid=" << tid << "): " << strerror(err_no)
                      << " (errno=" << err_no << ")\n";
            result = 1;
            break;
        }

        if (default_profile != 0) {
            if (int err = bpf_map_update_elem(profile_floor_fd, &tgid, &default_profile, BPF_ANY); err) {
                const int err_no = decode_bpf_syscall_errno(err);
                std::cerr << "设置 profile floor 失败 (tgid=" << tgid << "): " << strerror(err_no)
                          << " (errno=" << err_no << ")\n";
                result = 1;
                break;
            }
        }

        bool populate_ok = true;
        for (size_t profile_idx = 0; profile_idx < kGeneratedProfileCount; ++profile_idx) {
            const auto &spec = kGeneratedProfiles[profile_idx];
            if (!spec.syscalls || spec.syscall_count == 0)
                continue;

            for (size_t i = 0; i < spec.syscall_count; ++i) {
                profile_key key{spec.id, spec.syscalls[i]};
                if (int err = bpf_map_update_elem(whitelist_fd, &key, &kEnabled, BPF_ANY); err) {
                    const int err_no = decode_bpf_syscall_errno(err);
                    std::cerr << "写入 profile_whitelist 失败 (profile=" << spec.id
                              << ", __NR=" << spec.syscalls[i] << "): " << strerror(err_no)
                              << " (errno=" << err_no << ")\n";
                    result = 1;
                    populate_ok = false;
                    break;
                }
                inserted_keys.push_back(key);
            }
            if (!populate_ok)
                break;
        }
        if (!populate_ok)
            break;

        std::cout << "已启用 TGID=" << child_pid
                  << " 的 syscall 白名单，默认 profile=" << default_profile << "。" << std::endl;
        if (cfg.activate_profile.has_value()) {
            std::cout << "延迟激活已就绪：向 loader 发送 SIGUSR1 后，将所有 managed TGID 的 floor 切到 profile="
                      << *cfg.activate_profile << "。" << std::endl;
        }
        std::cout << "可用 profiles:" << std::endl;
        for (size_t profile_idx = 0; profile_idx < kGeneratedProfileCount; ++profile_idx) {
            const auto &spec = kGeneratedProfiles[profile_idx];
            const char *name = spec.name ? spec.name : "<unnamed>";
            std::cout << "  - id=" << spec.id << " (" << name << "), syscalls="
                      << spec.syscall_count << std::endl;
        }
    std::cout << "通过 prctl(" << std::showbase << std::hex << kGeneratedProfileSwitchMagic
          << std::dec << std::noshowbase << ", <profile_id>) 可切换。" << std::endl;

        // Find the shmem_base BPF map for shared memory addresses.
        const int shmem_base_fd = bpf_object__find_map_fd_by_name(obj, "shmem_base");
        const std::string shmem_path = make_shmem_path(child_pid);

        if (kill(child_pid, SIGCONT) == -1) {
            std::cerr << "唤醒子进程失败: " << strerror(errno) << std::endl;
            result = 1;
            break;
        }

        // Poll for the root protected process's shared-memory mapping.
        // Multi-process protected applications may mmap the same backing file at
        // different virtual addresses, so the loader tracks one base address per
        // managed TGID instead of relying on a single shared file header.
        if (shmem_base_fd >= 0) {
            if (!wait_for_shmem_base(managed_tgids_fd, shmem_base_fd, tgid, shmem_path, cfg.verbose)) {
                if (!process_alive(child_pid)) {
                    std::cerr << "受保护进程在共享内存地址同步前已退出。" << std::endl;
                    result = 1;
                    break;
                }
            } else if (cfg.verbose) {
                std::cout << "已检测到根 protected 进程的共享内存映射。" << std::endl;
            }
        }

        const auto start = std::chrono::steady_clock::now();
        const auto deadline = cfg.duration_sec > 0
                                   ? std::optional<std::chrono::steady_clock::time_point>(
                                         start + std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                                                     std::chrono::duration<double>(cfg.duration_sec)))
                                   : std::nullopt;

        while (g_running.load(std::memory_order_relaxed)) {
            if (shmem_base_fd >= 0 &&
                !sync_shmem_bases(managed_tgids_fd, shmem_base_fd, shmem_path, cfg.verbose)) {
                result = 1;
                break;
            }

            if (cfg.activate_profile.has_value() &&
                g_activate_requested.load(std::memory_order_relaxed) &&
                !delayed_activation_done) {
                if (!activate_profile_floor(
                        managed_tgids_fd,
                        profile_floor_fd,
                        *cfg.activate_profile,
                        cfg.verbose)) {
                    result = 1;
                    break;
                }
                delayed_activation_done = true;
            }

            int status;
            pid_t ret = waitpid(child_pid, &status, WNOHANG);
            if (ret == child_pid) {
                if (WIFEXITED(status)) {
                    std::cout << "子进程已退出，退出码: " << WEXITSTATUS(status) << std::endl;
                } else if (WIFSIGNALED(status)) {
                    std::cout << "子进程被信号 " << WTERMSIG(status) << " 终止。" << std::endl;
                }

                // Wait for all threads in the thread group to terminate.
                // waitpid() returns when the thread group leader exits, but
                // Go's M:N runtime may still have OS threads being torn down
                // by the kernel. If we unlink the shared memory file while
                // those threads are still running, their cancelWhitelist()
                // calls will SIGBUS on the now-deleted mmap region.
                std::string task_dir = "/proc/" + std::to_string(child_pid) + "/task";
                for (int i = 0; i < 50; ++i) { // max 50 * 10ms = 500ms
                    DIR *dir = opendir(task_dir.c_str());
                    if (!dir)
                        break; // /proc/<pid> gone → all threads dead
                    int count = 0;
                    while (readdir(dir)) ++count;
                    closedir(dir);
                    // ".", ".." always present, so count <= 2 means empty
                    if (count <= 2)
                        break;
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
                break;
            }
            if (ret == -1) {
                std::cerr << "waitpid 失败: " << strerror(errno) << std::endl;
                break;
            }

            if (deadline && std::chrono::steady_clock::now() >= *deadline) {
                kill(child_pid, SIGKILL);
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        std::cout << "停止白名单控制。" << std::endl;

    } while (false);

    if (whitelist_fd >= 0) {
        for (const auto &key : inserted_keys)
            bpf_map_delete_elem(whitelist_fd, &key);
    }

    // Clean up shmem_base BPF map.
    {
        int shmem_base_fd = bpf_object__find_map_fd_by_name(obj, "shmem_base");
        if (shmem_base_fd >= 0)
            clear_u32_keyed_map(shmem_base_fd);
    }

    // Remove shared memory file.
    {
        std::string shmem_path = make_shmem_path(child_pid);
        unlink(shmem_path.c_str());
    }

    if (profile_fd >= 0) {
        for (const uint32_t tid : tids_added)
            bpf_map_delete_elem(profile_fd, &tid);
    }

    if (managed_tids_fd >= 0) {
        for (const uint32_t tid : tids_added)
            bpf_map_delete_elem(managed_tids_fd, &tid);
    }

    if (managed_added)
        bpf_map_delete_elem(managed_tgids_fd, &tgid);

    for (auto *link : links)
        bpf_link__destroy(link);
    bpf_object__close(obj);
    if (cfg.pid_file.has_value()) {
        std::error_code ec;
        std::filesystem::remove(*cfg.pid_file, ec);
    }

    return result;
}
