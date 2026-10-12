#!/usr/bin/env python3
"""根据配置生成 syscall 白名单 BPF 程序与 C++ profile 头文件。"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import textwrap
from collections.abc import Iterable
from string import Template
from typing import Any

ARCH_PREFIX = {
    "x86_64": "__x64_sys_",
    "arm64": "__arm64_sys_",
    "aarch64": "__arm64_sys_",
}

SYSCALL_ALIASES = {
    "x86_64": {
        "pread": "pread64",
        "pwrite": "pwrite64",
    },
    "amd64": {
        "pread": "pread64",
        "pwrite": "pwrite64",
    },
}


def normalize_syscall_name(name: str, arch: str) -> str:
    return SYSCALL_ALIASES.get(arch, {}).get(name, name)


HEADER_TEMPLATE = Template("""// SPDX-License-Identifier: GPL-2.0
// 本文件由 scripts/gen_syscall_whitelist_bpf.py 自动生成，源配置: $config_path
// 请勿直接修改。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/errno.h>
#include <linux/unistd.h>

#ifdef ENABLE_BPF_DEBUG
#define DEBUG_LOG(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define DEBUG_LOG(fmt, ...) do { } while (0)
#endif

#ifndef EPERM
#define EPERM 1
#endif

#define PROFILE_SWITCH_MAGIC $profile_switch_magic
#define PROFILE_FLOOR_MAGIC  0x1234facf
#define MAX_PROFILE_ID $max_profile_id
#define DEFAULT_PROFILE_ID $default_profile

struct profile_key {
    u32 profile_id;
    u32 syscall_nr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u8);
} managed_tgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, u8);
} managed_tids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, u32);
} active_profiles SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} profile_floor SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    // 至少覆盖当前配置中的所有 (profile_id, syscall_nr) 键，并预留增长空间。
    __uint(max_entries, $profile_whitelist_max_entries);
    __type(key, struct profile_key);
    __type(value, u8);
} profile_whitelist SEC(".maps");

// Shared memory base address map.
// The loader stores the user-space address of each protected process's shared
// memory array here, keyed by TGID. The eBPF program reads whitelist IDs
// directly from user memory via bpf_probe_read_user(), eliminating the need
// for prctl() syscalls.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} shmem_base SEC(".maps");

static __always_inline bool is_tgid_managed(u32 tgid)
{
    u8 *flag = bpf_map_lookup_elem(&managed_tgids, &tgid);
    return flag && *flag;
}

static __always_inline bool is_tid_managed(u32 pid)
{
    u8 *flag = bpf_map_lookup_elem(&managed_tids, &pid);
    return flag && *flag;
}

static __always_inline u32 get_active_profile(u32 pid, u32 tgid)
{
    // Fast path: read whitelist ID from shared memory via bpf_probe_read_user.
    // The Go runtime writes directly to shared memory indexed by TID,
    // avoiding the overhead of a prctl() syscall. The loader maintains one
    // shared-memory base per protected process TGID, so multi-process
    // applications can coexist even if they mmap the same backing file at
    // different virtual addresses.
    u64 *base = bpf_map_lookup_elem(&shmem_base, &tgid);
    if (base && *base != 0) {
        u32 shmem_id = 0;
        // Array starts at base address, indexed by TID (4 bytes per entry).
        bpf_probe_read_user(&shmem_id, sizeof(shmem_id),
                            (const void *)(*base + (u64)pid * sizeof(u32)));
        if (shmem_id != 0)
            return shmem_id;
    }

    // Slow path: fall back to BPF map (used during fork/exit lifecycle
    // and as a fallback when shared memory is not yet initialized).
    u32 *profile = bpf_map_lookup_elem(&active_profiles, &pid);
    if (profile && *profile != 0)
        return *profile;
    u32 *floor = bpf_map_lookup_elem(&profile_floor, &tgid);
    return floor ? *floor : DEFAULT_PROFILE_ID;
}

static __always_inline bool is_syscall_allowed(u32 profile_id, u32 syscall_nr)
{
    struct profile_key key = {
        .profile_id = profile_id,
        .syscall_nr = syscall_nr,
    };
    u8 *value = bpf_map_lookup_elem(&profile_whitelist, &key);
    return value && *value;
}

static __always_inline int enforce_whitelist(struct pt_regs *ctx, long syscall_nr)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 pid = pid_tgid;

    if (!is_tgid_managed(tgid) || !is_tid_managed(pid))
        return 0;

    u32 profile_id = get_active_profile(pid, tgid);
    if (profile_id == 0)
        return 0;

    bool allowed = is_syscall_allowed(profile_id, (u32)syscall_nr);
    // Log process-creation syscalls for debugging (bpf_printk limited to 3 args)
    if (syscall_nr == 56 || syscall_nr == 57 || syscall_nr == 58 || syscall_nr == 59 || syscall_nr == 435)
        DEBUG_LOG("enf_allow: sys=%ld pid=%d allow=%d", syscall_nr, pid, (int)allowed);
    // Diagnostic: keep allowed alive so bpf_override_return is not
    // optimized away. Only enabled for waitid (247) to avoid trace flood.
    if (syscall_nr == 247)
        DEBUG_LOG("enforce: sys=%ld prof=%d allow=%d", syscall_nr, profile_id, (int)allowed);
    if (allowed)
        return 0;
    bpf_override_return(ctx, -EPERM);
    DEBUG_LOG("enforce_whitelist: blocked sys=%ld prof=%d", syscall_nr, profile_id);
    return 0;
}

static __always_inline int handle_prctl(struct pt_regs *ctx)
{
    struct pt_regs *sys_regs = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
    long option = BPF_CORE_READ(sys_regs, di);
    long arg2 = BPF_CORE_READ(sys_regs, si);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 pid = pid_tgid;

    // PROFILE_FLOOR_MAGIC: set the per-TGID floor profile.
    // A process with a floor set cannot lower its effective profile
    // below the floor, even if it switches to profile 0.
    if (option == PROFILE_FLOOR_MAGIC) {
        if (!is_tgid_managed(tgid)) {
            bpf_override_return(ctx, 0);
            return 0;
        }

        u32 floor_id = (u32)arg2;
        if (floor_id > MAX_PROFILE_ID)
            floor_id = DEFAULT_PROFILE_ID;

        bpf_map_update_elem(&profile_floor, &tgid, &floor_id, BPF_ANY);
        DEBUG_LOG("handle_prctl: floor set tgid=%d to profile %d", tgid, floor_id);

        bpf_override_return(ctx, 0);
        return 0;
    }

    if (option != PROFILE_SWITCH_MAGIC)
        return enforce_whitelist(ctx, __NR_prctl);

    if (!is_tgid_managed(tgid)) {
        bpf_override_return(ctx, 0);
        return 0;
    }

    if (!is_tid_managed(pid)) {
        bpf_override_return(ctx, 0);
        return 0;
    }

    u32 profile_id = (u32)arg2;
    if (profile_id > MAX_PROFILE_ID) {
        DEBUG_LOG("handle_prctl: clamp profile pid=%d requested=%ld", pid, arg2);
        profile_id = DEFAULT_PROFILE_ID;
    }

    bpf_map_update_elem(&active_profiles, &pid, &profile_id, BPF_ANY);
    DEBUG_LOG("handle_prctl: switched pid=%d to profile %d", pid, profile_id);

    bpf_override_return(ctx, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 parent_tgid = pid_tgid >> 32;

    if (!is_tgid_managed(parent_tgid))
        return 0;

    u32 child_pid = BPF_CORE_READ(ctx, child_pid);
    u32 child_tgid = child_pid; // 部分内核 tracepoint 无 child_tgid 字段，退化为 child_pid
    u32 parent_pid = BPF_CORE_READ(ctx, parent_pid);

    // 继承父线程当前的 profile（读共享内存 + active_profiles map + profile_floor）
    u32 inherited_profile = get_active_profile(parent_pid, parent_tgid);

    // 继承父进程的 profile floor
    u32 inherited_floor = DEFAULT_PROFILE_ID;
    u32 *parent_floor = bpf_map_lookup_elem(&profile_floor, &parent_tgid);
    if (parent_floor)
        inherited_floor = *parent_floor;

    // 子进程 floor：显式设置的 floor 优先，否则用父线程当前的 profile。
    // 这防止子进程 Go runtime 的 cancelWhitelist 把 profile 重置为 0 后逃逸。
    u32 child_floor = inherited_floor;
    if (child_floor == 0 && inherited_profile != 0)
        child_floor = inherited_profile;

    u8 enabled = 1;
    if (child_tgid != 0) {
        bpf_map_update_elem(&managed_tgids, &child_tgid, &enabled, BPF_ANY);
        if (child_floor != 0)
            bpf_map_update_elem(&profile_floor, &child_tgid, &child_floor, BPF_ANY);
    }
    bpf_map_update_elem(&managed_tids, &child_pid, &enabled, BPF_ANY);
    bpf_map_update_elem(&active_profiles, &child_pid, &inherited_profile, BPF_ANY);
    DEBUG_LOG("sched_fork: c_pid=%d c_tgid=%d inh=%d",
              child_pid, child_tgid, inherited_profile);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    u32 pid = BPF_CORE_READ(ctx, pid);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;

    if (!is_tid_managed(pid))
        return 0;

    bpf_map_delete_elem(&managed_tids, &pid);
    bpf_map_delete_elem(&active_profiles, &pid);
    if (pid == tgid) {
        bpf_map_delete_elem(&shmem_base, &tgid);
        bpf_map_delete_elem(&managed_tgids, &tgid);
        bpf_map_delete_elem(&profile_floor, &tgid);
    }
    return 0;
}

""")

FOOTER = """
char LICENSE[] SEC("license") = "GPL";
"""

CONTROL_SYSCALLS = {"prctl"}
IGNORED_SYSCALLS = {
    # 这些系统调用通常在头文件中定义，但现代内核已移除或不再作为独立符号暴露，
    # 强制 hook 它们会导致 attach 失败 (ENOENT)。
    "_sysctl",
    "nfsservctl",
    "get_kernel_syms",
    "create_module",
    "query_module",
    "uselib",
    "lookup_dcookie",
    # rt_sigreturn 不会由程序直接调用，而是由内核在信号处理后自动执行
    "rt_sigreturn",
}


def sanitize(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in name)


def parse_magic(value: Any) -> int:
    if isinstance(value, str):
        return int(value, 0)
    if isinstance(value, (int, float)):
        return int(value)
    raise ValueError("profile_switch_magic 必须是可转换为整数的类型")


def load_config(config_path: pathlib.Path) -> dict[str, Any]:
    return json.loads(config_path.read_text(encoding="utf-8"))


def discover_syscalls_from_ausyscall(arch: str) -> set[str]:
    # ausyscall uses 'x86_64', 'i386', 'aarch64', 'arm' etc.
    # Map our config arch to ausyscall arch.
    arch_map = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }
    target_arch = arch_map.get(arch, arch)

    if not shutil.which("ausyscall"):
        raise RuntimeError("ausyscall 未安装，请执行: sudo apt install auditd")

    # Try with specific arch
    cmd = ["ausyscall", target_arch, "--dump"]
    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        # If specific arch fails (e.g. not supported by installed ausyscall), try default
        print(
            f"Warning: ausyscall failed for arch {target_arch}, trying default",
            file=sys.stderr,
        )
        cmd = ["ausyscall", "--dump"]
        try:
            output = subprocess.check_output(cmd, text=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"执行 'ausyscall --dump' 失败: {e}")

    syscalls = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            int(parts[0])
            name = parts[1]
            syscalls.add(normalize_syscall_name(name, arch))
        except ValueError:
            continue
    return syscalls


def collect_all_syscalls(config: dict[str, Any], arch: str) -> list[str]:
    try:
        syscalls = discover_syscalls_from_ausyscall(arch)
        print(f"从 ausyscall 发现 {len(syscalls)} 个系统调用")
    except RuntimeError as e:
        raise SystemExit(str(e))

    extra = config.get("syscalls", [])
    if extra:
        syscalls.update(extra)
    for profile in config.get("profiles", []):
        syscalls.update(profile.get("syscalls", []))
    syscalls.update(CONTROL_SYSCALLS)

    if not syscalls:
        raise SystemExit(
            "无法获取需要 hook 的系统调用列表，请检查 ausyscall 是否正常工作"
        )

    return sorted(syscalls)


def render_function(syscall: str, prefix: str) -> str:
    func_name = sanitize(syscall)
    target = f"{prefix}{syscall}"
    syscall_const = f"__NR_{syscall}"
    if syscall in CONTROL_SYSCALLS:
        return textwrap.dedent(f"""
            SEC("kprobe/{target}")
            int BPF_KPROBE(kprobe__sys_{func_name})
            {{
                return handle_prctl(ctx);
            }}
            """)

    return textwrap.dedent(f"""
        SEC("kprobe/{target}")
        int BPF_KPROBE(kprobe__sys_{func_name})
        {{
            return enforce_whitelist(ctx, {syscall_const});
        }}
        """)


def analyse_profiles(
    config: dict[str, Any],
) -> tuple[list[dict[str, Any]], int, int, int]:
    profiles = config.get("profiles", [])
    if not profiles:
        raise SystemExit("配置文件中缺少 profiles 字段")

    default_profile = int(config.get("default_profile", 0))
    profile_switch_magic = parse_magic(config.get("profile_switch_magic", 0x1234FACE))
    sorted_profiles = sorted(profiles, key=lambda item: int(item.get("id", 0)))
    max_profile_id = 0
    for profile in sorted_profiles:
        pid = int(profile.get("id", 0))
        if pid == 0:
            raise SystemExit("profiles 中的 id 不能为 0，0 预留为无限制 profile")
        if pid > max_profile_id:
            max_profile_id = pid

    return sorted_profiles, max_profile_id, default_profile, profile_switch_magic


def dedupe_profile_syscalls(profile: dict[str, Any]) -> list[str]:
    return list(dict.fromkeys(profile.get("syscalls", [])))


def compute_profile_whitelist_capacity(
    sorted_profiles: Iterable[dict[str, Any]],
) -> tuple[int, int]:
    required_entries = 0
    for profile in sorted_profiles:
        required_entries += len(dedupe_profile_syscalls(profile))

    minimum_entries = 4096
    if required_entries <= minimum_entries:
        return required_entries, minimum_entries

    # 为后续 profile 增长预留 25% 空间，并向上取 2 的幂以降低 hash map 过满风险。
    target_entries = required_entries + max(64, required_entries // 4)
    map_capacity = 1 << (target_entries - 1).bit_length()
    return required_entries, map_capacity


def generate_profiles_header(
    config: dict[str, Any],
    header_path: pathlib.Path,
) -> None:
    sorted_profiles, max_profile_id, default_profile, profile_switch_magic = (
        analyse_profiles(config)
    )

    arrays: list[str] = []
    specs: list[str] = []
    for profile in sorted_profiles:
        pid = int(profile.get("id", 0))
        name = profile.get("name", f"profile_{pid}")
        syscall_names = dedupe_profile_syscalls(profile)
        array_name = f"profile_{pid}_syscalls"

        if syscall_names:
            body = ",\n".join(f"    __NR_{call}" for call in syscall_names)
            array_block = f"static const uint32_t {array_name}[] = {{\n{body}\n}};"
            arrays.append(array_block)
            array_ref = array_name
            count_expr = f"sizeof({array_name}) / sizeof({array_name}[0])"
        else:
            array_ref = "nullptr"
            count_expr = "0"

        specs.append(textwrap.dedent(f"""
                {{
                    {pid}u,
                    "{name}",
                    {array_ref},
                    {count_expr}
                }}
                """).strip())

    header = textwrap.dedent("""#pragma once
#include <cstddef>
#include <cstdint>
#include <sys/syscall.h>

struct GeneratedProfileSpec {
    uint32_t id;
    const char *name;
    const uint32_t *syscalls;
    size_t syscall_count;
};

""")

    if arrays:
        header += "\n\n".join(arrays)
        header += "\n\n"
    header += "static const GeneratedProfileSpec kGeneratedProfiles[] = {\n"
    header += ",\n".join(textwrap.indent(spec, "    ") for spec in specs)
    header += "\n};\n\n"
    header += textwrap.dedent(f"""
constexpr size_t kGeneratedProfileCount = sizeof(kGeneratedProfiles) / sizeof(kGeneratedProfiles[0]);
constexpr uint32_t kGeneratedMaxProfileId = {max_profile_id}u;
constexpr uint32_t kGeneratedDefaultProfile = {default_profile}u;
constexpr uint32_t kGeneratedProfileSwitchMagic = {profile_switch_magic:#x}u;
""")

    header_path.write_text(header, encoding="utf-8")


def wrap_with_guard(syscall: str) -> str:
    syscall_macro = f"__NR_{syscall}"
    body = textwrap.dedent(f"""
        DECLARE_SYSCALL_KPROBE({syscall});
        """).strip()
    return textwrap.dedent(f"""
#ifdef {syscall_macro}
{body}
#endif
""").strip()


def generate_bpf_source(
    config: dict[str, Any],
    config_path: pathlib.Path,
    output_path: pathlib.Path,
    syscalls: Iterable[str],
) -> None:
    arch = str(config.get("arch", "x86_64")).lower()
    if arch not in ARCH_PREFIX:
        raise SystemExit(f"unsupported arch '{arch}'")
    arch_prefix = ARCH_PREFIX[arch]

    sorted_profiles, max_profile_id, default_profile, profile_switch_magic = (
        analyse_profiles(config)
    )
    _, profile_whitelist_max_entries = compute_profile_whitelist_capacity(
        sorted_profiles
    )
    profile_switch_magic_str = f"{profile_switch_magic:#x}"

    syscall_blocks: list[str] = []
    for syscall in syscalls:
        if syscall in CONTROL_SYSCALLS:
            continue
        if syscall in IGNORED_SYSCALLS:
            continue
        syscall_blocks.append(wrap_with_guard(syscall))
    syscall_section = "\n\n".join(syscall_blocks)

    content = HEADER_TEMPLATE.substitute(
        config_path=config_path.resolve(),
        profile_switch_magic=profile_switch_magic_str,
        max_profile_id=max_profile_id,
        default_profile=default_profile,
        profile_whitelist_max_entries=profile_whitelist_max_entries,
    )

    content += textwrap.dedent(f"""
#define DECLARE_SYSCALL_KPROBE(name) \\
    SEC("kprobe/{arch_prefix}" #name) \\
    int BPF_KPROBE(kprobe__sys_##name) \\
    {{ \\
        return enforce_whitelist(ctx, __NR_##name); \\
    }}

{syscall_section}

SEC("kprobe/{arch_prefix}prctl")
int BPF_KPROBE(kprobe__sys_prctl)
{{
    return handle_prctl(ctx);
}}

{FOOTER}
""")

    output_path.write_text(content, encoding="utf-8")


def normalize_config(config: dict[str, Any], arch: str) -> None:
    if "syscalls" in config:
        config["syscalls"] = [
            normalize_syscall_name(s, arch) for s in config["syscalls"]
        ]

    for profile in config.get("profiles", []):
        if "syscalls" in profile:
            profile["syscalls"] = [
                normalize_syscall_name(s, arch) for s in profile["syscalls"]
            ]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="生成 syscall 白名单 BPF 源文件与 profile 头文件"
    )
    parser.add_argument(
        "--config",
        type=pathlib.Path,
        default=pathlib.Path("configs/io_syscalls.json"),
        help="包含 profiles 配置的 JSON 文件",
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=pathlib.Path("src/syscall_whitelist.bpf.c"),
        help="输出 BPF 源文件路径 (已弃用)",
    )
    parser.add_argument(
        "--profile-header",
        type=pathlib.Path,
        default=pathlib.Path("src/generated_syscall_profiles.hpp"),
        help="输出供 C++ 使用的 profile 头文件路径",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    arch = str(config.get("arch", "x86_64")).lower()
    normalize_config(config, arch)
    all_syscalls = collect_all_syscalls(config, arch)

    generate_bpf_source(config, args.config, args.output, all_syscalls)
    generate_profiles_header(config, args.profile_header)


if __name__ == "__main__":
    main()
