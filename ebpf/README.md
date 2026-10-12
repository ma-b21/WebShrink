# eBPF：构建与加载

[English](README_EN.md)

## 环境准备

在 Linux x86-64 安装 Clang/LLVM、C++ 编译器、libbpf/libelf/zlib 开发包及 auditd。内核须支持源码使用的 kprobe、tracepoint 与 `bpf_override_return`；加载需要 root 或等效权限。

从项目根目录执行 `uv sync` 安装 Python 依赖。按 [根目录说明](../README.md) 采集正常行为、生成白名单配置，并设置 `$ROOT`、`$EXP` 和 `$SRC`。

## 构建 BPF 和匹配的加载器

从项目根目录执行：

```bash
uv run python ebpf/scripts/build_whitelist_artifacts.py \
  --config "$EXP/whitelist_config.json" \
  --bpf-output "$EXP/ebpf.o" --loader-output "$EXP/syscall_loader"
```

需要诊断日志时加 `--debug`。脚本生成配置对应的 BPF 程序及头文件，并使用该头文件编译加载器。不要同时为不同配置运行构建，它们会使用同一份生成头文件。

## 启动受保护应用

先按 [根目录说明](../README.md) 用同一配置编译插桩应用，并在工作目录中放置运行时配置：

```bash
cp "$EXP/whitelist_config.json" "$SRC/whitelist_config.json"
cd "$SRC"
sudo "$EXP/syscall_loader" --bpf-obj "$EXP/ebpf.o" \
  --run-as "$(id -un)" -- "$EXP/app-protected" <application-arguments>
```

加载器通过 `-- <command>` 启动目标应用；不要使用未实现的现有进程接管接口。配置变化后重新构建应用、BPF 和加载器。

## 独立接口测试

`configs/example.json`、`sample_syscalls.py` 及线程白名单脚本用于兼容接口测试，不是 Go 调度器白名单切换的部署流程。可在本目录查看脚本参数后运行：

```bash
sudo bash scripts/run_whitelist_demo.sh -- python3 scripts/sample_syscalls.py --loops 2
sudo bash scripts/test_thread_whitelist.sh
```

加载失败时检查内核配置、权限及目标系统调用入口。以 `--debug` 构建后，可读取本机 tracefs 中的 `trace_pipe` 观察拦截日志。
