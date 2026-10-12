# eBPF: Build and Load

[简体中文](README.md)

## Environment Setup

On Linux x86-64, install Clang/LLVM, a C++ compiler, the libbpf/libelf/zlib development packages, and auditd. The kernel must support the kprobes, tracepoints, and `bpf_override_return` used by the source. Loading requires root or equivalent privileges.

Run `uv sync` from the project root to install Python dependencies. Follow the [root instructions](../README_EN.md) to collect normal behavior, generate the allowlist configuration, and set `$ROOT`, `$EXP`, and `$SRC`.

## Build the BPF Program and Matching Loader

Run the following from the project root:

```bash
uv run python ebpf/scripts/build_whitelist_artifacts.py \
  --config "$EXP/whitelist_config.json" \
  --bpf-output "$EXP/ebpf.o" --loader-output "$EXP/syscall_loader"
```

Add `--debug` for diagnostic logs. The script generates the BPF program and header for the configuration, then compiles the loader using that header. Do not build different configurations concurrently, as they share the same generated header.

## Launch the Protected Application

First compile the instrumented application with the same configuration following the [root instructions](../README_EN.md), then place the runtime configuration in the working directory:

```bash
cp "$EXP/whitelist_config.json" "$SRC/whitelist_config.json"
cd "$SRC"
sudo "$EXP/syscall_loader" --bpf-obj "$EXP/ebpf.o" \
  --run-as "$(id -un)" -- "$EXP/app-protected" <application-arguments>
```

The loader launches the target application through `-- <command>`; attaching to an existing process is not implemented. Rebuild the application, BPF program, and loader whenever the configuration changes.

## Standalone Interface Tests

`configs/example.json`, `sample_syscalls.py`, and the thread-allowlist scripts test compatibility interfaces; they are not the deployment workflow for Go scheduler allowlist switching. Check the script parameters, then run them from this directory:

```bash
sudo bash scripts/run_whitelist_demo.sh -- python3 scripts/sample_syscalls.py --loops 2
sudo bash scripts/test_thread_whitelist.sh
```

If loading fails, check the kernel configuration, privileges, and target syscall entry points. After building with `--debug`, read `trace_pipe` in the local tracefs to inspect blocking logs.
