# Webshrink: Build and Reproduce

[简体中文](README.md)

These instructions target Linux x86-64. Run PoCs and tests that modify system configuration only in an authorized, isolated virtual machine.

## 1. Environment and Toolchain

Install Python 3.12+, uv, a bootstrap Go toolchain, Clang/LLVM, a C++ compiler, the libbpf/libelf/zlib development packages, auditd (which provides `ausyscall`), and sysdig. See each scenario README for application-specific dependencies.

The kernel must support the eBPF kprobes, tracepoints, and `bpf_override_return` used by the prototype, with the required kernel configuration and syscall entry points that permit return-value overriding. The loader and system-wide tracing require appropriate privileges.

Run the following from this directory:

```bash
export ROOT="$(pwd -P)"
export TES="$ROOT/go-tesec"
uv sync
cd "$TES/src"
GOROOT_BOOTSTRAP=/absolute/path/to/bootstrap/go bash ./make.bash
export GOROOT="$TES"
export PATH="$TES/bin:$PATH"
cd "$ROOT"
```

All components are ordinary source directories; Git submodule initialization is not required.

## 2. Prepare a Scenario

Choose a scenario from the [scenario list](experiments/README_EN.md), follow its README to obtain the source and install dependencies, and set these variables to absolute paths:

```bash
export EXP="$ROOT/experiments/<CVE>"
export SRC="$EXP/<source-directory>"
export MAIN_PKG='<main-package>'
export HANDLER_SIG='<handler-signature>'
```

`MAIN_PKG` must identify the actual main package, not `./...`. `HANDLER_SIG` must match the application's Handler signature; the scenario converter's `signature` or `signatures` specifies the relevant types. Separate multiple analysis signatures with `|`. Keep application build tags, CGO settings, and resource-generation steps consistent across collection, analysis, and the protected build.

For each scenario, first collect normal behavior and generate `whitelist_config.json` as described in Sections 3 and 4, then build the protected application. Regenerate the configuration when source locations, versions, dependencies, or normal behavior change. File paths in closure locations must match the source used for compilation on the local machine.

## 3. Collect Normal Behavior

Generate policies using only normal tests; exclude PoCs from collection. Create a collection configuration with no Handler bindings:

```bash
mkdir -p "$ROOT/build"
printf '%s\n' '{"function_whitelists":{},"location_whitelists":[],"signatures":[]}' > "$ROOT/build/collection_config.json"
export WHITELIST_CONFIG="$ROOT/build/collection_config.json"
cd "$SRC"
"$TES/bin/go" build -a -buildvcs=false -gcflags=all=-ifacelog -o "$EXP/app-iface" <entry>
```

Replace `<entry>` with the scenario's entry point and add any required tags; LocalAI uses its scenario Makefile. Launch the collection build from a separate directory without `whitelist_config.json`, and specify application configuration and data directories explicitly. Run the normal-behavior scripts in another terminal, stop the application, and export the log from this run:

```bash
cd "$ROOT"
uv run python main.py --project "$SRC" --output "$EXP" --log /tmp/ifacecalls.log
```

Before collection, ensure that the logs contain no data from earlier runs or other programs. Run each collection build separately.

If normal operations spawn subprocesses, build another collection binary without `-ifacelog`, launch it with `GODEBUG=gosysdig=1`, and run normal tests. After stopping it, select `/tmp/go-exec-trace.<PID>` and `/tmp/go-sysdig.<PID>.scap` for that run's PID, copy them to `$EXP`, and convert the trace to JSON:

```bash
sysdig -p '*%evt.type %evt.info %proc.pid %proc.ppid %thread.tid %proc.name %proc.exepath %proc.cmdline' \
  -j -r "$EXP/go-sysdig.<PID>.scap" > "$EXP/log.jsonl"
```

The sysdig output must include process relationships and syscall-type fields; see `syscall-gen/vta-analyzer/utils/subproc.go` for the expected format. Do not mix traces from different runs.

## 4. Generate Handler Allowlists

Build the tools and language-boundary summaries following the [analyzer instructions](syscall-gen/README_EN.md), then run the analysis from the application's source directory:

```bash
cd "$SRC"
"$ROOT/build/analyzer" \
  -file ./... -main-pkg "$MAIN_PKG" \
  -linkname "$ROOT/syscall-gen/linkname-analyzer/linkname_mapping.json" \
  -builtins "$ROOT/syscall-gen/builtins/functions.go" \
  -asm "$ROOT/syscall-gen/asm-analyzer/func_sets.json" \
  -syscall-name -extra-edge "$EXP/dyn_calls.json"
```

Add `-build-flags` if tags are required. If normal subprocess traces are available, merge them next:

```bash
"$ROOT/build/analyzer" \
  -mode subprocess -main-pkg "$MAIN_PKG" \
  -trace-log "$EXP/go-exec-trace.<PID>" -sysdig-log "$EXP/log.jsonl" \
  -handler-func "$HANDLER_SIG" \
  -graph-syscall "$SRC/tmp/dag_syscalls.json" -syscall-name
```

Run the scenario's `profile_convert.py` in `$EXP`. Most converters read `$EXP/dag_syscalls_subproc.json`, which must first be copied from `$SRC/tmp/`; see the individual READMEs for the input paths used by LocalAI, WeKnora, and Gogs 0.12.5. When there are no subprocesses, use the first-stage `dag_syscalls.json` as the conversion input. Before conversion, adjust `path_mappings` to local paths and check the Handler signatures.

## 5. Build the Protected Binary and eBPF Artifacts

Build the BPF program, loader, and instrumented application using the same configuration:

```bash
cd "$ROOT"
uv run python ebpf/scripts/build_whitelist_artifacts.py \
  --config "$EXP/whitelist_config.json" \
  --bpf-output "$EXP/ebpf.o" --loader-output "$EXP/syscall_loader"
cd "$SRC"
export WHITELIST_CONFIG="$EXP/whitelist_config.json"
"$TES/bin/go" build -a -buildvcs=false -o "$EXP/app-protected" <entry>
```

Retain the application's required tags, CGO settings, and resource-generation steps; LocalAI uses its project Makefile. After changing the configuration, rebuild the application, BPF program, and loader rather than replacing only the JSON file. Add `--debug` to the BPF build to enable blocking diagnostics.

## 6. Launch and Test

The compiler reads the configuration through `WHITELIST_CONFIG`; the runtime reads `whitelist_config.json` from the current working directory. Copy the same configuration there before launch:

```bash
cp "$EXP/whitelist_config.json" "$SRC/whitelist_config.json"
cd "$SRC"
sudo "$EXP/syscall_loader" --bpf-obj "$EXP/ebpf.o" \
  --run-as "$(id -un)" -- "$EXP/app-protected" <application-arguments>
```

Use the scenario's specified runtime user for applications that require root. Compiling with the custom Go toolchain alone does not enable kernel enforcement; launch the binary through the eBPF loader.

In another terminal, run normal tests or PoCs following the scenario README, and inspect responses, process state, and the payload's local side effects. Some `e2e_*.py` scripts start services and create test resources themselves; check their launch parameters first to avoid port conflicts.

## Licenses

Retain the original licenses and credits for all components, applications, and PoCs. See `go-tesec/LICENSE` for the Go toolchain license.
