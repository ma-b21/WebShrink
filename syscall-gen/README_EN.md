# Call-Graph Analyzer: Build and Use

[简体中文](README.md)

First build the custom Go toolchain following the [root instructions](../README_EN.md), and set `$ROOT`, `$TES`, `GOROOT`, and `PATH` using absolute paths.

## Build the Tools and Language-Boundary Summaries

```bash
mkdir -p "$ROOT/build"
cd "$ROOT/syscall-gen/asm-analyzer"
"$TES/bin/go" run asm-analyzer.go
cd "$ROOT/syscall-gen/linkname-analyzer"
"$TES/bin/go" run linkname-analyzer.go -output linkname_mapping.json
cd "$ROOT/syscall-gen/vta-analyzer"
"$TES/bin/go" build -o "$ROOT/build/analyzer" vta-analyzer.go
```

This generates `asm-analyzer/func_sets.json`, `linkname-analyzer/linkname_mapping.json`, and `build/analyzer`. Generate the summaries using the toolchain that corresponds to the analysis target.

## Call Graph and Syscall Propagation

Run the following from the application's source directory:

```bash
"$ROOT/build/analyzer" \
  -file ./... -main-pkg "$MAIN_PKG" \
  -linkname "$ROOT/syscall-gen/linkname-analyzer/linkname_mapping.json" \
  -builtins "$ROOT/syscall-gen/builtins/functions.go" \
  -asm "$ROOT/syscall-gen/asm-analyzer/func_sets.json" \
  -syscall-name -extra-edge "$EXP/dyn_calls.json"
```

Set `-main-pkg` to the directory or import path of the actual main package. Omit `-extra-edge` when dynamic edges are not needed. Add `-build-flags='-tags=tag1,tag2 -buildvcs=false'` when tags are required.

Output is written to `tmp/` under the current directory. `dag_syscalls.json` is the call graph after syscall propagation.

## Merge Subprocess Behavior

```bash
"$ROOT/build/analyzer" \
  -mode subprocess -main-pkg "$MAIN_PKG" \
  -trace-log "$EXP/go-exec-trace.<PID>" -sysdig-log "$EXP/log.jsonl" \
  -handler-func "$HANDLER_SIG" \
  -graph-syscall ./tmp/dag_syscalls.json -syscall-name
```

Both logs must come from the same benign run; the trace argument must name a specific file. The `-handler-func` format is `(parameter type, parameter type) -> [return type]`. Separate multiple signatures with `|`.

The output is `tmp/dag_syscalls_subproc.json`. Convert it to an allowlist configuration using the scenario's `profile_convert.py`; see the root README for subsequent build and loading steps.
