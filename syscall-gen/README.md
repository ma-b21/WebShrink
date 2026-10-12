# 调用图分析器：构建与使用

[English](README_EN.md)

先按 [根目录说明](../README.md) 构建定制 Go，并设置绝对路径 `$ROOT`、`$TES`、`GOROOT` 和 `PATH`。

## 构建工具与语言边界摘要

```bash
mkdir -p "$ROOT/build"
cd "$ROOT/syscall-gen/asm-analyzer"
"$TES/bin/go" run asm-analyzer.go
cd "$ROOT/syscall-gen/linkname-analyzer"
"$TES/bin/go" run linkname-analyzer.go -output linkname_mapping.json
cd "$ROOT/syscall-gen/vta-analyzer"
"$TES/bin/go" build -o "$ROOT/build/analyzer" vta-analyzer.go
```

生成 `asm-analyzer/func_sets.json`、`linkname-analyzer/linkname_mapping.json` 和 `build/analyzer`。摘要须使用分析目标对应的工具链生成。

## 调用图与系统调用传播

从应用源码目录执行：

```bash
"$ROOT/build/analyzer" \
  -file ./... -main-pkg "$MAIN_PKG" \
  -linkname "$ROOT/syscall-gen/linkname-analyzer/linkname_mapping.json" \
  -builtins "$ROOT/syscall-gen/builtins/functions.go" \
  -asm "$ROOT/syscall-gen/asm-analyzer/func_sets.json" \
  -syscall-name -extra-edge "$EXP/dyn_calls.json"
```

`-main-pkg` 使用真实 main 包的目录或 import path。不需要动态边时省略 `-extra-edge`。需要 tags 时加 `-build-flags='-tags=tag1,tag2 -buildvcs=false'`。

输出位于当前目录 `tmp/`，其中 `dag_syscalls.json` 是完成系统调用传播的调用图。

## 子进程归并

```bash
"$ROOT/build/analyzer" \
  -mode subprocess -main-pkg "$MAIN_PKG" \
  -trace-log "$EXP/go-exec-trace.<PID>" -sysdig-log "$EXP/log.jsonl" \
  -handler-func "$HANDLER_SIG" \
  -graph-syscall ./tmp/dag_syscalls.json -syscall-name
```

两个日志须属于同一次良性执行，trace 参数使用一个具体文件。`-handler-func` 格式为 `(参数类型, 参数类型) -> [返回类型]`，多个签名用 `|` 分隔。

输出为 `tmp/dag_syscalls_subproc.json`。用场景 `profile_convert.py` 转换成白名单配置；后续编译与加载步骤见根目录 README。
