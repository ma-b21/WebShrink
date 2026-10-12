# Webshrink：构建与复现

[English](README_EN.md)

以下步骤适用于 Linux x86-64。PoC 及修改系统配置的测试只应在获得授权的隔离虚拟机中运行。

## 1. 环境与工具链

需要 Python 3.12+、uv、Go bootstrap 工具链、Clang/LLVM、C++ 编译器、libbpf/libelf/zlib 开发包、auditd（提供 `ausyscall`）和 sysdig。应用依赖见各场景 README。

内核须支持原型所用的 eBPF kprobe、tracepoint 和 `bpf_override_return`，包括相应的内核配置及可覆盖的系统调用入口。加载器和系统级采集需要相应权限。

在 Debian/Ubuntu 系上可执行：

```bash
sudo apt install clang llvm libbpf-dev libelf-dev zlib1g-dev bpftool linux-headers-$(uname -r)
```

生成脚本使用 `ausyscall --dump` 获取系统调用列表（由 `auditd` 提供），若未安装或不可用会直接报错退出。

加载失败（`operation not permitted`）时，确保以 root 运行，且内核启用了 `CONFIG_BPF`、`CONFIG_BPF_SYSCALL`、`CONFIG_BPF_JIT`。

从本目录执行：

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

组件均为普通源码目录，不需要初始化 Git 子模块。

## 2. 准备场景

在 [场景列表](experiments/README.md) 中选择一个场景，按其 README 获取源码、安装依赖，并设置绝对路径变量：

```bash
export EXP="$ROOT/experiments/<CVE>"
export SRC="$EXP/<source-directory>"
export MAIN_PKG='<main-package>'
export HANDLER_SIG='<handler-signature>'
```

`MAIN_PKG` 指向真正的 main 包，而非 `./...`。`HANDLER_SIG` 须与应用 Handler 签名一致；场景转换脚本的 `signature` 或 `signatures` 提供对应类型。多个分析签名用 `|` 分隔。应用的 build tags、CGO 和资源生成步骤在采集、分析与受保护构建中应保持一致。

所有场景均须先按第 3、4 节采集正常行为并生成 `whitelist_config.json`，再构建受保护应用。源码位置、版本、依赖或正常行为变化时，应重新生成配置；闭包位置中的文件路径须与本机编译源码一致。

## 3. 采集正常行为

仅用正常测试生成策略，PoC 不参与采集。建立无 Handler 绑定的采集配置：

```bash
mkdir -p "$ROOT/build"
printf '%s\n' '{"function_whitelists":{},"location_whitelists":[],"signatures":[]}' > "$ROOT/build/collection_config.json"
export WHITELIST_CONFIG="$ROOT/build/collection_config.json"
cd "$SRC"
"$TES/bin/go" build -a -buildvcs=false -gcflags=all=-ifacelog -o "$EXP/app-iface" <entry>
```

把 `<entry>` 换成场景入口并加上所需 tags；LocalAI 使用场景 Makefile。采集版本从不含 `whitelist_config.json` 的独立目录启动，用显式参数指定应用配置与数据目录。另开终端运行正常行为脚本，停止应用后导出本次日志：

```bash
cd "$ROOT"
uv run python main.py --project "$SRC" --output "$EXP" --log /tmp/ifacecalls.log
```

采集前确认日志不含旧运行或其他程序的数据；不同采集版本分别运行。

若正常业务启动子进程，再构建不带 `-ifacelog` 的采集版本，以 `GODEBUG=gosysdig=1` 启动并执行正常测试。停止后选取本次 PID 对应的 `/tmp/go-exec-trace.<PID>` 与 `/tmp/go-sysdig.<PID>.scap`，复制到 `$EXP`，转换为 JSON：

```bash
sysdig -p '*%evt.type %evt.info %proc.pid %proc.ppid %thread.tid %proc.name %proc.exepath %proc.cmdline' \
  -j -r "$EXP/go-sysdig.<PID>.scap" > "$EXP/log.jsonl"
```

sysdig 输出须包含进程关系和系统调用类型字段，解析格式见 `syscall-gen/vta-analyzer/utils/subproc.go`。不要混用多个运行的轨迹。

## 4. 生成 Handler 白名单

按 [分析器说明](syscall-gen/README.md) 构建工具和语言边界摘要，然后从应用源码目录分析：

```bash
cd "$SRC"
"$ROOT/build/analyzer" \
  -file ./... -main-pkg "$MAIN_PKG" \
  -linkname "$ROOT/syscall-gen/linkname-analyzer/linkname_mapping.json" \
  -builtins "$ROOT/syscall-gen/builtins/functions.go" \
  -asm "$ROOT/syscall-gen/asm-analyzer/func_sets.json" \
  -syscall-name -extra-edge "$EXP/dyn_calls.json"
```

需要 tags 时另加 `-build-flags`。有正常子进程轨迹时继续归并：

```bash
"$ROOT/build/analyzer" \
  -mode subprocess -main-pkg "$MAIN_PKG" \
  -trace-log "$EXP/go-exec-trace.<PID>" -sysdig-log "$EXP/log.jsonl" \
  -handler-func "$HANDLER_SIG" \
  -graph-syscall "$SRC/tmp/dag_syscalls.json" -syscall-name
```

在 `$EXP` 执行场景 `profile_convert.py`。多数脚本读取 `$EXP/dag_syscalls_subproc.json`，需先从 `$SRC/tmp/` 复制；LocalAI、WeKnora 和 Gogs 0.12.5 的输入路径见各自 README。无子进程时可将第一阶段 `dag_syscalls.json` 作为转换输入。转换前按本机路径调整 `path_mappings` 并核对 Handler 签名。

## 5. 构建受保护二进制及 eBPF

用同一份配置构建 BPF、加载器和插桩应用：

```bash
cd "$ROOT"
uv run python ebpf/scripts/build_whitelist_artifacts.py \
  --config "$EXP/whitelist_config.json" \
  --bpf-output "$EXP/ebpf.o" --loader-output "$EXP/syscall_loader"
cd "$SRC"
export WHITELIST_CONFIG="$EXP/whitelist_config.json"
"$TES/bin/go" build -a -buildvcs=false -o "$EXP/app-protected" <entry>
```

保留应用所需 tags、CGO 与资源生成设置；LocalAI 使用项目 Makefile。配置改变后重新构建应用、BPF 和加载器，不能只替换 JSON。需要拦截诊断日志时为 BPF 构建增加 `--debug`。

## 6. 启动与测试

编译器通过 `WHITELIST_CONFIG` 读取配置；运行时读取当前工作目录的 `whitelist_config.json`。启动前复制同一配置：

```bash
cp "$EXP/whitelist_config.json" "$SRC/whitelist_config.json"
cd "$SRC"
sudo "$EXP/syscall_loader" --bpf-obj "$EXP/ebpf.o" \
  --run-as "$(id -un)" -- "$EXP/app-protected" <application-arguments>
```

需要 root 的应用使用场景指定的运行用户。仅用定制 Go 编译、不通过 eBPF 加载器启动，不等于开启内核强制。

另开终端按场景 README 运行正常测试或 PoC，检查响应、进程状态和载荷的本地副作用。部分 `e2e_*.py` 自行启动服务、创建测试资源，应先看其启动参数，避免端口冲突。

## 许可证

保留各组件、应用和 PoC 的原有许可证与署名。Go 工具链许可见 `go-tesec/LICENSE`。
