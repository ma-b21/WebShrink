#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
用法:
  sudo ./scripts/test_thread_whitelist.sh [--duration 秒]

说明:
  - 需要 root 权限以加载 eBPF 程序
  - 默认持续 12 秒，可通过 --duration 调整
  - 自动执行 run_whitelist_demo.sh，并运行线程白名单验证程序
  - 成功时输出 THREAD_WHITELIST_TEST:PASS
EOF
}

if [[ $# -gt 0 ]]; then
    case "$1" in
        --help|-h)
            usage
            exit 0
            ;;
    esac
fi

if [[ $(id -u) -ne 0 ]]; then
    echo "请以 root 身份运行此脚本。" >&2
    exit 1
fi

DURATION=12
if [[ $# -gt 0 ]]; then
    if [[ "$1" == --duration && $# -ge 2 ]]; then
        DURATION="$2"
        shift 2
    else
        echo "未知参数: $1" >&2
        usage
        exit 1
    fi
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="$(mktemp)"
trap 'rm -f "$LOG_FILE"' EXIT

pushd "$REPO_ROOT" > /dev/null

if ! ./scripts/run_whitelist_demo.sh --duration "$DURATION" -- scripts/thread_whitelist_target.py >"$LOG_FILE" 2>&1; then
    cat "$LOG_FILE" >&2
    echo "run_whitelist_demo.sh 执行失败。" >&2
    exit 1
fi

popd > /dev/null

cat "$LOG_FILE"

if grep -q "THREAD_WHITELIST_TEST:PASS" "$LOG_FILE"; then
    echo "线程白名单测试通过。"
    exit 0
fi

echo "未检测到成功标记 THREAD_WHITELIST_TEST:PASS" >&2
exit 1
