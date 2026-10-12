#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
用法:
    run_whitelist_demo.sh --pid <PID> [--duration <秒>] [--config <文件>]
    run_whitelist_demo.sh [--duration <秒>] [--config <文件>] -- <命令...>

说明:
  --pid         指定已运行程序的 PID。
  --duration    运行白名单的时长，默认 10 秒，可通过 WHITELIST_DURATION 环境变量覆盖。
    --config      指定 profile 配置 JSON，相对路径以仓库根目录为基准。
  --            后续参数视为需要启动的命令，cwd 为仓库根目录。
EOF
}

if [[ $(id -u) -ne 0 ]]; then
    echo "请以 root 身份运行此脚本。"
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build"
SRC_DIR="${REPO_ROOT}/src"
CONFIG_DIR="${REPO_ROOT}/configs"
CONFIG_PATH="${CONFIG_DIR}/example.json"

DURATION="${WHITELIST_DURATION:-10}"
TARGET_PID=""
TARGET_COMMAND=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pid)
            if [[ -n "${TARGET_PID}" || ${#TARGET_COMMAND[@]} -ne 0 ]]; then
                echo "请勿同时指定多个目标。"
                usage
                exit 1
            fi
            if [[ $# -lt 2 ]]; then
                echo "--pid 需要一个参数。"
                usage
                exit 1
            fi
            TARGET_PID="$2"
            shift 2
            ;;
        --duration)
            if [[ $# -lt 2 ]]; then
                echo "--duration 需要一个参数。"
                usage
                exit 1
            fi
            DURATION="$2"
            shift 2
            ;;
        --config)
            if [[ $# -lt 2 ]]; then
                echo "--config 需要一个参数。"
                usage
                exit 1
            fi
            if [[ "$2" = /* ]]; then
                CONFIG_PATH="$2"
            else
                CONFIG_PATH="${REPO_ROOT}/$2"
            fi
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        --)
            shift
            if [[ -n "${TARGET_PID}" ]]; then
                echo "已指定 --pid，不可再传入命令。"
                usage
                exit 1
            fi
            if [[ $# -eq 0 ]]; then
                echo "-- 之后需要提供命令。"
                usage
                exit 1
            fi
            TARGET_COMMAND=("$@")
            break
            ;;
        *)
            echo "未知参数: $1"
            usage
            exit 1
            ;;
    esac
done

if [[ -z "${TARGET_PID}" && ${#TARGET_COMMAND[@]} -eq 0 ]]; then
    echo "必须通过 --pid 或 -- <命令> 指定目标程序。"
    usage
    exit 1
fi

if [[ ! -f "${CONFIG_PATH}" ]]; then
    echo "配置文件不存在: ${CONFIG_PATH}"
    exit 1
fi

mkdir -p "${BUILD_DIR}"

echo "生成 BPF 源文件（配置: ${CONFIG_PATH}）..."
"${REPO_ROOT}/scripts/gen_syscall_whitelist_bpf.py" --config "${CONFIG_PATH}" --output "${SRC_DIR}/syscall_whitelist.bpf.c"

echo "编译 syscall 白名单 BPF 程序..."
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I"${SRC_DIR}" \
    -I/usr/include/x86_64-linux-gnu \
    -Wall -Werror \
    -c "${SRC_DIR}/syscall_whitelist.bpf.c" \
    -o "${BUILD_DIR}/syscall_whitelist.bpf.o"

echo "编译用户态加载器..."
g++ -std=c++17 -O2 -Wall -Wextra -pedantic \
    "${SRC_DIR}/syscall_whitelist.cpp" \
    -o "${BUILD_DIR}/syscall_whitelist" \
    -lbpf -lelf -lz

LOG_FILE=""
TARGET_STARTED_BY_SCRIPT=0

if [[ ${#TARGET_COMMAND[@]} -gt 0 ]]; then
    LOG_FILE="$(mktemp)"
    trap '[[ -n "${LOG_FILE}" ]] && rm -f "${LOG_FILE}"' EXIT

    echo "启动目标程序: ${TARGET_COMMAND[*]}"
    (
        cd "${REPO_ROOT}"
        exec "${TARGET_COMMAND[@]}"
    ) > >(tee "${LOG_FILE}") 2>&1 &
    TARGET_PID=$!
    TARGET_STARTED_BY_SCRIPT=1

    sleep 0.5
fi

if ! kill -0 "${TARGET_PID}" 2>/dev/null; then
    echo "目标程序未运行，退出。"
    exit 1
fi

TARGET_TGID=$(awk '/^Tgid:/ {print $2}' "/proc/${TARGET_PID}/status" 2>/dev/null || true)
if [[ -z "${TARGET_TGID}" ]]; then
    TARGET_TGID="${TARGET_PID}"
fi

echo "目标程序 PID: ${TARGET_PID}，TGID: ${TARGET_TGID}"

"${BUILD_DIR}/syscall_whitelist" --pid "${TARGET_TGID}" --duration "${DURATION}" --verbose &
LOADER_PID=$!

if [[ ${TARGET_STARTED_BY_SCRIPT} -eq 1 ]]; then
    wait "${TARGET_PID}" || true
fi
wait "${LOADER_PID}" || true

if [[ ${TARGET_STARTED_BY_SCRIPT} -eq 1 && -n "${LOG_FILE}" ]]; then
    echo "===== 目标程序日志（grep unlink） ====="
    grep -E "unlink" "${LOG_FILE}" || true
fi
