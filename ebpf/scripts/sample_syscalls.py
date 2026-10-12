#!/usr/bin/env python3

"""示例程序：触发几个常见的系统调用便于演示。"""

import argparse
import ctypes
import ctypes.util
import json
import os
import time
from pathlib import Path

_libc_path = ctypes.util.find_library("c") or "libc.so.6"
_libc = ctypes.CDLL(_libc_path, use_errno=True)
_libc.prctl.argtypes = [
    ctypes.c_int,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
"""示例程序：触发几个常见的系统调用便于演示。"""

import argparse
import ctypes
import ctypes.util
import json
import os
import time
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parents[1] / "configs" / "example.json"

_libc_path = ctypes.util.find_library("c") or "libc.so.6"
_libc = ctypes.CDLL(_libc_path, use_errno=True)
_libc.prctl.argtypes = [
    ctypes.c_int,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
_libc.prctl.restype = ctypes.c_int


def _parse_magic(value: object) -> int:
    if isinstance(value, str):
        return int(value, 0)
    if isinstance(value, (int, float)):
        return int(value)
    raise RuntimeError("profile_switch_magic 字段格式不正确")


def _load_profile_settings() -> tuple[int, int, int, str, str]:
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"无法读取配置文件 {CONFIG_PATH}: {exc}") from exc

    magic = _parse_magic(data.get("profile_switch_magic", 0x1234FACE))
    default_profile = int(data.get("default_profile", 0))

    unlink_profile = default_profile
    unlink_profile_name = ""
    default_profile_name = ""
    for profile in data.get("profiles", []):
        pid = int(profile.get("id", 0))
        syscalls = profile.get("syscalls", [])
        name = profile.get("name", "")
        if pid == default_profile:
            default_profile_name = name
        if "unlink" in syscalls or "unlinkat" in syscalls:
            unlink_profile = pid
            unlink_profile_name = name
            break

    return (
        magic,
        default_profile,
        unlink_profile,
        default_profile_name,
        unlink_profile_name,
    )


try:
    (
        PROFILE_SWITCH_MAGIC,
        PROFILE_DEFAULT,
        PROFILE_WITH_UNLINK,
        PROFILE_DEFAULT_NAME,
        PROFILE_WITH_UNLINK_NAME,
    ) = _load_profile_settings()
except RuntimeError as exc:
    raise SystemExit(str(exc)) from exc


def switch_profile(profile: int) -> bool:
    ctypes.set_errno(0)
    ret = _libc.prctl(PROFILE_SWITCH_MAGIC, ctypes.c_ulong(profile), 0, 0, 0)
    if ret != 0:
        err = ctypes.get_errno()
        print(f"prctl 切换白名单失败: errno={err}")
        return False
    if profile == PROFILE_WITH_UNLINK and PROFILE_WITH_UNLINK_NAME:
        label = PROFILE_WITH_UNLINK_NAME
    elif profile == PROFILE_DEFAULT and PROFILE_DEFAULT_NAME:
        label = PROFILE_DEFAULT_NAME
    else:
        label = "profile"
    print(
        f"已请求切换到白名单 profile {profile} ({label})，魔数=0x{PROFILE_SWITCH_MAGIC:x}"
    )
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="触发一些系统调用供 eBPF 演示使用")
    parser.add_argument(
        "--delay",
        type=float,
        default=1.5,
        help="启动后等待的秒数，便于监控程序就位",
    )
    parser.add_argument(
        "--loops",
        type=int,
        default=3,
        help="重复触发 I/O 循环次数",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print(f"示例程序 PID: {os.getpid()}，将在 {args.delay:.1f} 秒后开始触发系统调用...")
    default_label = PROFILE_DEFAULT_NAME or "未命名"
    unlink_label = PROFILE_WITH_UNLINK_NAME or "未命名"
    if PROFILE_WITH_UNLINK == PROFILE_DEFAULT:
        print(
            f"当前配置的默认白名单 profile {PROFILE_DEFAULT} ({default_label}) 将禁止 unlink。"
        )
    else:
        print(
            f"默认白名单 profile {PROFILE_DEFAULT} ({default_label}) 禁止 unlink，"
            f"profile {PROFILE_WITH_UNLINK} ({unlink_label}) 允许 unlink。"
        )
    time.sleep(max(args.delay, 0))

    base_dir = os.getcwd()
    current_profile = PROFILE_DEFAULT

    for idx in range(args.loops):
        path = os.path.join(base_dir, f"sample_tmp_{os.getpid()}_{idx}")

        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, f"loop={idx} from sample program\n".encode())
        finally:
            os.close(fd)

        fd = os.open(path, os.O_RDONLY)
        try:
            data = os.read(fd, 64)
            print(f"读取到数据: {data.decode().strip()}")
        finally:
            os.close(fd)
            while True:
                try:
                    os.unlink(path)
                    break
                except PermissionError as exc:
                    print(f"unlink 失败: {exc}")
                    if current_profile != PROFILE_WITH_UNLINK and switch_profile(
                        PROFILE_WITH_UNLINK
                    ):
                        current_profile = PROFILE_WITH_UNLINK
                        print("切换成功，准备重试 unlink...")
                        continue
                    break

        # 获取进程号并稍作等待，触发 getpid、nanosleep 等
        print(f"当前进程 PID: {os.getpid()}，循环 {idx + 1}/{args.loops}")
        time.sleep(0.3)

    if current_profile != PROFILE_DEFAULT:
        switch_profile(PROFILE_DEFAULT)

    print("示例程序执行完毕。")


if __name__ == "__main__":
    main()
