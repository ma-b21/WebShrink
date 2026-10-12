#!/usr/bin/env python3
"""多线程白名单演示程序：验证线程级 profile 隔离。"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import json
import os
import sys
import threading
import time
from pathlib import Path
from tempfile import TemporaryDirectory

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


def _load_profile_settings() -> tuple[int, int, int]:
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"无法读取配置文件 {CONFIG_PATH}: {exc}") from exc

    magic = _parse_magic(data.get("profile_switch_magic", 0x1234FACE))
    default_profile = int(data.get("default_profile", 0))

    allow_unlink_profile = default_profile
    for profile in data.get("profiles", []):
        pid = int(profile.get("id", 0))
        syscalls = profile.get("syscalls", [])
        if "unlink" in syscalls or "unlinkat" in syscalls:
            allow_unlink_profile = pid
            break

    return magic, default_profile, allow_unlink_profile


try:
    PROFILE_SWITCH_MAGIC, PROFILE_DEFAULT, PROFILE_ALLOW_UNLINK = (
        _load_profile_settings()
    )
except RuntimeError as exc:
    print(f"载入配置失败: {exc}", file=sys.stderr)
    sys.exit(1)


def switch_profile(
    profile: int,
    *,
    retry: bool = False,
    timeout: float = 3.0,
    interval: float = 0.05,
) -> None:
    deadline = time.monotonic() + timeout
    while True:
        ctypes.set_errno(0)
        ret = _libc.prctl(PROFILE_SWITCH_MAGIC, ctypes.c_ulong(profile), 0, 0, 0)
        if ret == 0:
            return
        err = ctypes.get_errno()
        if retry and err == errno.EINVAL and time.monotonic() < deadline:
            time.sleep(interval)
            continue
        raise RuntimeError(f"prctl 切换白名单失败: errno={err}")


def try_unlink(path: Path) -> tuple[bool, str]:
    try:
        path.unlink()
        return True, ""
    except PermissionError as exc:
        return False, str(exc)
    except FileNotFoundError:
        return True, "file already removed"
    except OSError as exc:  # pragma: no cover - 防御性
        return False, str(exc)


START_DELAY = float(os.environ.get("THREAD_WHITELIST_DELAY", "1.0"))


def ensure_default_profile(timeout: float = 3.0) -> bool:
    try:
        switch_profile(PROFILE_DEFAULT, retry=True, timeout=timeout)
        return True
    except RuntimeError as exc:
        print(f"[ensure-default] 切换失败: {exc}", file=sys.stderr)
        return False


def main() -> int:
    print(f"测试程序 PID: {os.getpid()}，准备创建两个线程进行白名单验证...")
    print(
        "线程默认使用 profile"
        f" {PROFILE_DEFAULT}，其中不允许 unlink；profile {PROFILE_ALLOW_UNLINK} 允许 unlink。"
    )
    print(f"将在开始 unlink 前等待 {START_DELAY:.2f} 秒，以确保 eBPF 控制器就位。")

    results: dict[str, tuple[bool, str]] = {}
    results_lock = threading.Lock()
    start_barrier = threading.Barrier(2)
    switch_done = threading.Event()

    def record(key: str, value: tuple[bool, str]) -> None:
        with results_lock:
            results[key] = value

    def default_thread(base_dir: Path) -> None:
        path = base_dir / "default_thread.tmp"
        path.write_text("data", encoding="utf-8")
        try:
            start_barrier.wait(timeout=5)
        except threading.BrokenBarrierError as exc:
            record("default_barrier", (False, f"barrier broken: {exc}"))
            return

        if not ensure_default_profile():
            record("default_register", (False, "prctl default profile 超时"))
            return

        time.sleep(START_DELAY)
        success, detail = try_unlink(path)
        print(
            f"[default-thread] 第一次 unlink 结果: success={success}, detail={detail}"
        )
        record("default_first", (success, detail))

        if not switch_done.wait(timeout=10):
            record("default_wait", (False, "等待允许线程完成超时"))
            return

        if not path.exists():
            path.write_text("data", encoding="utf-8")

        time.sleep(START_DELAY)
        success, detail = try_unlink(path)
        print(
            f"[default-thread] 第二次 unlink 结果: success={success}, detail={detail}"
        )
        record("default_second", (success, detail))

    def allow_thread(base_dir: Path) -> None:
        path = base_dir / "allow_thread.tmp"
        path.write_text("data", encoding="utf-8")
        try:
            start_barrier.wait(timeout=5)
        except threading.BrokenBarrierError as exc:
            record("allow_barrier", (False, f"barrier broken: {exc}"))
            return

        if not ensure_default_profile():
            record("allow_register", (False, "prctl default profile 超时"))
            switch_done.set()
            return

        time.sleep(START_DELAY)
        success, detail = try_unlink(path)
        print(f"[allow-thread] 第一次 unlink 结果: success={success}, detail={detail}")
        record("allow_first", (success, detail))

        try:
            switch_profile(PROFILE_ALLOW_UNLINK)
            print(f"[allow-thread] 调用了 prctl 切换到 profile {PROFILE_ALLOW_UNLINK}")
        except RuntimeError as exc:
            record("allow_switch", (False, str(exc)))
            switch_done.set()
            return

        time.sleep(0.2)
        success, detail = try_unlink(path)
        print(f"[allow-thread] 第二次 unlink 结果: success={success}, detail={detail}")
        record("allow_second", (success, detail))
        switch_done.set()

        time.sleep(0.1)
        try:
            switch_profile(PROFILE_DEFAULT)
            print(f"[allow-thread] 已恢复为默认 profile {PROFILE_DEFAULT}")
        except RuntimeError as exc:
            record("allow_reset", (False, str(exc)))

    cleanup_profile_set = False
    try:
        with TemporaryDirectory(prefix="thread_whitelist_") as tmp:
            base_dir = Path(tmp)
            thread_a = threading.Thread(
                target=default_thread, args=(base_dir,), name="default"
            )
            thread_b = threading.Thread(
                target=allow_thread, args=(base_dir,), name="allow"
            )

            thread_a.start()
            thread_b.start()

            thread_a.join(timeout=15)
            thread_b.join(timeout=15)

            if thread_a.is_alive() or thread_b.is_alive():
                print("线程未在预期时间内结束", file=sys.stderr)
                return 1

            try:
                switch_profile(PROFILE_ALLOW_UNLINK, retry=True, timeout=3.0)
                cleanup_profile_set = True
            except RuntimeError as exc:
                print(f"清理前切换到允许 profile 失败: {exc}", file=sys.stderr)
                cleanup_profile_set = False

    finally:
        if cleanup_profile_set:
            try:
                switch_profile(PROFILE_DEFAULT, retry=True, timeout=3.0)
            except RuntimeError as exc:
                print(f"恢复默认 profile 失败: {exc}", file=sys.stderr)

    expected = {
        "default_second": False,
        "allow_second": True,
    }

    ok = True
    for key, must_be_success in expected.items():
        if key not in results:
            print(f"缺少结果 {key}", file=sys.stderr)
            ok = False
            continue
        actual_success = results[key][0]
        if actual_success != must_be_success:
            print(
                f"断言失败: {key} 预期 success={must_be_success}，实际 {actual_success}"
                f"，细节: {results[key][1]}",
                file=sys.stderr,
            )
            ok = False

    # 检查是否有 barrier/切换错误记录
    for key in (
        "default_barrier",
        "default_wait",
        "allow_barrier",
        "allow_switch",
        "allow_reset",
        "default_register",
        "allow_register",
    ):
        if key in results and not results[key][0]:
            print(f"{key} 失败: {results[key][1]}", file=sys.stderr)
            ok = False

    if not ok:
        print("THREAD_WHITELIST_TEST:FAIL")
        return 1

    print("THREAD_WHITELIST_TEST:PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
