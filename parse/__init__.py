from datetime import datetime
from typing import Literal, NotRequired, TypedDict

from loguru import logger

Log = TypedDict(
    "Log",
    {
        "container.id": str,
        # 事件 ID
        "evt.num": int,
        # 事件的参数
        "evt.arg.data": str | None,
        "evt.arg.pid": int | None,
        "evt.arg.filename": str | None,
        "evt.arg.oldpath": str | None,
        "evt.arg.newpath": str | None,
        # 事件类别
        "evt.category": Literal["net", "file", "memory"],
        # 事件方向，> 代表参数，< 代表结果
        "evt.dir": NotRequired[Literal["<", ">"]],
        # syscall 返回值，仅在 < 方向有
        "evt.rawres": int | None,
        # 事件的时间戳 (ns)
        "evt.datetime": str,
        # syscall
        "evt.type": str,
        # 是否读写
        "evt.is_io_read": bool | None,
        "evt.is_io_write": bool | None,
        # 文件目录
        "fd.directory": str | None,
        # 文件路径，或者 x.x.x.x:port->y.y.y.y:port
        "fd.name": str | None,
        # fd 数字
        "fd.num": int | None,
        # 文件类型
        "fd.type": Literal["file", "ipv4", "ipv6"] | str | None,
        # 本地和远程 IP
        "fd.lip": str | None,
        "fd.rip": str | None,
        # server / client IP
        "fd.cip": str | None,
        "fd.sip": str | None,
        # 本地和远程端口
        "fd.lport": int | None,
        "fd.rport": int | None,
        # server / client 端口
        "fd.cport": int | None,
        "fd.sport": int | None,
        # 进程名
        "proc.name": str,
        # 进程 id
        "proc.pid": int,
        # 进程路径
        "proc.exepath": str,
        # 线程 id
        "thread.tid": int,
        "thread.vtid": int,
    },
)


class LogCombiner:
    def __init__(self) -> None:
        self.cache: dict[int, Log] = {}

    def parse(self, log: Log) -> Log | None:
        tid = log["thread.tid"]
        match log.get("evt.dir", "<"):
            case ">":
                self.cache[tid] = log
            case "<":
                input_log = self.cache.pop(tid, {})
                if not input_log:
                    logger.warning(f"> log of thread {tid} not found")
                for k, v in input_log.items():
                    if not log.get(k):
                        log[k] = v
                del log["evt.dir"]
                return log


def process_format(log: Log) -> Log:
    if isinstance(log["evt.datetime"], int):
        # Sysdig may decode timestamps from scap files as integer nanoseconds.
        timestamp_ns = log["evt.datetime"]
        # 转换为秒和纳秒
        timestamp_s = timestamp_ns // 10**9  # 整数秒部分
        remaining_ns = timestamp_ns % 10**9  # 纳秒部分

        # 转换为 datetime 对象
        dt = datetime.fromtimestamp(timestamp_s)

        # 格式化为带纳秒的字符串
        log["evt.datetime"] = f"{dt.strftime('%Y-%m-%d %H:%M:%S')}.{remaining_ns:09d}"
    return log
