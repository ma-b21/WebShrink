import asyncio
from datetime import datetime
from typing import Callable, Generator


def get_current_time() -> str:
    now = datetime.now()
    formatted_time = now.strftime("%Y_%m%d_%H%M_%S")
    return formatted_time


async def generator_to_queue[
    V, T
](
    generator: Callable[[], Generator[V, None, None]],
    queue: asyncio.Queue[tuple[T, V] | None],
    tag: T,
) -> None:
    """将生成器的产出值放入异步队列"""
    for item in generator():
        await queue.put((tag, item))
    await queue.put(None)  # 用于标记生成器完成


class IncreaseIdGen:
    def __init__(self) -> None:
        self.value = 0

    def gen(self) -> int:
        val = self.value
        self.value += 1
        return val
