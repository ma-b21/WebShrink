import orjson as json
import os
from datetime import datetime
from typing import Any


def ns_datetime_str_to_int(ns_datetime_str: str) -> int:
    time_str_micro = ns_datetime_str[:26]
    ns = ns_datetime_str[-3:]

    # 使用strptime解析
    dt = datetime.strptime(time_str_micro, "%Y-%m-%d %H:%M:%S.%f")
    return int(dt.timestamp() * (10**6)) * (10**3) + int(ns)


def ns_datetime_str_to_datetime(ns_datetime_str: str) -> datetime:
    """
    注意有精度丢失：只能精确到微秒
    """
    # 手动解析各个部分
    year = int(ns_datetime_str[0:4])
    month = int(ns_datetime_str[5:7])
    day = int(ns_datetime_str[8:10])
    hour = int(ns_datetime_str[11:13])
    minute = int(ns_datetime_str[14:16])
    second = int(ns_datetime_str[17:19])
    microsecond = int(ns_datetime_str[20:26])

    return datetime(year, month, day, hour, minute, second, microsecond)


def ns_datetime_datetime_to_str(dt: datetime) -> str:
    time_str_micro = dt.strftime("%Y-%m-%d %H:%M:%S.%f")
    ns = f"{dt.microsecond * 1000:03d}"[-3:]
    return f"{time_str_micro}{ns}"


def ns_datetime_int_to_str(ns_datetime_int: int) -> str:
    dt = datetime.fromtimestamp(ns_datetime_int / (10**9))
    time_str_micro = dt.strftime("%Y-%m-%d %H:%M:%S.%f")
    ns = f"{dt.microsecond * 1000:03d}"[-3:]
    return f"{time_str_micro}{ns}"


def flatten_dict(d: dict[str, Any]) -> dict[str, Any]:
    """
    将
    ```python
    {
        'a': {
            'b': {
                'c': 'd'
            }
        }
    }
    ```

    变成
    ```python
    {
        'a.b.c': 'd',
        'a.b': {
            'c': 'd'
        },
        'a': {
            'b': {
                'c': 'd'
            }
        }
    }
    ```
    """
    ret: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, dict):
            flatten_v = flatten_dict(v)
            for kk, vv in flatten_v.items():
                ret[f"{k}.{kk}"] = vv
        ret[k] = v
    return ret


def format_dict(d: dict[Any, Any]) -> str:
    return json.dumps(d, option=json.OPT_INDENT_2).decode()


def str_batch_replace(s: str, new: str, *olds: str) -> str:
    for old in olds:
        s = s.replace(old, new)
    return s


def underline_to_big_camel_case(string: str) -> str:
    splited = string.split("_")
    return "".join([s[0].upper() + s[1:] for s in splited])


def longest_common_parent_path(paths: list[str]) -> str:
    if not paths:
        return ""

    # 将路径拆分为各个部分
    split_paths = [path.split(os.sep) for path in paths]

    # 找到最短路径的长度
    min_length = min(len(parts) for parts in split_paths)

    common_path = []
    for i in range(min_length):
        # 获取所有路径的第i部分
        current = [parts[i] for parts in split_paths]

        # 如果所有路径的第i部分都相同，则加入公共路径
        if all(c == current[0] for c in current):
            common_path.append(current[0])
        else:
            break

    # 将公共路径部分拼接成完整路径
    return os.sep.join(common_path)
