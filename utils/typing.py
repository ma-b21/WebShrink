from enum import Enum
from types import GenericAlias
from typing import Any, Callable, Mapping, ParamSpec, Sequence

type GenericAliasTuple = tuple[type] | tuple[type, tuple[GenericAliasTuple, ...]]


def expand_generic_alias(alias: GenericAlias | type) -> GenericAliasTuple:
    if isinstance(alias, GenericAlias):
        return (
            alias.__origin__,
            tuple(expand_generic_alias(arg) for arg in alias.__args__),
        )
    else:
        return (alias,)


class AutoStrEnum(str, Enum):
    """
    StrEnum where auto() returns the field name.
    See https://docs.python.org/3.9/library/enum.html#using-automatic-values
    """

    @staticmethod
    def _generate_next_value_(
        name: str, start: int, count: int, last_values: list
    ) -> str:
        return name


JSONType = (
    Mapping[str, "JSONType"] | Sequence["JSONType"] | str | int | float | bool | None
)
NotNoneJSONType = Mapping[str, JSONType] | Sequence[JSONType] | str | int | float | bool

P = ParamSpec("P")


def except_to_bool_result(
    f: Callable[P, Any], *args: P.args, **kwargs: P.kwargs
) -> bool:
    """
    执行 `f`，若其抛出任何异常则返回 False，否则返回 True
    """
    try:
        f(*args, **kwargs)
        return True
    except:
        return False
