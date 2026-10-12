from enum import auto
from typing import overload
from urllib.parse import urlparse

from utils.typing import AutoStrEnum


class Method(AutoStrEnum):
    GET = auto()
    POST = auto()
    PUT = auto()
    DELETE = auto()
    HEAD = auto()
    OPTIONS = auto()
    TRACE = auto()
    PATCH = auto()
    OTHER = auto()


def is_valid_status_code(code: int) -> bool:
    return 200 <= code < 300


class Uri:
    __slots__ = ["tokens", "url", "method"]

    @overload
    def __init__(self, method: Method, url: str, tokens: None = None) -> None: ...

    @overload
    def __init__(
        self, method: Method, url: None = None, tokens: list[str] = []
    ) -> None: ...

    def __init__(self, method: Method, url=None, tokens=None):
        if url:
            parse_result = urlparse(url)
            self.tokens = get_url_tokens(parse_result.path)
            self.url = parse_result.path
        elif tokens:
            self.tokens = tokens
            self.url = f"/{'/'.join(tokens)}"
        self.method = method

    @classmethod
    def from_request_string(cls, request: str) -> "Uri | None":
        request = request.strip()
        if " " not in request:
            return None
        method, url = request.split(" ")[:2]
        if method.upper() in Method:
            return cls(Method(method.upper()), url)
        return None

    def __repr__(self) -> str:
        return f"Uri(url='{self.url}', method={self.method})"

    def __hash__(self) -> int:
        return hash(self.method + self.url)

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Uri):
            return False
        return self.method == value.method and self.url == value.url


def get_url_tokens(url_path: str) -> list[str]:
    return [token for token in url_path.split("/") if token]
