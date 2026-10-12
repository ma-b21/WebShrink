from typing import Container


def dict_diff[K, V](a: dict[K, V], b: dict[K, V]) -> dict[K, V]:
    """
    returns a - b like set operation
    """
    keys = set(a.keys()) - set(b.keys())
    return {k: a[k] for k in keys}


def dict_intersect[K, V](a: dict[K, V], b: Container[K]) -> dict[K, V]:
    """
    return keys in both a and b, and their values from a
    """
    return {k: v for k, v in a.items() if k in b}


class InversibleDict[K, V](dict[K, V]):
    def __init__(self) -> None:
        super().__init__()
        self.inverse_query: dict[V, set[K]] = {}

    def __setitem__(self, key: K, value: V) -> None:
        exist_value = self.get(key)
        if exist_value is not None:
            self.inverse_query[exist_value].remove(key)
            if not self.inverse_query[exist_value]:
                del self.inverse_query[exist_value]
        self.inverse_query.setdefault(value, set()).add(key)
        return super().__setitem__(key, value)

    def __delitem__(self, key: K) -> None:
        value = self[key]
        self.inverse_query[value].remove(key)
        if not self.inverse_query[value]:
            del self.inverse_query[value]
        return super().__delitem__(key)

    def delvalue(self, value: V) -> None:
        keys = self.inverse_query.get(value, set())
        if keys:
            del self.inverse_query[value]
        for k in keys:
            super().__delitem__(k)
