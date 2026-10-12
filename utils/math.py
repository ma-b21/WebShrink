import math
from typing import Callable, Mapping, Sequence


def jaccard_similarity[T](set1: set[T], set2: set[T]) -> float:
    intersection = set1.intersection(set2)
    union = set1.union(set2)
    if not union:
        # 两个都是空集
        return 1
    return len(intersection) / len(union)


def cosine_similarity[K](d1: Mapping[K, float], d2: Mapping[K, float]) -> float:
    all_keys = set(d1.keys()) | set(d2.keys())
    dot_product = sum([d1.get(k, 0) * d2.get(k, 0) for k in all_keys])
    magnitude1 = math.sqrt(sum([d1.get(k, 0) ** 2 for k in all_keys]))
    magnitude2 = math.sqrt(sum([d2.get(k, 0) ** 2 for k in all_keys]))
    divider = magnitude1 * magnitude2
    if divider == 0:
        return 0
    return dot_product / divider


def dissimilarity[
    T
](me: T, all_items: Sequence[T], similarity_func: Callable[[T, T], float]) -> float:
    if not me:
        return 0.0
    similarity_scores = [similarity_func(me, s) for s in all_items]
    avg_similarity_score = sum(similarity_scores) / len(similarity_scores)
    return 1 - avg_similarity_score
