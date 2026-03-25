from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, Iterable, List


ASCII_PATTERN = re.compile(r"[a-z0-9_]+")


def tokenize(text: str) -> List[str]:
    # A tiny bilingual tokenizer is enough for schema matching and entity
    # relatedness, where simplicity matters more than linguistic perfection.
    lowered = text.lower()
    ascii_tokens = ASCII_PATTERN.findall(lowered)
    chinese_chars = [char for char in text if "\u4e00" <= char <= "\u9fff"]
    bigrams = [
        chinese_chars[index] + chinese_chars[index + 1]
        for index in range(len(chinese_chars) - 1)
    ]
    return ascii_tokens + chinese_chars + bigrams


def vectorize(text: str) -> Dict[str, float]:
    tokens = tokenize(text)
    if not tokens:
        return {}
    counts = Counter(tokens)
    total = float(sum(counts.values()))
    return {token: count / total for token, count in counts.items()}


def cosine_similarity(left: Dict[str, float], right: Dict[str, float]) -> float:
    if not left or not right:
        return 0.0
    dot = sum(left.get(token, 0.0) * right.get(token, 0.0) for token in left)
    left_norm = math.sqrt(sum(value * value for value in left.values()))
    right_norm = math.sqrt(sum(value * value for value in right.values()))
    if not left_norm or not right_norm:
        return 0.0
    return dot / (left_norm * right_norm)


def top_k_similarities(
    vector: Dict[str, float],
    candidates: Iterable[tuple],
    k: int,
) -> List[tuple]:
    # The schema is intentionally small, so on-the-fly scoring is simpler than
    # maintaining a separate vector index.
    scored = []
    for name, definition in candidates:
        score = cosine_similarity(vector, vectorize(definition))
        scored.append((name, definition, score))
    scored.sort(key=lambda item: item[2], reverse=True)
    return scored[:k]
