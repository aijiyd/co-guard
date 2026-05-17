from __future__ import annotations

import json
import math
import os
from typing import Dict, List, Sequence
from urllib import error, request

from ..config import AppConfig
from .vectorizer import cosine_similarity as sparse_cosine_similarity
from .vectorizer import vectorize


class BaseSemanticEmbedder:
    backend_name = "vector"

    def __init__(self) -> None:
        self._warnings: List[str] = []

    def embed(self, texts: Sequence[str]) -> List[object]:
        raise NotImplementedError

    def similarity(self, left: object, right: object) -> float:
        raise NotImplementedError

    def drain_warnings(self) -> List[str]:
        warnings = list(self._warnings)
        self._warnings.clear()
        return warnings


class LightweightVectorSemanticEmbedder(BaseSemanticEmbedder):
    backend_name = "vector"

    def embed(self, texts: Sequence[str]) -> List[object]:
        return [vectorize(text) for text in texts]

    def similarity(self, left: object, right: object) -> float:
        if not isinstance(left, dict) or not isinstance(right, dict):
            return 0.0
        return sparse_cosine_similarity(left, right)


class OpenAICompatibleSemanticEmbedder(BaseSemanticEmbedder):
    backend_name = "openai_embedding"

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str = "",
        timeout_seconds: float = 60.0,
        fallback: BaseSemanticEmbedder | None = None,
    ) -> None:
        super().__init__()
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key or os.getenv("DASHSCOPE_API_KEY", "")
        self.timeout_seconds = timeout_seconds
        self.fallback = fallback

    def embed(self, texts: Sequence[str]) -> List[object]:
        if not texts:
            return []
        if not self.model:
            if self.fallback is None:
                raise ValueError("embedding backend requires a model name")
            self._warnings.append(
                "Semantic embedding backend has no model configured, falling back to lightweight vectors."
            )
            return self.fallback.embed(texts)
        payload = json.dumps({"model": self.model, "input": list(texts)}).encode("utf-8")
        req = request.Request(
            "%s/embeddings" % self.base_url,
            data=payload,
            headers=self._headers(),
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
        except error.URLError as exc:  # pragma: no cover - network dependent
            if self.fallback is None:
                raise RuntimeError("embedding request failed: %s" % exc) from exc
            self._warnings.append(
                "Semantic embedding request failed, falling back to lightweight vectors: %s"
                % exc
            )
            return self.fallback.embed(texts)

        embeddings = [item.get("embedding", []) for item in data.get("data", [])]
        if len(embeddings) != len(texts):
            if self.fallback is None:
                raise RuntimeError("embedding response length mismatch")
            self._warnings.append(
                "Semantic embedding response length mismatch, falling back to lightweight vectors."
            )
            return self.fallback.embed(texts)
        return embeddings

    def similarity(self, left: object, right: object) -> float:
        if not isinstance(left, list) or not isinstance(right, list):
            if self.fallback is None:
                return 0.0
            return self.fallback.similarity(left, right)
        if not left or not right:
            return 0.0
        dot = sum(float(l) * float(r) for l, r in zip(left, right))
        left_norm = math.sqrt(sum(float(value) * float(value) for value in left))
        right_norm = math.sqrt(sum(float(value) * float(value) for value in right))
        if not left_norm or not right_norm:
            return 0.0
        return dot / (left_norm * right_norm)

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer %s" % self.api_key
        return headers


def build_semantic_embedder(config: AppConfig) -> BaseSemanticEmbedder:
    fallback = LightweightVectorSemanticEmbedder()
    backend = (config.semantic_embedding_backend or "vector").strip().lower()
    if backend in {"", "vector"}:
        return fallback
    if backend in {"openai_embedding", "aliyun_bailian_embedding", "dashscope_embedding"}:
        return OpenAICompatibleSemanticEmbedder(
            base_url=config.semantic_embedding_base_url,
            model=config.semantic_embedding_model,
            api_key=config.semantic_embedding_api_key,
            timeout_seconds=config.llm_timeout_seconds,
            fallback=fallback,
        )
    raise ValueError("unsupported semantic embedding backend: %s" % backend)
