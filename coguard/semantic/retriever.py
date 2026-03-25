from __future__ import annotations

import json
from typing import Dict, List, Optional, Sequence
from urllib import error, request

from ..config import AppConfig
from ..models import RelationCandidate, SchemaRelation
from .prompts import build_retriever_query, schema_relation_texts
from .vectorizer import top_k_similarities, vectorize


class BaseSchemaRetriever:
    backend_name = "vector"

    def __init__(self) -> None:
        self._warnings: List[str] = []

    def retrieve(
        self,
        query: str,
        schema_relations: Sequence[SchemaRelation],
        top_k: int,
    ) -> List[RelationCandidate]:
        raise NotImplementedError

    def drain_warnings(self) -> List[str]:
        warnings = list(self._warnings)
        self._warnings.clear()
        return warnings


class VectorSimilaritySchemaRetriever(BaseSchemaRetriever):
    backend_name = "vector"

    def __init__(self, instruction_template: str) -> None:
        super().__init__()
        self.instruction_template = instruction_template

    def retrieve(
        self,
        query: str,
        schema_relations: Sequence[SchemaRelation],
        top_k: int,
    ) -> List[RelationCandidate]:
        # This lightweight fallback keeps refinement available even without a
        # dedicated retriever model or embedding service.
        query_text = build_retriever_query(query, self.instruction_template)
        scored = top_k_similarities(
            vectorize(query_text),
            ((relation.name, relation.definition) for relation in schema_relations),
            top_k,
        )
        return [
            RelationCandidate(name=name, definition=definition, score=score)
            for name, definition, score in scored
        ]


class SentenceTransformerSchemaRetriever(BaseSchemaRetriever):
    backend_name = "sentence_transformer"

    def __init__(
        self,
        model_name_or_path: str,
        instruction_template: str,
        fallback: Optional[BaseSchemaRetriever] = None,
    ) -> None:
        super().__init__()
        self.model_name_or_path = model_name_or_path
        self.instruction_template = instruction_template
        self.fallback = fallback
        self._model = None
        self._schema_cache: Dict[str, List[float]] = {}

    def retrieve(
        self,
        query: str,
        schema_relations: Sequence[SchemaRelation],
        top_k: int,
    ) -> List[RelationCandidate]:
        try:
            model = self._load_model()
        except Exception as exc:
            # Retriever failure should degrade gracefully instead of blocking the
            # entire pipeline.
            self._warnings.append(
                "Sentence-transformer schema retriever failed to load, falling back to vector retriever: %s"
                % exc
            )
            if self.fallback is not None:
                return self.fallback.retrieve(query, schema_relations, top_k)
            raise

        query_text = build_retriever_query(query, self.instruction_template)
        query_embedding = self._encode(model, [query_text])[0]
        scored = []
        for relation in schema_relations:
            cache_key = "%s::%s" % (relation.name, relation.definition)
            if cache_key not in self._schema_cache:
                self._schema_cache[cache_key] = self._encode(
                    model,
                    ["%s: %s" % (relation.name, relation.definition)],
                )[0]
            score = self._cosine_similarity(query_embedding, self._schema_cache[cache_key])
            scored.append(
                RelationCandidate(
                    name=relation.name,
                    definition=relation.definition,
                    score=score,
                )
            )
        scored.sort(key=lambda item: item.score, reverse=True)
        return scored[:top_k]

    def _load_model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self.model_name_or_path)
        return self._model

    def _encode(self, model, texts: Sequence[str]) -> List[List[float]]:
        embeddings = model.encode(list(texts), normalize_embeddings=True)
        return [embedding.tolist() for embedding in embeddings]

    def _cosine_similarity(self, left: Sequence[float], right: Sequence[float]) -> float:
        if not left or not right:
            return 0.0
        return sum(l * r for l, r in zip(left, right))


class OpenAIEmbeddingSchemaRetriever(BaseSchemaRetriever):
    backend_name = "openai_embedding"

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "",
        timeout_seconds: float = 60.0,
        instruction_template: str = "Instruct: retrieve relations that are present in the given text\nQuery: {text}",
        fallback: Optional[BaseSchemaRetriever] = None,
    ) -> None:
        super().__init__()
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.instruction_template = instruction_template
        self.fallback = fallback
        self._schema_cache: Dict[str, List[float]] = {}

    def retrieve(
        self,
        query: str,
        schema_relations: Sequence[SchemaRelation],
        top_k: int,
    ) -> List[RelationCandidate]:
        try:
            query_text = build_retriever_query(query, self.instruction_template)
            query_embedding = self._embed([query_text])[0]
            scored = []
            for relation, relation_text in zip(schema_relations, schema_relation_texts(schema_relations)):
                cache_key = relation_text
                if cache_key not in self._schema_cache:
                    self._schema_cache[cache_key] = self._embed([relation_text])[0]
                score = self._cosine_similarity(query_embedding, self._schema_cache[cache_key])
                scored.append(
                    RelationCandidate(
                        name=relation.name,
                        definition=relation.definition,
                        score=score,
                    )
                )
            scored.sort(key=lambda item: item.score, reverse=True)
            return scored[:top_k]
        except Exception as exc:
            self._warnings.append(
                "Embedding schema retriever failed, falling back to vector retriever: %s"
                % exc
            )
            if self.fallback is not None:
                return self.fallback.retrieve(query, schema_relations, top_k)
            raise

    def _embed(self, texts: Sequence[str]) -> List[List[float]]:
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
            raise RuntimeError("Embedding request failed: %s" % exc) from exc
        return [item["embedding"] for item in data.get("data", [])]

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer %s" % self.api_key
        return headers

    def _cosine_similarity(self, left: Sequence[float], right: Sequence[float]) -> float:
        if not left or not right:
            return 0.0
        return sum(l * r for l, r in zip(left, right))


def build_schema_retriever(config: AppConfig) -> BaseSchemaRetriever:
    # Every backend shares the same vector fallback, which makes experiments
    # easy to swap without changing the rest of the pipeline.
    fallback = VectorSimilaritySchemaRetriever(
        instruction_template=config.schema_retriever_instruction,
    )
    backend = config.schema_retriever_backend.lower()
    if backend == "sentence_transformer":
        return SentenceTransformerSchemaRetriever(
            model_name_or_path=config.schema_retriever_model,
            instruction_template=config.schema_retriever_instruction,
            fallback=fallback,
        )
    if backend == "openai_embedding":
        return OpenAIEmbeddingSchemaRetriever(
            base_url=config.schema_retriever_base_url,
            model=config.schema_retriever_model,
            api_key=config.schema_retriever_api_key,
            timeout_seconds=config.llm_timeout_seconds,
            instruction_template=config.schema_retriever_instruction,
            fallback=fallback,
        )
    return fallback
