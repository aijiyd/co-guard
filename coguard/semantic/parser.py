from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Sequence, Tuple

from ..models import NormalizedTriple, RawTriple, RelationCandidate, SchemaRelation
from .llm import BaseLLMAdapter
from .schema import DEFAULT_SCHEMA_RELATIONS, exact_schema_match
from .vectorizer import cosine_similarity, top_k_similarities, vectorize


ENTITY_TRIM_CHARS = " \t\r\n,.;:!?，。；：！？()[]{}<>《》\"'“”‘’"


class SemanticParser:
    def __init__(
        self,
        llm_adapter: BaseLLMAdapter,
        schema_relations: List[SchemaRelation] = None,
        top_k: int = 3,
        cluster_threshold: float = 0.62,
        schema_match_threshold: float = 0.28,
    ) -> None:
        self.llm_adapter = llm_adapter
        self.schema_relations = schema_relations or DEFAULT_SCHEMA_RELATIONS
        self.top_k = top_k
        self.cluster_threshold = cluster_threshold
        self.schema_match_threshold = schema_match_threshold

    def parse(
        self,
        query: str,
        candidate_entities: Sequence[str] | None = None,
        candidate_relations: Sequence[SchemaRelation] | None = None,
    ) -> List[NormalizedTriple]:
        # Follow the EDC stages closely:
        # 1) extract raw triples
        # 2) define each relation in context
        # 3) map relations into the canonical schema
        # 4) cluster semantically similar relations within the same query
        raw_triples = self.llm_adapter.extract_triples(
            query=query,
            candidate_entities=candidate_entities,
            candidate_relations=candidate_relations,
        )
        relation_definitions = self.llm_adapter.define_relations(query=query, triples=raw_triples)
        normalized = []
        for raw_triple in raw_triples:
            subject = self._normalize_entity(raw_triple.subject)
            object_name = self._normalize_entity(raw_triple.object)
            relation_definition = relation_definitions.get(
                raw_triple.relation,
                self.llm_adapter.define_relation(
                    query=query,
                    triple=raw_triple,
                    triples=raw_triples,
                ),
            )
            relation_name, confidence, candidates = self._normalize_relation(
                query=query,
                raw_triple=raw_triple,
                relation_definition=relation_definition,
            )
            normalized.append(
                NormalizedTriple(
                    subject=subject,
                    raw_relation=raw_triple.relation,
                    object=object_name,
                    relation_definition=relation_definition,
                    normalized_relation=relation_name,
                    confidence=confidence,
                    candidate_relations=candidates,
                )
            )

        cluster_ids = self._cluster_relations(normalized)
        for index, triple in enumerate(normalized):
            triple.cluster_id = cluster_ids[index]
        return normalized

    def _normalize_relation(
        self,
        query: str,
        raw_triple: RawTriple,
        relation_definition: str,
    ) -> Tuple[str, float, List[RelationCandidate]]:
        # Canonicalization is "retrieve then verify" rather than "take the top
        # score", so out-of-schema relations can remain custom when needed.
        relation_vector = vectorize(relation_definition)
        candidates = top_k_similarities(
            relation_vector,
            ((schema.name, schema.definition) for schema in self.schema_relations),
            self.top_k,
        )
        exact_match = exact_schema_match(raw_triple.relation)
        if exact_match:
            candidates = self._promote_exact_match(candidates, exact_match)

        candidate_models = [
            RelationCandidate(name=name, definition=definition, score=score)
            for name, definition, score in candidates
        ]
        if not candidate_models:
            return self._custom_relation_name(raw_triple.relation), 0.0, []

        if exact_match:
            return candidate_models[0].name, candidate_models[0].score, candidate_models

        selected_relation = self.llm_adapter.choose_canonical_relation(
            query=query,
            triple=raw_triple,
            relation_definition=relation_definition,
            candidates=candidate_models,
        )
        if selected_relation:
            selected_candidate = next(
                (
                    candidate
                    for candidate in candidate_models
                    if candidate.name == selected_relation
                ),
                candidate_models[0],
            )
            return selected_candidate.name, selected_candidate.score, candidate_models

        best_candidate = candidate_models[0]
        if best_candidate.score < self.schema_match_threshold:
            return (
                self._custom_relation_name(raw_triple.relation),
                best_candidate.score,
                candidate_models,
            )
        return (
            self._custom_relation_name(raw_triple.relation),
            best_candidate.score,
            candidate_models,
        )

    def _promote_exact_match(
        self, candidates: List[Tuple[str, str, float]], exact_match: str
    ) -> List[Tuple[str, str, float]]:
        promoted = []
        seen_exact = False
        for name, definition, score in candidates:
            if name == exact_match:
                promoted.append((name, definition, max(score, 0.99)))
                seen_exact = True
            else:
                promoted.append((name, definition, score))
        if not seen_exact:
            for schema in self.schema_relations:
                if schema.name == exact_match:
                    promoted.append((schema.name, schema.definition, 0.99))
                    break
        promoted.sort(key=lambda item: item[2], reverse=True)
        return promoted[: self.top_k]

    def _cluster_relations(self, triples: List[NormalizedTriple]) -> List[int]:
        # A small union-find assigns query-local cluster ids to relation
        # definitions that are semantically close.
        size = len(triples)
        if size == 0:
            return []
        parents = list(range(size))
        vectors = [vectorize(triple.relation_definition) for triple in triples]

        def find(index: int) -> int:
            while parents[index] != index:
                parents[index] = parents[parents[index]]
                index = parents[index]
            return index

        def union(left: int, right: int) -> None:
            left_root = find(left)
            right_root = find(right)
            if left_root != right_root:
                parents[right_root] = left_root

        for left_index in range(size):
            for right_index in range(left_index + 1, size):
                if (
                    cosine_similarity(vectors[left_index], vectors[right_index])
                    >= self.cluster_threshold
                ):
                    union(left_index, right_index)

        cluster_lookup: Dict[int, int] = {}
        cluster_ids = []
        next_cluster_id = 0
        for index in range(size):
            root = find(index)
            if root not in cluster_lookup:
                cluster_lookup[root] = next_cluster_id
                next_cluster_id += 1
            cluster_ids.append(cluster_lookup[root])
        return cluster_ids

    def _normalize_entity(self, text: str) -> str:
        # Entity normalization is intentionally conservative to avoid over-merging
        # before graph storage and later entity-similarity expansion.
        cleaned = text.strip(ENTITY_TRIM_CHARS)
        cleaned = re.sub(r"\s+", " ", cleaned)
        if re.fullmatch(r"[A-Za-z0-9_./:-]+", cleaned):
            return cleaned.lower()
        return cleaned

    def _custom_relation_name(self, relation: str) -> str:
        slug = re.sub(r"[^a-z0-9]+", "_", relation.lower()).strip("_")
        if not slug:
            slug = "rel_%s" % hashlib.sha1(relation.encode("utf-8")).hexdigest()[:8]
        return "custom_%s" % slug
