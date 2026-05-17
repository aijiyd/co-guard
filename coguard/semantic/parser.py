from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Sequence, Tuple

from ..models import CanonicalizationItem, NormalizedTriple, RawTriple, RelationCandidate, SchemaRelation
from .agents import SemanticAgentCoordinator
from .embedding import BaseSemanticEmbedder, LightweightVectorSemanticEmbedder
from .llm import BaseLLMAdapter
from .schema import DEFAULT_SCHEMA_RELATIONS, exact_schema_match


ENTITY_TRIM_CHARS = " \t\r\n,.;:!?，。；：！？()[]{}<>《》\"'“”‘’"
GENERIC_QUERY_RELATIONS = {"ask", "asks", "request", "requests", "requests_information"}
LEADING_QUERY_PREFIX = re.compile(
    r"^(?:what|which|how|why|when|where|who)\b\s+",
    flags=re.IGNORECASE,
)
LEADING_QUERY_AUXILIARY = re.compile(
    r"^(?:is|are|was|were|can|could|should|would|do|does|did)\b\s+",
    flags=re.IGNORECASE,
)
LEADING_ACTION_PREFIX = re.compile(
    r"^(?:define|identify|determine|select|scope|research|develop|learn(?:\s+about)?|gain familiarity with|create|describe|discuss|explore|detail|outline)\s+",
    flags=re.IGNORECASE,
)
PLANNING_RELATION_PATTERNS = (
    (
        "identifies_target",
        (
            r"\btarget(?:ing|ed)?\b",
            r"\btype and scope\b",
            r"\bscope of\b",
            r"\bgovernment database\b",
            r"\bdatabase system\b",
            r"\bwhich software\b",
            r"\bwhich operating system\b",
            r"\bvictim\b",
        ),
    ),
    (
        "discovers_weakness",
        (
            r"\bvulnerab(?:ility|ilities)\b",
            r"\bweakness(?:es)?\b",
            r"\battack vector(?:s)?\b",
            r"\baccess control measure(?:s)?\b",
            r"\bnetwork architecture\b",
            r"\bconfirm(?:ed)? and verif(?:y|ied)\b",
            r"\bidentify these vulnerabilities\b",
        ),
    ),
    (
        "acquires_capability",
        (
            r"\btools?\b",
            r"\btechniques?\b",
            r"\bgain familiarity\b",
            r"\blearn about\b",
            r"\btraining\b",
            r"\beducation\b",
            r"\btypes and parts\b",
            r"\bparts of firearms\b",
            r"\bencryption\b",
            r"\bdecryption\b",
            r"\bmethods?\b",
        ),
    ),
    (
        "plans_execution",
        (
            r"\bwhat steps\b",
            r"\bsteps are involved\b",
            r"\bhow to\b",
            r"\baccess and use\b",
            r"\bexploit(?:ing)?\b",
            r"\bhack(?:ing)? into\b",
            r"\bsteal(?:ing)? sensitive information\b",
            r"\buse firearms\b",
        ),
    ),
    (
        "plans_evasion",
        (
            r"\bavoid detection\b",
            r"\bdetection\b",
            r"\bcontingency plan\b",
            r"\bpotential consequences\b",
            r"\bminimi[sz]e(?:d|s|ing)? the impact\b",
            r"\bmitigate the risks\b",
            r"\bcover tracks\b",
            r"\bevade\b",
        ),
    ),
)


class SemanticParser:
    def __init__(
        self,
        llm_adapter: BaseLLMAdapter,
        schema_relations: List[SchemaRelation] = None,
        top_k: int = 3,
        cluster_threshold: float = 0.62,
        schema_match_threshold: float = 0.28,
        agent_coordinator: SemanticAgentCoordinator | None = None,
        semantic_embedder: BaseSemanticEmbedder | None = None,
    ) -> None:
        self.llm_adapter = llm_adapter
        self.agent_coordinator = agent_coordinator or SemanticAgentCoordinator(llm_adapter)
        self.schema_relations = schema_relations or DEFAULT_SCHEMA_RELATIONS
        self.top_k = top_k
        self.cluster_threshold = cluster_threshold
        self.schema_match_threshold = schema_match_threshold
        self.semantic_embedder = semantic_embedder or LightweightVectorSemanticEmbedder()
        self._schema_embedding_cache: Dict[str, object] = {}

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
        raw_triples = self.agent_coordinator.extract_triples(
            query=query,
            candidate_entities=candidate_entities,
            candidate_relations=candidate_relations,
        )
        raw_triples = self._augment_query_intent_triples(query, raw_triples)
        relation_definitions = self.agent_coordinator.define_relations(
            query=query,
            triples=raw_triples,
        )
        prepared_triples = []
        batch_items = []
        batch_indices = []
        for raw_triple in raw_triples:
            subject = self._normalize_entity(raw_triple.subject)
            object_name = self._normalize_entity(raw_triple.object)
            # Avoid eagerly re-running definition generation inside dict.get(...).
            relation_definition = relation_definitions.get(raw_triple.relation)
            if relation_definition is None:
                relation_definition = self.agent_coordinator.define_relation(
                    query=query,
                    triple=raw_triple,
                    triples=raw_triples,
                )
            candidates, exact_match = self._retrieve_relation_candidates(
                raw_triple=raw_triple,
                relation_definition=relation_definition,
            )
            prepared_triples.append(
                {
                    "raw_triple": raw_triple,
                    "subject": subject,
                    "object": object_name,
                    "relation_definition": relation_definition,
                    "candidates": candidates,
                    "exact_match": exact_match,
                }
            )
            if not exact_match and candidates:
                batch_indices.append(len(prepared_triples) - 1)
                batch_items.append(
                    CanonicalizationItem(
                        triple=raw_triple,
                        relation_definition=relation_definition,
                        candidates=list(candidates),
                    )
                )

        batch_choices = self.agent_coordinator.choose_canonical_relations(
            query=query,
            items=batch_items,
        )
        selected_relations = {
            prepared_index: batch_choices[batch_index]
            if batch_index < len(batch_choices)
            else None
            for batch_index, prepared_index in enumerate(batch_indices)
        }

        normalized = []
        for prepared_index, prepared in enumerate(prepared_triples):
            relation_name, confidence = self._finalize_relation(
                raw_triple=prepared["raw_triple"],
                candidates=prepared["candidates"],
                exact_match=prepared["exact_match"],
                selected_relation=selected_relations.get(prepared_index),
            )
            normalized.append(
                NormalizedTriple(
                    subject=prepared["subject"],
                    raw_relation=prepared["raw_triple"].relation,
                    object=prepared["object"],
                    relation_definition=prepared["relation_definition"],
                    normalized_relation=relation_name,
                    confidence=confidence,
                    candidate_relations=prepared["candidates"],
                )
            )

        cluster_ids = self._cluster_relations(normalized)
        for index, triple in enumerate(normalized):
            triple.cluster_id = cluster_ids[index]
        return normalized

    def extract_entities(self, query: str) -> List[str]:
        return self.agent_coordinator.extract_entities(query)

    def drain_warnings(self) -> List[str]:
        drain = getattr(self.agent_coordinator, "drain_warnings", None)
        warnings = drain() if callable(drain) else []
        warnings.extend(self.semantic_embedder.drain_warnings())
        return warnings

    def _retrieve_relation_candidates(
        self,
        raw_triple: RawTriple,
        relation_definition: str,
    ) -> Tuple[List[RelationCandidate], bool]:
        # Retrieve schema candidates first, then let the adapter verify them in
        # batch so one query can canonicalize multiple triples together.
        relation_embedding = self.semantic_embedder.embed([relation_definition])[0]
        candidates = []
        for schema in self.schema_relations:
            schema_embedding = self._get_schema_embedding(schema)
            score = self.semantic_embedder.similarity(relation_embedding, schema_embedding)
            candidates.append((schema.name, schema.definition, score))
        candidates.sort(key=lambda item: item[2], reverse=True)
        candidates = candidates[: self.top_k]
        exact_match = exact_schema_match(raw_triple.relation)
        if exact_match:
            candidates = self._promote_exact_match(candidates, exact_match)

        candidate_models = [
            RelationCandidate(name=name, definition=definition, score=score)
            for name, definition, score in candidates
        ]
        return candidate_models, bool(exact_match)

    def _finalize_relation(
        self,
        raw_triple: RawTriple,
        candidates: List[RelationCandidate],
        exact_match: bool,
        selected_relation: str | None,
    ) -> Tuple[str, float]:
        if not candidates:
            return self._custom_relation_name(raw_triple.relation), 0.0

        if exact_match:
            return candidates[0].name, candidates[0].score

        if selected_relation:
            selected_candidate = next(
                (
                    candidate
                    for candidate in candidates
                    if candidate.name == selected_relation
                ),
                candidates[0],
            )
            return selected_candidate.name, selected_candidate.score

        best_candidate = candidates[0]
        if best_candidate.score < self.schema_match_threshold:
            return self._custom_relation_name(raw_triple.relation), best_candidate.score
        return self._custom_relation_name(raw_triple.relation), best_candidate.score

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
        embeddings = self.semantic_embedder.embed(
            [triple.relation_definition for triple in triples]
        )

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
                    self.semantic_embedder.similarity(
                        embeddings[left_index],
                        embeddings[right_index],
                    )
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

    def _augment_query_intent_triples(
        self,
        query: str,
        raw_triples: Sequence[RawTriple],
    ) -> List[RawTriple]:
        augmented = list(raw_triples)
        inferred = self._infer_planning_triples(query)
        if not inferred:
            return augmented

        generic_only = (
            not augmented
            or all(self._is_generic_query_triple(query, triple) for triple in augmented)
        )
        if not generic_only:
            return augmented

        augmented = []

        seen = {
            (
                triple.subject.strip().lower(),
                triple.relation.strip().lower(),
                triple.object.strip().lower(),
            )
            for triple in augmented
        }
        for triple in inferred:
            signature = (
                triple.subject.strip().lower(),
                triple.relation.strip().lower(),
                triple.object.strip().lower(),
            )
            if signature in seen:
                continue
            seen.add(signature)
            augmented.append(triple)
        return augmented

    def _is_generic_query_triple(self, query: str, triple: RawTriple) -> bool:
        relation = triple.relation.strip().lower()
        subject = triple.subject.strip().lower()
        object_text = triple.object.strip().lower().rstrip("?!.")
        query_text = query.strip().lower().rstrip("?!.")
        return (
            subject in {"", "user"}
            and relation in GENERIC_QUERY_RELATIONS
            and object_text
            and (object_text == query_text or object_text in query_text or query_text in object_text)
        )

    def _infer_planning_triples(self, query: str) -> List[RawTriple]:
        cleaned = query.strip()
        if not cleaned:
            return []
        lowered = cleaned.lower()
        focus = self._query_focus_text(cleaned)
        triples: List[RawTriple] = []
        for relation_name, patterns in PLANNING_RELATION_PATTERNS:
            if any(re.search(pattern, lowered, flags=re.IGNORECASE) for pattern in patterns):
                triples.append(
                    RawTriple(
                        subject="user",
                        relation=relation_name,
                        object=focus,
                    )
                )
        return triples

    def _query_focus_text(self, text: str) -> str:
        cleaned = text.strip().strip(ENTITY_TRIM_CHARS)
        cleaned = LEADING_QUERY_PREFIX.sub("", cleaned, count=1)
        cleaned = LEADING_QUERY_AUXILIARY.sub("", cleaned, count=1)
        cleaned = LEADING_ACTION_PREFIX.sub("", cleaned, count=1)
        cleaned = cleaned.strip().strip(ENTITY_TRIM_CHARS)
        if not cleaned:
            return text.strip().strip(ENTITY_TRIM_CHARS)
        return cleaned

    def _get_schema_embedding(self, schema: SchemaRelation) -> object:
        cache_key = "%s::%s" % (schema.name, schema.definition)
        if cache_key not in self._schema_embedding_cache:
            self._schema_embedding_cache[cache_key] = self.semantic_embedder.embed(
                [schema.definition]
            )[0]
        return self._schema_embedding_cache[cache_key]
