from __future__ import annotations

from typing import List, Optional

from .config import AppConfig
from .graph import BaseGraphStore, InMemoryGraphStore, Neo4jGraphStore
from .models import QueryAnalysisResult, SchemaRelation
from .reasoning import Reasoner
from .semantic import (
    BaseLLMAdapter,
    BaseSchemaRetriever,
    SemanticParser,
    build_llm_adapter,
    build_schema_retriever,
)


class CoGuardPipeline:
    def __init__(
        self,
        config: Optional[AppConfig] = None,
        llm_adapter: Optional[BaseLLMAdapter] = None,
        graph_store: Optional[BaseGraphStore] = None,
        schema_retriever: Optional[BaseSchemaRetriever] = None,
    ) -> None:
        # The pipeline is the only place that wires the three main modules
        # together, which keeps each module independently replaceable.
        self.config = config or AppConfig.from_env()
        self.initialization_warnings: List[str] = []
        self.llm_adapter = llm_adapter or self._build_llm_adapter()
        self.graph_store = graph_store or self._build_graph_store()
        self.schema_retriever = schema_retriever or self._build_schema_retriever()
        self.semantic_parser = SemanticParser(
            llm_adapter=self.llm_adapter,
            top_k=self.config.schema_top_k,
            cluster_threshold=self.config.relation_cluster_threshold,
            schema_match_threshold=self.config.schema_match_threshold,
        )
        self.reasoner = Reasoner(
            llm_adapter=self.llm_adapter,
            config=self.config,
        )

    def process_query(self, query: str) -> QueryAnalysisResult:
        # Main flow: EDC parsing -> graph persistence/context lookup -> reasoning.
        triples = self._run_edc(query)
        warnings = self._dedupe(
            list(self.initialization_warnings)
            + self.llm_adapter.drain_warnings()
            + self.schema_retriever.drain_warnings()
        )
        query_id = self.graph_store.upsert_query(query, triples)
        context = self.graph_store.get_context_subgraph(
            query_id=query_id,
            hops=self.config.context_hops,
            limit=self.config.context_limit,
        )
        context_description = self.reasoner.describe_context(context)
        assessment = self.reasoner.assess(
            query_id=query_id,
            query=query,
            triples=triples,
            context=context,
            context_description=context_description,
        )
        decision = "refuse" if assessment.malicious else "allow"
        return QueryAnalysisResult(
            query_id=query_id,
            query=query,
            triples=triples,
            context=context,
            context_description=context_description,
            malicious=assessment.malicious,
            decision=decision,
            score=assessment.score,
            reasons=assessment.reasons,
            reasoning_mode=assessment.reasoning_mode,
            adequacy=assessment.adequacy,
            evidence_paths=assessment.evidence_paths,
            counter_evidence_paths=assessment.counter_evidence_paths,
            missing_links=assessment.missing_links,
            graph_backend=self.graph_store.backend_name,
            warnings=warnings,
        )

    def _run_edc(self, query: str):
        # EDC+R style loop: parse once, then feed extracted entities and
        # retrieved relation hints back into the parser for refinement.
        triples = self.semantic_parser.parse(query)
        previous_signature = self._triple_signature(triples)

        for _ in range(max(0, self.config.refinement_iterations)):
            candidate_entities = self._build_candidate_entities(query, triples)
            candidate_relations = self._build_candidate_relations(query, triples)
            refined_triples = self.semantic_parser.parse(
                query=query,
                candidate_entities=candidate_entities,
                candidate_relations=candidate_relations,
            )
            refined_signature = self._triple_signature(refined_triples)
            triples = refined_triples
            if refined_signature == previous_signature:
                break
            previous_signature = refined_signature
        return triples

    def _build_candidate_entities(self, query: str, triples) -> List[str]:
        extracted_entities = self.llm_adapter.extract_entities(query)
        previous_entities = []
        for triple in triples:
            previous_entities.append(triple.subject)
            previous_entities.append(triple.object)
        return self._dedupe(previous_entities + extracted_entities)

    def _build_candidate_relations(self, query: str, triples) -> List[SchemaRelation]:
        # Keep relations already observed in the current parse, then augment them
        # with retriever proposals for the next refinement pass.
        relation_map = {}
        for triple in triples:
            relation_name = (
                triple.raw_relation
                if triple.normalized_relation.startswith("custom_")
                else triple.normalized_relation
            )
            relation_map.setdefault(
                relation_name,
                SchemaRelation(name=relation_name, definition=triple.relation_definition),
            )

        retrieved_relations = self.schema_retriever.retrieve(
            query=query,
            schema_relations=self.semantic_parser.schema_relations,
            top_k=self.config.refinement_relation_top_k,
        )
        for relation in retrieved_relations:
            relation_map.setdefault(
                relation.name,
                SchemaRelation(name=relation.name, definition=relation.definition),
            )
        return list(relation_map.values())

    def _build_graph_store(self) -> BaseGraphStore:
        if self.config.use_neo4j():
            try:
                return Neo4jGraphStore.from_config(self.config)
            except Exception as exc:  # pragma: no cover - fallback path
                # Local experiments should still run even if the production graph
                # backend is unavailable or misconfigured.
                self.initialization_warnings.append(
                    "Neo4j backend unavailable, falling back to memory: %s" % exc
                )
        return InMemoryGraphStore(config=self.config)

    def _build_llm_adapter(self) -> BaseLLMAdapter:
        return build_llm_adapter(
            backend=self.config.llm_backend,
            base_url=self.config.llm_base_url,
            model=self.config.llm_model,
            api_key=self.config.llm_api_key,
            temperature=self.config.llm_temperature,
            timeout_seconds=self.config.llm_timeout_seconds,
            max_tokens=self.config.llm_max_tokens,
        )

    def _build_schema_retriever(self) -> BaseSchemaRetriever:
        return build_schema_retriever(self.config)

    def _dedupe(self, values: List[str]) -> List[str]:
        seen = set()
        result = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            result.append(value)
        return result

    def _triple_signature(self, triples) -> tuple:
        return tuple(
            (triple.subject, triple.normalized_relation, triple.object)
            for triple in triples
        )
