from __future__ import annotations

import logging
import re
from typing import List, Optional

from .agents import BaseLocalAgentRuntime, build_local_agent_runtime
from .config import AppConfig
from .graph import BaseGraphStore, InMemoryGraphStore, Neo4jGraphStore
from .models import QueryAnalysisResult, SchemaRelation
from .reasoning import Reasoner, build_reasoning_agent_coordinator
from .semantic import (
    BaseLLMAdapter,
    BaseSchemaRetriever,
    SemanticParser,
    build_semantic_embedder,
    build_semantic_agent_coordinator,
    build_llm_adapter,
    build_schema_retriever,
)


logger = logging.getLogger(__name__)


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
        self.local_agent_runtime = self._build_local_agent_runtime()
        self.graph_store = graph_store or self._build_graph_store()
        self.schema_retriever = schema_retriever or self._build_schema_retriever()
        self.semantic_parser = self._build_semantic_parser()
        self.reasoner = Reasoner(
            llm_adapter=self.llm_adapter,
            config=self.config,
            agent_coordinator=build_reasoning_agent_coordinator(
                self.config,
                self.llm_adapter,
                runtime=self.local_agent_runtime,
            ),
        )

    def process_query(
        self,
        query: str,
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> QueryAnalysisResult:
        # Main flow: EDC parsing -> graph persistence/context lookup -> reasoning.
        query_preview = self._preview_query(query)
        logger.info(
            "[pipeline] start session=%s context=%s query=%s"
            % (session_id or "-", context_id or session_id or "-", query_preview)
        )
        logger.info("[pipeline] semantic:start query=%s" % query_preview)
        triples = self._run_edc(query)
        logger.info("[pipeline] semantic:done triples=%d query=%s" % (len(triples), query_preview))
        initial_warnings = self._dedupe(
            list(self.initialization_warnings)
            + self.semantic_parser.drain_warnings()
            + self.reasoner.drain_warnings()
            + self.llm_adapter.drain_warnings()
            + self.schema_retriever.drain_warnings()
        )
        effective_context_id = context_id or session_id
        logger.info("[pipeline] graph:start query=%s" % query_preview)
        query_id = self.graph_store.upsert_query(
            query,
            triples,
            session_id=session_id,
            context_id=context_id,
        )
        context = self.graph_store.get_context_subgraph(
            query_id=query_id,
            hops=self.config.context_hops,
            limit=self.config.context_limit,
            session_id=session_id,
            context_id=context_id,
        )
        logger.info(
            "[pipeline] graph:done query_id=%s nodes=%d edges=%d query=%s"
            % (query_id, len(context.nodes), len(context.edges), query_preview)
        )
        context_description = self.reasoner.describe_context(context)
        logger.info("[pipeline] reasoning:start query_id=%s query=%s" % (query_id, query_preview))
        assessment = self.reasoner.assess(
            query_id=query_id,
            query=query,
            triples=triples,
            context=context,
            context_description=context_description,
        )
        logger.info(
            "[pipeline] reasoning:done query_id=%s malicious=%s mode=%s score=%.4f"
            % (
                query_id,
                assessment.malicious,
                assessment.reasoning_mode,
                assessment.score,
            )
        )
        warnings = self._dedupe(
            initial_warnings
            + self.semantic_parser.drain_warnings()
            + self.reasoner.drain_warnings()
            + self.llm_adapter.drain_warnings()
            + self.schema_retriever.drain_warnings()
        )
        decision = "refuse" if assessment.malicious else "allow"
        logger.info(
            "[pipeline] done query_id=%s decision=%s warnings=%d"
            % (query_id, decision, len(warnings))
        )
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
            session_id=session_id or "",
            context_id=effective_context_id or "",
            assembly_chain_score=assessment.assembly.chain_score,
            assembly_current_advances_chain=assessment.assembly.current_query_advances_chain,
            assembly_current_closes_chain=assessment.assembly.current_query_closes_chain,
            assembly_current_phases=sorted(assessment.assembly.current_phases),
            assembly_historical_phases=sorted(assessment.assembly.historical_phases),
            assembly_current_topics=sorted(assessment.assembly.current_topics),
            assembly_historical_topics=sorted(assessment.assembly.historical_topics),
            assembly_shared_topics=sorted(assessment.assembly.shared_topics),
            assembly_reasons=list(assessment.assembly.reasons),
            assembly_timeline=list(assessment.assembly.query_timeline),
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
        extracted_entities = self.semantic_parser.extract_entities(query)
        previous_entities = []
        for triple in triples:
            previous_entities.append(triple.subject)
            previous_entities.append(triple.object)
        return self._merge_entities_for_refinement(previous_entities, extracted_entities)

    def _build_candidate_relations(self, query: str, triples) -> List[SchemaRelation]:
        # Build EDC-style relation hints: keep already observed relations first,
        # attach one in-context example when available, then augment with
        # retriever proposals.
        relation_map = {}
        for triple in triples:
            if triple.normalized_relation.startswith("custom_"):
                relation_name = triple.raw_relation
                relation_example = [triple.subject, triple.raw_relation, triple.object]
            else:
                relation_name = triple.normalized_relation
                relation_example = [triple.subject, triple.normalized_relation, triple.object]

            relation_map.setdefault(
                relation_name,
                SchemaRelation(
                    name=relation_name,
                    definition=triple.relation_definition,
                    example_text=query,
                    example_triple=relation_example,
                ),
            )

        retrieved_relations = self.schema_retriever.retrieve(
            query=query,
            schema_relations=self.semantic_parser.schema_relations,
            top_k=self.config.refinement_relation_top_k,
        )
        for relation in retrieved_relations:
            relation_map.setdefault(
                relation.name,
                SchemaRelation(
                    name=relation.name,
                    definition=relation.definition,
                ),
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

    def _preview_query(self, query: str, limit: int = 72) -> str:
        compact = re.sub(r"\s+", " ", query).strip()
        if len(compact) <= limit:
            return compact
        return compact[: limit - 3] + "..."

    def _build_semantic_parser(self) -> SemanticParser:
        return SemanticParser(
            llm_adapter=self.llm_adapter,
            top_k=self.config.schema_top_k,
            cluster_threshold=self.config.relation_cluster_threshold,
            schema_match_threshold=self.config.schema_match_threshold,
            agent_coordinator=build_semantic_agent_coordinator(
                self.config,
                self.llm_adapter,
                runtime=self.local_agent_runtime,
            ),
            semantic_embedder=build_semantic_embedder(self.config),
        )

    def _build_local_agent_runtime(self) -> BaseLocalAgentRuntime | None:
        if not self.config.local_agent_runtime_backend:
            return None
        try:
            return build_local_agent_runtime(
                backend=self.config.local_agent_runtime_backend,
                base_url=self.config.local_agent_base_url,
                model_path=self.config.local_agent_model_path,
                default_model=self.config.local_agent_default_model,
                api_key=self.config.local_agent_api_key,
                device=self.config.llm_device,
                timeout_seconds=self.config.llm_timeout_seconds,
            )
        except Exception as exc:  # pragma: no cover - runtime construction fallback
            self.initialization_warnings.append(
                "Local agent runtime unavailable, falling back to direct adapters: %s" % exc
            )
            return None

    def _build_llm_adapter(self) -> BaseLLMAdapter:
        return build_llm_adapter(
            backend=self.config.llm_backend,
            model=self.config.llm_model,
            base_url=self.config.llm_base_url,
            api_key=self.config.llm_api_key,
            model_path=self.config.llm_model_path,
            device=self.config.llm_device,
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

    def _merge_entities_for_refinement(
        self,
        previous_entities: List[str],
        extracted_entities: List[str],
    ) -> List[str]:
        merged: List[str] = []
        normalized_entities: List[str] = []
        for raw_entity in previous_entities + extracted_entities:
            entity = raw_entity.strip()
            if not entity:
                continue
            normalized = self._normalize_refinement_entity(entity)
            if not normalized:
                continue

            skip_entity = False
            for index, existing_normalized in enumerate(normalized_entities):
                if normalized == existing_normalized:
                    skip_entity = True
                    break
                if normalized in existing_normalized and len(normalized) <= len(existing_normalized):
                    skip_entity = True
                    break
                if existing_normalized in normalized and len(normalized) > len(existing_normalized):
                    merged[index] = entity
                    normalized_entities[index] = normalized
                    skip_entity = True
                    break
            if skip_entity:
                continue
            merged.append(entity)
            normalized_entities.append(normalized)
        return merged

    def _normalize_refinement_entity(self, value: str) -> str:
        lowered = value.strip().lower()
        lowered = re.sub(r"\s+", " ", lowered)
        lowered = lowered.strip(" \t\r\n,.;:!?，。；：！？()[]{}<>《》\"'“”‘’")
        return lowered

    def _triple_signature(self, triples) -> tuple:
        return tuple(
            (triple.subject, triple.normalized_relation, triple.object)
            for triple in triples
        )
