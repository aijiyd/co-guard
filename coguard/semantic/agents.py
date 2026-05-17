from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

from ..agents.runtime import BaseLocalAgentRuntime, build_local_agent_runtime
from ..config import AppConfig
from ..models import CanonicalizationItem, RawTriple, RelationCandidate, SchemaRelation
from .llm import (
    BaseLLMAdapter,
    SYSTEM_MESSAGE,
    _parse_batch_canonicalization_output_text,
    _parse_oie_response_text,
    _parse_relation_definition_text,
)
from .prompts import (
    build_batch_canonicalization_prompt,
    build_entity_extraction_prompt,
    build_oie_prompt,
    build_relation_definition_prompt,
)


WarningSink = Callable[[str], None]


@dataclass
class TripleExtractionRequest:
    """Input envelope for the semantic extractor agent."""

    query: str
    candidate_entities: Sequence[str] | None = None
    candidate_relations: Sequence[SchemaRelation] | None = None


@dataclass
class RelationDefinitionRequest:
    """Input envelope for the relation definition agent."""

    query: str
    triples: Sequence[RawTriple]


@dataclass
class BatchCanonicalizationRequest:
    """Input envelope for the batch canonicalization agent."""

    query: str
    items: Sequence[CanonicalizationItem]


@dataclass
class EntityExtractionRequest:
    """Input envelope for the entity extraction agent."""

    query: str


class BaseSemanticAgent:
    """Runtime-aware role wrapper for module-one semantic subtasks."""

    name: str = "semantic.agent"

    def __init__(
        self,
        llm_adapter: BaseLLMAdapter,
        runtime: BaseLocalAgentRuntime | None = None,
        model: str = "",
        temperature: float = 0.0,
        max_tokens: int = 1024,
        warning_sink: WarningSink | None = None,
    ) -> None:
        self.llm_adapter = llm_adapter
        self.runtime = runtime
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.warning_sink = warning_sink

    def _warn(self, message: str) -> None:
        if self.warning_sink is not None:
            self.warning_sink(message)


class TripleExtractionAgent(BaseSemanticAgent):
    name = "semantic.extractor"

    def run(self, request: TripleExtractionRequest) -> List[RawTriple]:
        if self.runtime is not None:
            prompt = build_oie_prompt(
                text=request.query,
                candidate_entities=request.candidate_entities,
                candidate_relations=request.candidate_relations,
            )
            try:
                completion = self.runtime.invoke_text(
                    agent_name=self.name,
                    system_prompt=SYSTEM_MESSAGE,
                    user_prompt=prompt,
                    model=self.model,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
                triples = _parse_oie_response_text(completion)
                if triples:
                    return triples
                raise ValueError("runtime returned no triples")
            except Exception as exc:
                self._warn(
                    "Semantic extractor runtime failed, falling back to llm adapter: %s" % exc
                )
        return self.llm_adapter.extract_triples(
            query=request.query,
            candidate_entities=request.candidate_entities,
            candidate_relations=request.candidate_relations,
        )


class RelationDefinitionAgent(BaseSemanticAgent):
    name = "semantic.definer"

    def run(self, request: RelationDefinitionRequest) -> Dict[str, str]:
        if self.runtime is not None:
            prompt = build_relation_definition_prompt(request.query, request.triples)
            try:
                completion = self.runtime.invoke_text(
                    agent_name=self.name,
                    system_prompt=SYSTEM_MESSAGE,
                    user_prompt=prompt,
                    model=self.model,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
                normalized = _parse_relation_definition_text(completion)
                if normalized:
                    return normalized
                raise ValueError("runtime returned no relation definitions")
            except Exception as exc:
                self._warn(
                    "Semantic definer runtime failed, falling back to llm adapter: %s" % exc
                )
        return self.llm_adapter.define_relations(
            query=request.query,
            triples=request.triples,
        )

    def define_single(
        self,
        query: str,
        triple: RawTriple,
        triples: Sequence[RawTriple],
    ) -> str:
        return self.llm_adapter.define_relation(
            query=query,
            triple=triple,
            triples=triples,
        )


class BatchCanonicalizationAgent(BaseSemanticAgent):
    name = "semantic.canonicalizer"

    def run(self, request: BatchCanonicalizationRequest) -> List[Optional[str]]:
        if self.runtime is not None and request.items:
            prompt = build_batch_canonicalization_prompt(
                text=request.query,
                items=request.items,
            )
            try:
                completion = self.runtime.invoke_text(
                    agent_name=self.name,
                    system_prompt=SYSTEM_MESSAGE,
                    user_prompt=prompt,
                    model=self.model,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
                parsed = _parse_batch_canonicalization_output_text(
                    completion,
                    request.items,
                )
                if parsed is not None:
                    return parsed
                raise ValueError("runtime returned no valid canonicalization choices")
            except Exception as exc:
                self._warn(
                    "Semantic canonicalizer runtime failed, falling back to llm adapter: %s"
                    % exc
                )
        return self.llm_adapter.choose_canonical_relations(
            query=request.query,
            items=request.items,
        )

    def choose_single(
        self,
        query: str,
        triple: RawTriple,
        relation_definition: str,
        candidates: Sequence[RelationCandidate],
    ) -> Optional[str]:
        return self.llm_adapter.choose_canonical_relation(
            query=query,
            triple=triple,
            relation_definition=relation_definition,
            candidates=candidates,
        )


class EntityExtractionAgent(BaseSemanticAgent):
    name = "semantic.entity_agent"

    def run(self, request: EntityExtractionRequest) -> List[str]:
        if self.runtime is not None:
            prompt = build_entity_extraction_prompt(request.query)
            try:
                payload = self.runtime.invoke_json(
                    agent_name=self.name,
                    system_prompt=SYSTEM_MESSAGE,
                    user_prompt=prompt,
                    model=self.model,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
                entities = payload.get("entities") or payload.get("items", [])
                normalized = [str(entity).strip() for entity in entities if str(entity).strip()]
                if normalized:
                    return normalized
                raise ValueError("runtime returned no entities")
            except Exception as exc:
                self._warn(
                    "Semantic entity agent runtime failed, falling back to llm adapter: %s"
                    % exc
                )
        return self.llm_adapter.extract_entities(request.query)


@dataclass
class SemanticAgentCoordinator:
    """Module-one coordinator that exposes the semantic multi-agent seams."""

    llm_adapter: BaseLLMAdapter
    runtime: BaseLocalAgentRuntime | None = None
    extractor_model: str = ""
    definer_model: str = ""
    canonicalizer_model: str = ""
    entity_model: str = ""
    temperature: float = 0.0
    max_tokens: int = 1024
    extractor: TripleExtractionAgent | None = None
    definer: RelationDefinitionAgent | None = None
    canonicalizer: BatchCanonicalizationAgent | None = None
    entity_agent: EntityExtractionAgent | None = None
    metadata: Dict[str, str] = field(default_factory=dict)
    _warnings: List[str] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        self.extractor = self.extractor or TripleExtractionAgent(
            llm_adapter=self.llm_adapter,
            runtime=self.runtime,
            model=self.extractor_model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            warning_sink=self._warnings.append,
        )
        self.definer = self.definer or RelationDefinitionAgent(
            llm_adapter=self.llm_adapter,
            runtime=self.runtime,
            model=self.definer_model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            warning_sink=self._warnings.append,
        )
        self.canonicalizer = self.canonicalizer or BatchCanonicalizationAgent(
            llm_adapter=self.llm_adapter,
            runtime=self.runtime,
            model=self.canonicalizer_model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            warning_sink=self._warnings.append,
        )
        self.entity_agent = self.entity_agent or EntityExtractionAgent(
            llm_adapter=self.llm_adapter,
            runtime=self.runtime,
            model=self.entity_model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            warning_sink=self._warnings.append,
        )

    def extract_triples(
        self,
        query: str,
        candidate_entities: Sequence[str] | None = None,
        candidate_relations: Sequence[SchemaRelation] | None = None,
    ) -> List[RawTriple]:
        return self.extractor.run(
            TripleExtractionRequest(
                query=query,
                candidate_entities=candidate_entities,
                candidate_relations=candidate_relations,
            )
        )

    def define_relations(
        self,
        query: str,
        triples: Sequence[RawTriple],
    ) -> Dict[str, str]:
        return self.definer.run(
            RelationDefinitionRequest(query=query, triples=triples)
        )

    def define_relation(
        self,
        query: str,
        triple: RawTriple,
        triples: Sequence[RawTriple],
    ) -> str:
        return self.definer.define_single(query=query, triple=triple, triples=triples)

    def choose_canonical_relations(
        self,
        query: str,
        items: Sequence[CanonicalizationItem],
    ) -> List[Optional[str]]:
        return self.canonicalizer.run(
            BatchCanonicalizationRequest(query=query, items=items)
        )

    def choose_canonical_relation(
        self,
        query: str,
        triple: RawTriple,
        relation_definition: str,
        candidates: Sequence[RelationCandidate],
    ) -> Optional[str]:
        return self.canonicalizer.choose_single(
            query=query,
            triple=triple,
            relation_definition=relation_definition,
            candidates=candidates,
        )

    def extract_entities(self, query: str) -> List[str]:
        return self.entity_agent.run(EntityExtractionRequest(query=query))

    def drain_warnings(self) -> List[str]:
        warnings = list(self._warnings)
        self._warnings.clear()
        return warnings


def build_semantic_agent_coordinator(
    config: AppConfig,
    llm_adapter: BaseLLMAdapter,
    runtime: BaseLocalAgentRuntime | None = None,
) -> SemanticAgentCoordinator:
    runtime_instance = runtime
    if runtime_instance is None and config.local_agent_runtime_backend:
        runtime_instance = build_local_agent_runtime(
            backend=config.local_agent_runtime_backend,
            base_url=config.local_agent_base_url,
            model_path=config.local_agent_model_path,
            default_model=config.local_agent_default_model,
            api_key=config.local_agent_api_key,
            device=config.llm_device,
            timeout_seconds=config.llm_timeout_seconds,
        )
    return SemanticAgentCoordinator(
        llm_adapter=llm_adapter,
        runtime=runtime_instance,
        extractor_model=config.semantic_extractor_model,
        definer_model=config.semantic_definer_model,
        canonicalizer_model=config.semantic_canonicalizer_model,
        entity_model=config.semantic_entity_model,
        temperature=config.llm_temperature,
        max_tokens=config.llm_max_tokens,
        metadata={
            "runtime_backend": config.local_agent_runtime_backend or "disabled",
        },
    )
