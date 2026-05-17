"""Semantic module: EDC-style extraction, definition, and canonicalization."""

from .agents import (
    BaseSemanticAgent,
    BatchCanonicalizationAgent,
    EntityExtractionAgent,
    RelationDefinitionAgent,
    SemanticAgentCoordinator,
    TripleExtractionAgent,
    build_semantic_agent_coordinator,
)
from .embedding import BaseSemanticEmbedder, build_semantic_embedder
from .llm import (
    BaseLLMAdapter,
    LocalModelLLMAdapter,
    OpenAICompatibleLLMAdapter,
    RuleBasedLLMAdapter,
    build_llm_adapter,
)
from .parser import SemanticParser
from .retriever import BaseSchemaRetriever, build_schema_retriever

__all__ = [
    "BaseSemanticAgent",
    "TripleExtractionAgent",
    "RelationDefinitionAgent",
    "BatchCanonicalizationAgent",
    "EntityExtractionAgent",
    "SemanticAgentCoordinator",
    "build_semantic_agent_coordinator",
    "BaseLLMAdapter",
    "BaseSemanticEmbedder",
    "LocalModelLLMAdapter",
    "OpenAICompatibleLLMAdapter",
    "RuleBasedLLMAdapter",
    "build_semantic_embedder",
    "build_llm_adapter",
    "SemanticParser",
    "BaseSchemaRetriever",
    "build_schema_retriever",
]
