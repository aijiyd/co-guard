"""Semantic module: EDC-style extraction, definition, and canonicalization."""

from .llm import (
    BaseLLMAdapter,
    OpenAICompatibleLLMAdapter,
    RuleBasedLLMAdapter,
    build_llm_adapter,
)
from .parser import SemanticParser
from .retriever import BaseSchemaRetriever, build_schema_retriever

__all__ = [
    "BaseLLMAdapter",
    "OpenAICompatibleLLMAdapter",
    "RuleBasedLLMAdapter",
    "build_llm_adapter",
    "SemanticParser",
    "BaseSchemaRetriever",
    "build_schema_retriever",
]
