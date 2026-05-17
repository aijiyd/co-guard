from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict


DEFAULT_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"


def _get_value(name: str, default: str, env_defaults: Dict[str, str]) -> str:
    # Precedence is: process environment > .env defaults > hard-coded default.
    value = os.getenv(name)
    if value not in (None, ""):
        return value
    if name in env_defaults and env_defaults[name] != "":
        return env_defaults[name]
    return default


def _get_int(name: str, default: int, env_defaults: Dict[str, str]) -> int:
    value = _get_value(name, str(default), env_defaults)
    return int(value) if value else default


def _get_float(name: str, default: float, env_defaults: Dict[str, str]) -> float:
    value = _get_value(name, str(default), env_defaults)
    return float(value) if value else default


def _load_env_defaults(env_path: str | os.PathLike | None = None) -> Dict[str, str]:
    path = Path(env_path) if env_path else DEFAULT_ENV_PATH
    if not path.exists():
        return {}

    defaults: Dict[str, str] = {}
    # A tiny built-in parser keeps startup lightweight and avoids adding a
    # dependency just to read local default configuration.
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, raw_value = stripped.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            quote_char = value[0]
            value = value[1:-1]
            if quote_char == '"':
                value = bytes(value, "utf-8").decode("unicode_escape")
        defaults[key] = value
    return defaults


@dataclass
class AppConfig:
    """Runtime configuration shared across semantic, graph, and reasoning."""

    graph_backend: str = "memory"
    llm_backend: str = "auto"
    llm_model: str = ""
    llm_base_url: str = "http://127.0.0.1:8000/v1"
    llm_api_key: str = ""
    llm_model_path: str = "/model"
    llm_device: str = "auto"
    llm_temperature: float = 0.0
    llm_timeout_seconds: float = 60.0
    llm_max_tokens: int = 1024
    local_agent_runtime_backend: str = ""
    local_agent_base_url: str = "http://127.0.0.1:8000/v1"
    local_agent_model_path: str = "/model"
    local_agent_default_model: str = ""
    local_agent_api_key: str = ""
    semantic_extractor_model: str = ""
    semantic_definer_model: str = ""
    semantic_canonicalizer_model: str = ""
    semantic_entity_model: str = ""
    reasoning_judge_model: str = ""
    semantic_embedding_backend: str = "vector"
    semantic_embedding_model: str = ""
    semantic_embedding_base_url: str = "http://localhost:8001/v1"
    semantic_embedding_api_key: str = ""
    schema_top_k: int = 3
    schema_match_threshold: float = 0.28
    relation_cluster_threshold: float = 0.62
    refinement_iterations: int = 1
    refinement_relation_top_k: int = 5
    schema_retriever_backend: str = "vector"
    schema_retriever_model: str = ""
    schema_retriever_base_url: str = "http://localhost:8001/v1"
    schema_retriever_api_key: str = ""
    schema_retriever_instruction: str = (
        "Instruct: retrieve relations that are present in the given text\nQuery: {text}"
    )
    entity_relatedness_threshold: float = 0.68
    reasoning_strategy: str = "hybrid"
    reasoning_max_depth: int = 3
    reasoning_beam_width: int = 3
    reasoning_risk_evidence_threshold: float = 4.5
    reasoning_benign_evidence_threshold: float = 2.4
    reasoning_llm_confidence_threshold: float = 0.7
    reasoning_hybrid_rule_weight: float = 0.65
    context_hops: int = 2
    context_limit: int = 24
    neo4j_uri: str = ""
    neo4j_username: str = ""
    neo4j_password: str = ""
    neo4j_database: str = "neo4j"

    @classmethod
    def from_env(
        cls,
        env_path: str | os.PathLike | None = None,
        **overrides: object,
    ) -> "AppConfig":
        # Construct one config object up front so the rest of the codebase can
        # stay focused on behavior instead of repeatedly reading env vars.
        env_defaults = _load_env_defaults(env_path)
        config = cls(
            graph_backend=_get_value("GRAPH_BACKEND", "memory", env_defaults),
            llm_backend=_get_value("LLM_BACKEND", "auto", env_defaults),
            llm_model=_get_value("LLM_MODEL", "", env_defaults),
            llm_base_url=_get_value(
                "LLM_BASE_URL",
                "http://127.0.0.1:8000/v1",
                env_defaults,
            ),
            llm_api_key=_get_value("LLM_API_KEY", "", env_defaults),
            llm_model_path=_get_value("LLM_MODEL_PATH", "/model", env_defaults),
            llm_device=_get_value("LLM_DEVICE", "auto", env_defaults),
            llm_temperature=_get_float("LLM_TEMPERATURE", 0.0, env_defaults),
            llm_timeout_seconds=_get_float(
                "LLM_TIMEOUT_SECONDS",
                60.0,
                env_defaults,
            ),
            llm_max_tokens=_get_int("LLM_MAX_TOKENS", 1024, env_defaults),
            local_agent_runtime_backend=_get_value(
                "LOCAL_AGENT_RUNTIME_BACKEND",
                "",
                env_defaults,
            ),
            local_agent_base_url=_get_value(
                "LOCAL_AGENT_BASE_URL",
                "http://127.0.0.1:8000/v1",
                env_defaults,
            ),
            local_agent_model_path=_get_value(
                "LOCAL_AGENT_MODEL_PATH",
                "/model",
                env_defaults,
            ),
            local_agent_default_model=_get_value(
                "LOCAL_AGENT_DEFAULT_MODEL",
                "",
                env_defaults,
            ),
            local_agent_api_key=_get_value(
                "LOCAL_AGENT_API_KEY",
                "",
                env_defaults,
            ),
            semantic_extractor_model=_get_value(
                "SEMANTIC_EXTRACTOR_MODEL",
                "",
                env_defaults,
            ),
            semantic_definer_model=_get_value(
                "SEMANTIC_DEFINER_MODEL",
                "",
                env_defaults,
            ),
            semantic_canonicalizer_model=_get_value(
                "SEMANTIC_CANONICALIZER_MODEL",
                "",
                env_defaults,
            ),
            semantic_entity_model=_get_value(
                "SEMANTIC_ENTITY_MODEL",
                "",
                env_defaults,
            ),
            reasoning_judge_model=_get_value(
                "REASONING_JUDGE_MODEL",
                "",
                env_defaults,
            ),
            semantic_embedding_backend=_get_value(
                "SEMANTIC_EMBEDDING_BACKEND",
                "vector",
                env_defaults,
            ),
            semantic_embedding_model=_get_value(
                "SEMANTIC_EMBEDDING_MODEL",
                "",
                env_defaults,
            ),
            semantic_embedding_base_url=_get_value(
                "SEMANTIC_EMBEDDING_BASE_URL",
                "http://localhost:8001/v1",
                env_defaults,
            ),
            semantic_embedding_api_key=_get_value(
                "SEMANTIC_EMBEDDING_API_KEY",
                "",
                env_defaults,
            ),
            schema_top_k=_get_int("SCHEMA_TOP_K", 3, env_defaults),
            schema_match_threshold=_get_float(
                "SCHEMA_MATCH_THRESHOLD",
                0.28,
                env_defaults,
            ),
            relation_cluster_threshold=_get_float(
                "RELATION_CLUSTER_THRESHOLD",
                0.62,
                env_defaults,
            ),
            refinement_iterations=_get_int(
                "REFINEMENT_ITERATIONS",
                1,
                env_defaults,
            ),
            refinement_relation_top_k=_get_int(
                "REFINEMENT_RELATION_TOP_K",
                5,
                env_defaults,
            ),
            schema_retriever_backend=_get_value(
                "SCHEMA_RETRIEVER_BACKEND",
                "vector",
                env_defaults,
            ),
            schema_retriever_model=_get_value(
                "SCHEMA_RETRIEVER_MODEL",
                "",
                env_defaults,
            ),
            schema_retriever_base_url=_get_value(
                "SCHEMA_RETRIEVER_BASE_URL",
                "http://localhost:8001/v1",
                env_defaults,
            ),
            schema_retriever_api_key=_get_value(
                "SCHEMA_RETRIEVER_API_KEY",
                "",
                env_defaults,
            ),
            schema_retriever_instruction=_get_value(
                "SCHEMA_RETRIEVER_INSTRUCTION",
                "Instruct: retrieve relations that are present in the given text\nQuery: {text}",
                env_defaults,
            ),
            entity_relatedness_threshold=_get_float(
                "ENTITY_RELATEDNESS_THRESHOLD",
                0.68,
                env_defaults,
            ),
            reasoning_strategy=_get_value(
                "REASONING_STRATEGY",
                "hybrid",
                env_defaults,
            ),
            reasoning_max_depth=_get_int(
                "REASONING_MAX_DEPTH",
                3,
                env_defaults,
            ),
            reasoning_beam_width=_get_int(
                "REASONING_BEAM_WIDTH",
                3,
                env_defaults,
            ),
            reasoning_risk_evidence_threshold=_get_float(
                "REASONING_RISK_EVIDENCE_THRESHOLD",
                4.5,
                env_defaults,
            ),
            reasoning_benign_evidence_threshold=_get_float(
                "REASONING_BENIGN_EVIDENCE_THRESHOLD",
                2.4,
                env_defaults,
            ),
            reasoning_llm_confidence_threshold=_get_float(
                "REASONING_LLM_CONFIDENCE_THRESHOLD",
                0.7,
                env_defaults,
            ),
            reasoning_hybrid_rule_weight=_get_float(
                "REASONING_HYBRID_RULE_WEIGHT",
                0.65,
                env_defaults,
            ),
            context_hops=_get_int("CONTEXT_HOPS", 2, env_defaults),
            context_limit=_get_int("CONTEXT_LIMIT", 24, env_defaults),
            neo4j_uri=_get_value("NEO4J_URI", "", env_defaults),
            neo4j_username=_get_value("NEO4J_USERNAME", "", env_defaults),
            neo4j_password=_get_value("NEO4J_PASSWORD", "", env_defaults),
            neo4j_database=_get_value("NEO4J_DATABASE", "neo4j", env_defaults),
        )
        for key, value in overrides.items():
            if value is not None:
                setattr(config, key, value)
        return config

    def use_neo4j(self) -> bool:
        return self.graph_backend.lower() == "neo4j"
