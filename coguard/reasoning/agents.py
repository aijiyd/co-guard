from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from ..agents.runtime import BaseLocalAgentRuntime, build_local_agent_runtime
from ..config import AppConfig
from ..models import (
    ContextSubgraph,
    LLMGraphJudgment,
    NormalizedTriple,
    ReasoningPath,
)
from ..semantic.llm import (
    BaseLLMAdapter,
    REASONING_SYSTEM_MESSAGE,
    _build_graph_judgment_prompt,
    _parse_graph_judgment,
)


@dataclass
class ReasoningJudgeRequest:
    """Structured packet passed to the reasoning judge agent."""

    query: str
    triples: Sequence[NormalizedTriple]
    context: ContextSubgraph
    context_description: str
    evidence_paths: Sequence[ReasoningPath]
    counter_evidence_paths: Sequence[ReasoningPath]
    missing_links: Sequence[str]
    rule_summary: Dict[str, object]


class ReasoningJudgeAgent:
    """Single reasoning agent that reviews graph evidence and returns a verdict."""

    name = "reasoning.judge"

    def __init__(
        self,
        llm_adapter: BaseLLMAdapter,
        runtime: BaseLocalAgentRuntime | None = None,
        model: str = "",
        temperature: float = 0.0,
        max_tokens: int = 1024,
        warning_sink=None,
    ) -> None:
        self.llm_adapter = llm_adapter
        self.runtime = runtime
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.warning_sink = warning_sink

    def run(self, request: ReasoningJudgeRequest) -> Optional[LLMGraphJudgment]:
        if self.runtime is not None:
            prompt = _build_graph_judgment_prompt(
                query=request.query,
                triples=request.triples,
                context=request.context,
                context_description=request.context_description,
                evidence_paths=request.evidence_paths,
                counter_evidence_paths=request.counter_evidence_paths,
                missing_links=request.missing_links,
                rule_summary=request.rule_summary,
            )
            try:
                payload = self.runtime.invoke_json(
                    agent_name=self.name,
                    system_prompt=REASONING_SYSTEM_MESSAGE,
                    user_prompt=prompt,
                    model=self.model,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
                return _parse_graph_judgment(payload)
            except Exception as exc:
                if self.warning_sink is not None:
                    self.warning_sink(
                        "Reasoning judge runtime failed, falling back to llm adapter: %s" % exc
                    )
        return self.llm_adapter.judge_graph_risk(
            query=request.query,
            triples=request.triples,
            context=request.context,
            context_description=request.context_description,
            evidence_paths=request.evidence_paths,
            counter_evidence_paths=request.counter_evidence_paths,
            missing_links=request.missing_links,
            rule_summary=request.rule_summary,
        )

@dataclass
class ReasoningAgentCoordinator:
    """Coordinator wrapper so module three can swap judge implementations cleanly."""

    llm_adapter: BaseLLMAdapter
    runtime: BaseLocalAgentRuntime | None = None
    judge_model: str = ""
    temperature: float = 0.0
    max_tokens: int = 1024
    judge: ReasoningJudgeAgent | None = None
    metadata: Dict[str, str] = field(default_factory=dict)
    _warnings: List[str] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        self.judge = self.judge or ReasoningJudgeAgent(
            llm_adapter=self.llm_adapter,
            runtime=self.runtime,
            model=self.judge_model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            warning_sink=self._warnings.append,
        )

    def judge_graph_risk(self, request: ReasoningJudgeRequest) -> Optional[LLMGraphJudgment]:
        return self.judge.run(request)

    def drain_warnings(self) -> List[str]:
        warnings = list(self._warnings)
        self._warnings.clear()
        return warnings


def build_reasoning_agent_coordinator(
    config: AppConfig,
    llm_adapter: BaseLLMAdapter,
    runtime: BaseLocalAgentRuntime | None = None,
) -> ReasoningAgentCoordinator:
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
    return ReasoningAgentCoordinator(
        llm_adapter=llm_adapter,
        runtime=runtime_instance,
        judge_model=config.reasoning_judge_model,
        temperature=config.llm_temperature,
        max_tokens=config.llm_max_tokens,
        metadata={
            "runtime_backend": config.local_agent_runtime_backend or "disabled",
        },
    )
