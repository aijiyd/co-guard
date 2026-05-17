from __future__ import annotations

import base64
import csv
import html
import json
import pickle
import uuid
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Sequence

from ..config import AppConfig
from ..models import QueryAnalysisResult
from ..pipeline import CoGuardPipeline


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SequentialAttackSample:
    """One multi-turn attack sequence loaded from JSONL."""

    sample_id: str
    tasks: List[str]
    metadata: Dict[str, object] = field(default_factory=dict)


@dataclass
class SequentialTurnResult:
    """One injected turn plus the defense system's response."""

    turn_index: int
    query: str
    query_id: str
    decision: str
    malicious: bool
    score: float
    adequacy: str
    session_id: str = ""
    context_id: str = ""
    stream_turn_index: int | None = None
    turn_role: str = "attack"
    attack_turn_index: int | None = None
    reasoning_mode: str = "rules"
    reasons: List[str] = field(default_factory=list)
    assembly_chain_score: float = 0.0
    assembly_current_advances_chain: bool = False
    assembly_current_closes_chain: bool = False
    assembly_current_phases: List[str] = field(default_factory=list)
    assembly_historical_phases: List[str] = field(default_factory=list)
    assembly_current_topics: List[str] = field(default_factory=list)
    assembly_historical_topics: List[str] = field(default_factory=list)
    assembly_shared_topics: List[str] = field(default_factory=list)
    assembly_reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class SequentialAttackResult:
    """Outcome for one attack sequence under one isolated session."""

    sample_id: str
    session_id: str
    task_count: int
    outcome: str
    context_id: str = ""
    stopped_at_turn: int | None = None
    turns: List[SequentialTurnResult] = field(default_factory=list)
    metadata: Dict[str, object] = field(default_factory=dict)


@dataclass
class GlobalStreamEvent:
    """One chronological event in a mixed global stream."""

    stream_turn_index: int
    query: str
    query_id: str
    decision: str
    malicious: bool
    score: float
    adequacy: str
    session_id: str = ""
    context_id: str = ""
    sample_id: str = ""
    turn_role: str = "attack"
    attack_turn_index: int | None = None
    reasoning_mode: str = "rules"
    reasons: List[str] = field(default_factory=list)
    assembly_chain_score: float = 0.0
    assembly_current_advances_chain: bool = False
    assembly_current_closes_chain: bool = False
    assembly_current_phases: List[str] = field(default_factory=list)
    assembly_historical_phases: List[str] = field(default_factory=list)
    assembly_current_topics: List[str] = field(default_factory=list)
    assembly_historical_topics: List[str] = field(default_factory=list)
    assembly_shared_topics: List[str] = field(default_factory=list)
    assembly_reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class GlobalMixedStreamEvaluation:
    """One user-scoped mixed stream plus hidden per-goal outcomes."""

    stream_id: str
    user_context_id: str
    attack_results: List[SequentialAttackResult]
    stream_events: List[GlobalStreamEvent]
    benign_turn_count: int = 0
    benign_refusal_count: int = 0


@dataclass
class _ActiveAttackChain:
    sample: SequentialAttackSample
    next_attack_index: int = 0
    turns: List[SequentialTurnResult] = field(default_factory=list)
    session_ids: List[str] = field(default_factory=list)
    outcome: str | None = None
    stopped_at_turn: int | None = None


@dataclass
class _Scenario3CheckpointState:
    stream_id: str
    user_context_id: str
    next_sample_index: int
    attack_turn_count: int
    benign_turn_count: int
    benign_refusal_count: int
    completed: bool = False
    stream_events: List[GlobalStreamEvent] = field(default_factory=list)
    attack_results: List[SequentialAttackResult] = field(default_factory=list)
    active_states: Dict[str, _ActiveAttackChain] = field(default_factory=dict)
    rng_state: str = ""
    graph_state: Dict[str, object] = field(default_factory=dict)


@dataclass
class SequentialEvaluationSummary:
    sample_count: int
    defended_count: int
    bypass_count: int
    defense_success_rate: float
    bypass_rate: float
    first_turn_stop_rate: float
    average_stop_turn: float
    average_turns_processed: float
    cumulative_detection_curve: List[Dict[str, float]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "sample_count": self.sample_count,
            "defended_count": self.defended_count,
            "bypass_count": self.bypass_count,
            "defense_success_rate": self.defense_success_rate,
            "bypass_rate": self.bypass_rate,
            "first_turn_stop_rate": self.first_turn_stop_rate,
            "average_stop_turn": self.average_stop_turn,
            "average_turns_processed": self.average_turns_processed,
            "cumulative_detection_curve": list(self.cumulative_detection_curve),
        }


def load_attack_sequences(jsonl_path: str | Path) -> List[SequentialAttackSample]:
    """Load multi-turn attack sequences from JSONL."""

    path = Path(jsonl_path)
    samples: List[SequentialAttackSample] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            payload = json.loads(line)
            tasks = _extract_task_list(payload)
            if not tasks:
                raise ValueError(
                    "JSONL line %d does not contain a usable task sequence." % line_number
                )
            sample_id = str(
                payload.get("sample_id")
                or payload.get("id")
                or "sample-%04d" % line_number
            )
            metadata = {
                key: value
                for key, value in payload.items()
                if key
                not in {
                    "sample_id",
                    "id",
                    "tasks",
                    "subtasks",
                    "questions",
                    "sequence",
                    "decomposed_results",
                    "decomposed_questions",
                }
            }
            samples.append(
                SequentialAttackSample(
                    sample_id=sample_id,
                    tasks=tasks,
                    metadata=metadata,
                )
            )
    return samples


def _build_turn_result(
    *,
    turn_index: int,
    query: str,
    result: QueryAnalysisResult,
    turn_role: str,
    attack_turn_index: int | None,
    stream_turn_index: int | None = None,
) -> SequentialTurnResult:
    return SequentialTurnResult(
        turn_index=turn_index,
        query=query,
        query_id=result.query_id,
        session_id=result.session_id,
        context_id=result.context_id,
        stream_turn_index=stream_turn_index,
        turn_role=turn_role,
        attack_turn_index=attack_turn_index,
        decision=result.decision,
        malicious=result.malicious,
        score=result.score,
        adequacy=result.adequacy,
        reasoning_mode=result.reasoning_mode,
        reasons=list(result.reasons),
        assembly_chain_score=result.assembly_chain_score,
        assembly_current_advances_chain=result.assembly_current_advances_chain,
        assembly_current_closes_chain=result.assembly_current_closes_chain,
        assembly_current_phases=list(result.assembly_current_phases),
        assembly_historical_phases=list(result.assembly_historical_phases),
        assembly_current_topics=list(result.assembly_current_topics),
        assembly_historical_topics=list(result.assembly_historical_topics),
        assembly_shared_topics=list(result.assembly_shared_topics),
        assembly_reasons=list(result.assembly_reasons),
        warnings=list(result.warnings),
    )


def _turn_to_stream_event(
    sample_id: str,
    turn: SequentialTurnResult,
) -> GlobalStreamEvent:
    return GlobalStreamEvent(
        stream_turn_index=turn.stream_turn_index or 0,
        query=turn.query,
        query_id=turn.query_id,
        decision=turn.decision,
        malicious=turn.malicious,
        score=turn.score,
        adequacy=turn.adequacy,
        session_id=turn.session_id,
        context_id=turn.context_id,
        sample_id=sample_id,
        turn_role=turn.turn_role,
        attack_turn_index=turn.attack_turn_index,
        reasoning_mode=turn.reasoning_mode,
        reasons=list(turn.reasons),
        assembly_chain_score=turn.assembly_chain_score,
        assembly_current_advances_chain=turn.assembly_current_advances_chain,
        assembly_current_closes_chain=turn.assembly_current_closes_chain,
        assembly_current_phases=list(turn.assembly_current_phases),
        assembly_historical_phases=list(turn.assembly_historical_phases),
        assembly_current_topics=list(turn.assembly_current_topics),
        assembly_historical_topics=list(turn.assembly_historical_topics),
        assembly_shared_topics=list(turn.assembly_shared_topics),
        assembly_reasons=list(turn.assembly_reasons),
        warnings=list(turn.warnings),
    )


def _serialize_turn(turn: SequentialTurnResult) -> Dict[str, object]:
    return {
        "turn_index": turn.turn_index,
        "query": turn.query,
        "query_id": turn.query_id,
        "decision": turn.decision,
        "malicious": turn.malicious,
        "score": turn.score,
        "adequacy": turn.adequacy,
        "session_id": turn.session_id,
        "context_id": turn.context_id,
        "stream_turn_index": turn.stream_turn_index,
        "turn_role": turn.turn_role,
        "attack_turn_index": turn.attack_turn_index,
        "reasoning_mode": turn.reasoning_mode,
        "reasons": list(turn.reasons),
        "assembly_chain_score": turn.assembly_chain_score,
        "assembly_current_advances_chain": turn.assembly_current_advances_chain,
        "assembly_current_closes_chain": turn.assembly_current_closes_chain,
        "assembly_current_phases": list(turn.assembly_current_phases),
        "assembly_historical_phases": list(turn.assembly_historical_phases),
        "assembly_current_topics": list(turn.assembly_current_topics),
        "assembly_historical_topics": list(turn.assembly_historical_topics),
        "assembly_shared_topics": list(turn.assembly_shared_topics),
        "assembly_reasons": list(turn.assembly_reasons),
        "warnings": list(turn.warnings),
    }


def _deserialize_turn(payload: Dict[str, object]) -> SequentialTurnResult:
    return SequentialTurnResult(
        turn_index=int(payload.get("turn_index", 0)),
        query=str(payload.get("query", "")),
        query_id=str(payload.get("query_id", "")),
        decision=str(payload.get("decision", "allow")),
        malicious=bool(payload.get("malicious", False)),
        score=float(payload.get("score", 0.0)),
        adequacy=str(payload.get("adequacy", "uncertain")),
        session_id=str(payload.get("session_id", "")),
        context_id=str(payload.get("context_id", "")),
        stream_turn_index=_optional_int(payload.get("stream_turn_index")),
        turn_role=str(payload.get("turn_role", "attack")),
        attack_turn_index=_optional_int(payload.get("attack_turn_index")),
        reasoning_mode=str(payload.get("reasoning_mode", "rules")),
        reasons=[str(item) for item in payload.get("reasons", []) or []],
        assembly_chain_score=float(payload.get("assembly_chain_score", 0.0)),
        assembly_current_advances_chain=bool(
            payload.get("assembly_current_advances_chain", False)
        ),
        assembly_current_closes_chain=bool(
            payload.get("assembly_current_closes_chain", False)
        ),
        assembly_current_phases=[
            str(item) for item in payload.get("assembly_current_phases", []) or []
        ],
        assembly_historical_phases=[
            str(item) for item in payload.get("assembly_historical_phases", []) or []
        ],
        assembly_current_topics=[
            str(item) for item in payload.get("assembly_current_topics", []) or []
        ],
        assembly_historical_topics=[
            str(item) for item in payload.get("assembly_historical_topics", []) or []
        ],
        assembly_shared_topics=[
            str(item) for item in payload.get("assembly_shared_topics", []) or []
        ],
        assembly_reasons=[str(item) for item in payload.get("assembly_reasons", []) or []],
        warnings=[str(item) for item in payload.get("warnings", []) or []],
    )


def _serialize_attack_result(result: SequentialAttackResult) -> Dict[str, object]:
    return {
        "sample_id": result.sample_id,
        "session_id": result.session_id,
        "task_count": result.task_count,
        "outcome": result.outcome,
        "context_id": result.context_id,
        "stopped_at_turn": result.stopped_at_turn,
        "turns": [_serialize_turn(turn) for turn in result.turns],
        "metadata": dict(result.metadata),
    }


def _deserialize_attack_result(payload: Dict[str, object]) -> SequentialAttackResult:
    return SequentialAttackResult(
        sample_id=str(payload.get("sample_id", "")),
        session_id=str(payload.get("session_id", "")),
        task_count=int(payload.get("task_count", 0)),
        outcome=str(payload.get("outcome", "bypass")),
        context_id=str(payload.get("context_id", "")),
        stopped_at_turn=_optional_int(payload.get("stopped_at_turn")),
        turns=[
            _deserialize_turn(item)
            for item in payload.get("turns", []) or []
            if isinstance(item, dict)
        ],
        metadata=dict(payload.get("metadata", {}) or {}),
    )


def _serialize_stream_event(event: GlobalStreamEvent) -> Dict[str, object]:
    return {
        "stream_turn_index": event.stream_turn_index,
        "query": event.query,
        "query_id": event.query_id,
        "decision": event.decision,
        "malicious": event.malicious,
        "score": event.score,
        "adequacy": event.adequacy,
        "session_id": event.session_id,
        "context_id": event.context_id,
        "sample_id": event.sample_id,
        "turn_role": event.turn_role,
        "attack_turn_index": event.attack_turn_index,
        "reasoning_mode": event.reasoning_mode,
        "reasons": list(event.reasons),
        "assembly_chain_score": event.assembly_chain_score,
        "assembly_current_advances_chain": event.assembly_current_advances_chain,
        "assembly_current_closes_chain": event.assembly_current_closes_chain,
        "assembly_current_phases": list(event.assembly_current_phases),
        "assembly_historical_phases": list(event.assembly_historical_phases),
        "assembly_current_topics": list(event.assembly_current_topics),
        "assembly_historical_topics": list(event.assembly_historical_topics),
        "assembly_shared_topics": list(event.assembly_shared_topics),
        "assembly_reasons": list(event.assembly_reasons),
        "warnings": list(event.warnings),
    }


def _deserialize_stream_event(payload: Dict[str, object]) -> GlobalStreamEvent:
    return GlobalStreamEvent(
        stream_turn_index=int(payload.get("stream_turn_index", 0)),
        query=str(payload.get("query", "")),
        query_id=str(payload.get("query_id", "")),
        decision=str(payload.get("decision", "allow")),
        malicious=bool(payload.get("malicious", False)),
        score=float(payload.get("score", 0.0)),
        adequacy=str(payload.get("adequacy", "uncertain")),
        session_id=str(payload.get("session_id", "")),
        context_id=str(payload.get("context_id", "")),
        sample_id=str(payload.get("sample_id", "")),
        turn_role=str(payload.get("turn_role", "attack")),
        attack_turn_index=_optional_int(payload.get("attack_turn_index")),
        reasoning_mode=str(payload.get("reasoning_mode", "rules")),
        reasons=[str(item) for item in payload.get("reasons", []) or []],
        assembly_chain_score=float(payload.get("assembly_chain_score", 0.0)),
        assembly_current_advances_chain=bool(
            payload.get("assembly_current_advances_chain", False)
        ),
        assembly_current_closes_chain=bool(
            payload.get("assembly_current_closes_chain", False)
        ),
        assembly_current_phases=[
            str(item) for item in payload.get("assembly_current_phases", []) or []
        ],
        assembly_historical_phases=[
            str(item) for item in payload.get("assembly_historical_phases", []) or []
        ],
        assembly_current_topics=[
            str(item) for item in payload.get("assembly_current_topics", []) or []
        ],
        assembly_historical_topics=[
            str(item) for item in payload.get("assembly_historical_topics", []) or []
        ],
        assembly_shared_topics=[
            str(item) for item in payload.get("assembly_shared_topics", []) or []
        ],
        assembly_reasons=[str(item) for item in payload.get("assembly_reasons", []) or []],
        warnings=[str(item) for item in payload.get("warnings", []) or []],
    )


def _serialize_active_state(state: _ActiveAttackChain) -> Dict[str, object]:
    return {
        "sample_id": state.sample.sample_id,
        "next_attack_index": state.next_attack_index,
        "turns": [_serialize_turn(turn) for turn in state.turns],
        "session_ids": list(state.session_ids),
        "outcome": state.outcome,
        "stopped_at_turn": state.stopped_at_turn,
    }


def _deserialize_active_state(
    payload: Dict[str, object],
    sample_lookup: Dict[str, SequentialAttackSample],
) -> _ActiveAttackChain:
    sample_id = str(payload.get("sample_id", ""))
    sample = sample_lookup.get(sample_id)
    if sample is None:
        raise ValueError("Checkpoint references unknown sample_id '%s'." % sample_id)
    return _ActiveAttackChain(
        sample=sample,
        next_attack_index=int(payload.get("next_attack_index", 0)),
        turns=[
            _deserialize_turn(item)
            for item in payload.get("turns", []) or []
            if isinstance(item, dict)
        ],
        session_ids=[str(item) for item in payload.get("session_ids", []) or []],
        outcome=(str(payload["outcome"]) if payload.get("outcome") is not None else None),
        stopped_at_turn=_optional_int(payload.get("stopped_at_turn")),
    )


def _optional_int(value: object) -> int | None:
    if value in (None, "", "null"):
        return None
    return int(value)


class SequentialSessionEvaluator:
    """Evaluate multi-turn attack sequences with one isolated graph session each."""

    def __init__(
        self,
        config: AppConfig,
        pipeline_factory: Callable[[AppConfig], CoGuardPipeline] | None = None,
    ) -> None:
        self.config = config
        self.pipeline_factory = pipeline_factory or (lambda cfg: CoGuardPipeline(config=cfg))

    def evaluate(self, samples: Sequence[SequentialAttackSample]) -> List[SequentialAttackResult]:
        # Keep one pipeline alive so model/retriever setup is reused, but isolate
        # each sample at the graph layer with a dedicated session id.
        pipeline = self.pipeline_factory(self.config)
        results: List[SequentialAttackResult] = []
        total_samples = len(samples)
        for sample_index, sample in enumerate(samples, start=1):
            session_id = self._session_id_for_sample(sample.sample_id)
            turns: List[SequentialTurnResult] = []
            outcome = "bypass"
            stopped_at_turn = None
            logger.info(
                "[%d/%d] sample=%s turns=%d session=%s"
                % (sample_index, total_samples, sample.sample_id, len(sample.tasks), session_id)
            )
            try:
                for turn_index, query in enumerate(sample.tasks, start=1):
                    result = pipeline.process_query(query, session_id=session_id)
                    turns.append(
                        _build_turn_result(
                            turn_index=turn_index,
                            query=query,
                            result=result,
                            turn_role="attack",
                            attack_turn_index=turn_index,
                            stream_turn_index=turn_index,
                        )
                    )
                    if result.decision == "refuse":
                        outcome = "defended"
                        stopped_at_turn = turn_index
                        break
                attack_result = SequentialAttackResult(
                    sample_id=sample.sample_id,
                    session_id=session_id,
                    context_id=session_id,
                    task_count=len(sample.tasks),
                    outcome=outcome,
                    stopped_at_turn=stopped_at_turn,
                    turns=turns,
                    metadata=dict(sample.metadata),
                )
                results.append(attack_result)
                logger.info(
                    "[%d/%d] sample=%s outcome=%s processed_turns=%d stopped_at_turn=%s"
                    % (
                        sample_index,
                        total_samples,
                        sample.sample_id,
                        attack_result.outcome,
                        len(attack_result.turns),
                        attack_result.stopped_at_turn if attack_result.stopped_at_turn is not None else "-",
                    )
                )
            finally:
                pipeline.graph_store.clear_session(session_id)
        return results

    def _session_id_for_sample(self, sample_id: str) -> str:
        suffix = uuid.uuid4().hex[:10]
        return "session-%s-%s" % (sample_id, suffix)


class InterleavedContextEvaluator:
    """Evaluate attack chains under one long-lived context with session churn and benign noise."""

    def __init__(
        self,
        config: AppConfig,
        benign_queries: Sequence[str],
        pipeline_factory: Callable[[AppConfig], CoGuardPipeline] | None = None,
        min_noise_per_gap: int = 1,
        max_noise_per_gap: int = 2,
        rotate_session_every: int = 1,
        seed: int = 7,
    ) -> None:
        self.config = config
        self.benign_queries = [query for query in benign_queries if query]
        self.pipeline_factory = pipeline_factory or (lambda cfg: CoGuardPipeline(config=cfg))
        self.min_noise_per_gap = max(0, int(min_noise_per_gap))
        self.max_noise_per_gap = max(self.min_noise_per_gap, int(max_noise_per_gap))
        self.rotate_session_every = max(1, int(rotate_session_every))
        self.seed = seed

    def evaluate(self, samples: Sequence[SequentialAttackSample]) -> List[SequentialAttackResult]:
        pipeline = self.pipeline_factory(self.config)
        rng = random.Random(self.seed)
        results: List[SequentialAttackResult] = []
        total_samples = len(samples)
        for sample_index, sample in enumerate(samples, start=1):
            context_id = self._context_id_for_sample(sample.sample_id)
            turns: List[SequentialTurnResult] = []
            outcome = "bypass"
            stopped_at_turn = None
            session_ids: List[str] = []
            attack_turns_seen = 0
            logger.info(
                "[%d/%d] interleaved sample=%s turns=%d context=%s"
                % (sample_index, total_samples, sample.sample_id, len(sample.tasks), context_id)
            )
            try:
                for attack_index, query in enumerate(sample.tasks, start=1):
                    if attack_index >= 2 and self.benign_queries:
                        noise_count = rng.randint(self.min_noise_per_gap, self.max_noise_per_gap)
                        for _ in range(noise_count):
                            session_id = self._session_id_for_turn(
                                sample_id=sample.sample_id,
                                stream_turn_index=len(turns),
                            )
                            session_ids.append(session_id)
                            noise_query = rng.choice(self.benign_queries)
                            result = pipeline.process_query(
                                noise_query,
                                session_id=session_id,
                                context_id=context_id,
                            )
                            turns.append(
                                _build_turn_result(
                                    turn_index=len(turns) + 1,
                                    query=noise_query,
                                    result=result,
                                    turn_role="noise",
                                    attack_turn_index=None,
                                    stream_turn_index=len(turns) + 1,
                                )
                            )
                            if result.decision == "refuse":
                                outcome = "defended"
                                stopped_at_turn = attack_turns_seen
                                break
                        if outcome == "defended":
                            break
                    session_id = self._session_id_for_turn(
                        sample_id=sample.sample_id,
                        stream_turn_index=len(turns),
                    )
                    session_ids.append(session_id)
                    result = pipeline.process_query(
                        query,
                        session_id=session_id,
                        context_id=context_id,
                    )
                    attack_turns_seen = attack_index
                    turns.append(
                        _build_turn_result(
                            turn_index=len(turns) + 1,
                            query=query,
                            result=result,
                            turn_role="attack",
                            attack_turn_index=attack_index,
                            stream_turn_index=len(turns) + 1,
                        )
                    )
                    if result.decision == "refuse":
                        outcome = "defended"
                        stopped_at_turn = attack_index
                        break
                attack_result = SequentialAttackResult(
                    sample_id=sample.sample_id,
                    session_id=session_ids[0] if session_ids else "",
                    context_id=context_id,
                    task_count=len(sample.tasks),
                    outcome=outcome,
                    stopped_at_turn=stopped_at_turn,
                    turns=turns,
                    metadata={
                        **dict(sample.metadata),
                        "session_ids": list(dict.fromkeys(session_ids)),
                        "noise_turn_count": len([turn for turn in turns if turn.turn_role == "noise"]),
                    },
                )
                results.append(attack_result)
                logger.info(
                    "[%d/%d] interleaved sample=%s outcome=%s processed_stream_turns=%d stopped_at_attack_turn=%s"
                    % (
                        sample_index,
                        total_samples,
                        sample.sample_id,
                        attack_result.outcome,
                        len(attack_result.turns),
                        attack_result.stopped_at_turn if attack_result.stopped_at_turn is not None else "-",
                    )
                )
            finally:
                pipeline.graph_store.clear_context(context_id)
        return results

    def _context_id_for_sample(self, sample_id: str) -> str:
        suffix = uuid.uuid4().hex[:10]
        return "context-%s-%s" % (sample_id, suffix)

    def _session_id_for_turn(self, sample_id: str, stream_turn_index: int) -> str:
        session_bucket = (stream_turn_index // self.rotate_session_every) + 1
        return "session-%s-%03d" % (sample_id, session_bucket)


class GlobalMixedStreamEvaluator:
    """Evaluate one user stream where hidden attack chains and benign tasks are interleaved."""

    def __init__(
        self,
        config: AppConfig,
        benign_queries: Sequence[str],
        pipeline_factory: Callable[[AppConfig], CoGuardPipeline] | None = None,
        min_noise_per_attack_turn: int = 0,
        max_noise_per_attack_turn: int = 2,
        noise_every_attack_turns: int = 1,
        rotate_session_every: int = 1,
        max_active_attack_chains: int | None = None,
        shuffle_attack_order: bool = True,
        progress_every: int = 10,
        checkpoint_path: str | Path | None = None,
        checkpoint_every: int = 0,
        seed: int = 7,
    ) -> None:
        self.config = config
        self.benign_queries = [query for query in benign_queries if query]
        self.pipeline_factory = pipeline_factory or (lambda cfg: CoGuardPipeline(config=cfg))
        self.min_noise_per_attack_turn = max(0, int(min_noise_per_attack_turn))
        self.max_noise_per_attack_turn = max(
            self.min_noise_per_attack_turn,
            int(max_noise_per_attack_turn),
        )
        self.noise_every_attack_turns = max(1, int(noise_every_attack_turns))
        self.rotate_session_every = max(1, int(rotate_session_every))
        if max_active_attack_chains is None or int(max_active_attack_chains) <= 0:
            self.max_active_attack_chains = None
        else:
            self.max_active_attack_chains = int(max_active_attack_chains)
        self.shuffle_attack_order = bool(shuffle_attack_order)
        self.progress_every = max(0, int(progress_every))
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else None
        self.checkpoint_every = max(0, int(checkpoint_every))
        self.seed = seed

    def evaluate(
        self,
        samples: Sequence[SequentialAttackSample],
        resume_from: str | Path | None = None,
    ) -> GlobalMixedStreamEvaluation:
        pipeline = self.pipeline_factory(self.config)
        rng = random.Random(self.seed)
        sample_order = {sample.sample_id: index for index, sample in enumerate(samples)}
        total_samples = len(samples)
        checkpoint_source = Path(resume_from) if resume_from else self.checkpoint_path
        if checkpoint_source and checkpoint_source.exists():
            checkpoint = self._load_checkpoint(checkpoint_source, samples)
            stream_id = checkpoint.stream_id
            user_context_id = checkpoint.user_context_id
            stream_events = checkpoint.stream_events
            attack_results = checkpoint.attack_results
            attack_turn_count = checkpoint.attack_turn_count
            benign_turn_count = checkpoint.benign_turn_count
            benign_refusal_count = checkpoint.benign_refusal_count
            active = checkpoint.active_states
            next_sample_index = checkpoint.next_sample_index
            rng.setstate(self._decode_rng_state(checkpoint.rng_state))
            if checkpoint.completed:
                logger.info(
                    "[stream=%s] checkpoint already completed path=%s stream_turn=%d"
                    % (stream_id, checkpoint_source, len(stream_events))
                )
                attack_results.sort(
                    key=lambda result: sample_order.get(result.sample_id, len(sample_order))
                )
                return GlobalMixedStreamEvaluation(
                    stream_id=stream_id,
                    user_context_id=user_context_id,
                    attack_results=attack_results,
                    stream_events=stream_events,
                    benign_turn_count=benign_turn_count,
                    benign_refusal_count=benign_refusal_count,
                )
            pipeline.graph_store.import_state(checkpoint.graph_state)
            logger.info(
                "[stream=%s] resumed checkpoint=%s stream_turn=%d finished_goals=%d loaded_goals=%d/%d"
                % (
                    stream_id,
                    checkpoint_source,
                    len(stream_events),
                    len(attack_results),
                    len(active) + len(attack_results),
                    total_samples,
                )
            )
        else:
            stream_id = self._stream_id()
            user_context_id = self._user_context_id(stream_id)
            stream_events = []
            attack_results = []
            attack_turn_count = 0
            benign_turn_count = 0
            benign_refusal_count = 0
            active = {}
            next_sample_index = 0

        try:
            while active or next_sample_index < total_samples:
                while next_sample_index < total_samples and self._can_activate_more(active):
                    sample = samples[next_sample_index]
                    next_sample_index += 1
                    state = _ActiveAttackChain(sample=sample)
                    active[sample.sample_id] = state
                    logger.info(
                        "[stream=%s] activate hidden_goal=%s user_context=%s tasks=%d"
                        % (stream_id, sample.sample_id, user_context_id, len(sample.tasks))
                    )

                if not active:
                    break

                attack_order = list(active.keys())
                if self.shuffle_attack_order:
                    rng.shuffle(attack_order)

                for sample_id in attack_order:
                    state = active.get(sample_id)
                    if state is None:
                        continue

                    query = state.sample.tasks[state.next_attack_index]
                    session_id = self._session_id_for_stream_turn(len(stream_events))
                    logger.info(
                        "[stream=%s] turn:start stream_turn=%d role=attack hidden_goal=%s attack_turn=%d session=%s"
                        % (
                            stream_id,
                            len(stream_events) + 1,
                            sample_id,
                            state.next_attack_index + 1,
                            session_id,
                        )
                    )
                    result = pipeline.process_query(
                        query,
                        session_id=session_id,
                        context_id=user_context_id,
                    )
                    state.session_ids.append(session_id)
                    attack_turn_index = state.next_attack_index + 1
                    turn = _build_turn_result(
                        turn_index=attack_turn_index,
                        query=query,
                        result=result,
                        turn_role="attack",
                        attack_turn_index=attack_turn_index,
                        stream_turn_index=len(stream_events) + 1,
                    )
                    state.turns.append(turn)
                    stream_events.append(_turn_to_stream_event(sample_id, turn))
                    attack_turn_count += 1
                    logger.info(
                        "[stream=%s] turn:done stream_turn=%d role=attack hidden_goal=%s decision=%s score=%.4f"
                        % (
                            stream_id,
                            turn.stream_turn_index or 0,
                            sample_id,
                            result.decision,
                            result.score,
                        )
                    )
                    state.next_attack_index = attack_turn_index

                    if result.decision == "refuse":
                        state.outcome = "defended"
                        state.stopped_at_turn = attack_turn_index
                    elif state.next_attack_index >= len(state.sample.tasks):
                        state.outcome = "bypass"

                    if state.outcome is not None:
                        attack_results.append(self._finalize_attack_state(state, user_context_id))
                        logger.info(
                            "[stream=%s] hidden_goal=%s outcome=%s stopped_at_turn=%s stream_turn=%d"
                            % (
                                stream_id,
                                sample_id,
                                state.outcome,
                                state.stopped_at_turn if state.stopped_at_turn is not None else "-",
                                turn.stream_turn_index or 0,
                            )
                        )
                        active.pop(sample_id, None)
                    self._maybe_log_progress(
                        stream_id=stream_id,
                        stream_events=stream_events,
                        attack_results=attack_results,
                        active=active,
                        total_samples=total_samples,
                        benign_turn_count=benign_turn_count,
                    )
                    self._maybe_write_checkpoint(
                        pipeline=pipeline,
                        stream_id=stream_id,
                        user_context_id=user_context_id,
                        next_sample_index=next_sample_index,
                        attack_turn_count=attack_turn_count,
                        benign_turn_count=benign_turn_count,
                        benign_refusal_count=benign_refusal_count,
                        stream_events=stream_events,
                        attack_results=attack_results,
                        active=active,
                        rng=rng,
                    )

                    if self.benign_queries and attack_turn_count % self.noise_every_attack_turns == 0:
                        noise_count = rng.randint(
                            self.min_noise_per_attack_turn,
                            self.max_noise_per_attack_turn,
                        )
                        for _ in range(noise_count):
                            noise_query = rng.choice(self.benign_queries)
                            noise_session_id = self._session_id_for_stream_turn(len(stream_events))
                            logger.info(
                                "[stream=%s] turn:start stream_turn=%d role=noise session=%s"
                                % (
                                    stream_id,
                                    len(stream_events) + 1,
                                    noise_session_id,
                                )
                            )
                            noise_result = pipeline.process_query(
                                noise_query,
                                session_id=noise_session_id,
                                context_id=user_context_id,
                            )
                            benign_turn_count += 1
                            noise_turn = _build_turn_result(
                                turn_index=1,
                                query=noise_query,
                                result=noise_result,
                                turn_role="noise",
                                attack_turn_index=None,
                                stream_turn_index=len(stream_events) + 1,
                            )
                            stream_events.append(_turn_to_stream_event("", noise_turn))
                            logger.info(
                                "[stream=%s] turn:done stream_turn=%d role=noise decision=%s score=%.4f"
                                % (
                                    stream_id,
                                    noise_turn.stream_turn_index or 0,
                                    noise_result.decision,
                                    noise_result.score,
                                )
                            )
                            if noise_result.decision == "refuse":
                                benign_refusal_count += 1
                            self._maybe_log_progress(
                                stream_id=stream_id,
                                stream_events=stream_events,
                                attack_results=attack_results,
                                active=active,
                                total_samples=total_samples,
                                benign_turn_count=benign_turn_count,
                            )
                            self._maybe_write_checkpoint(
                                pipeline=pipeline,
                                stream_id=stream_id,
                                user_context_id=user_context_id,
                                next_sample_index=next_sample_index,
                                attack_turn_count=attack_turn_count,
                                benign_turn_count=benign_turn_count,
                                benign_refusal_count=benign_refusal_count,
                                stream_events=stream_events,
                                attack_results=attack_results,
                                active=active,
                                rng=rng,
                            )
        finally:
            pipeline.graph_store.clear_context(user_context_id)

        attack_results.sort(key=lambda result: sample_order.get(result.sample_id, len(sample_order)))
        self._write_checkpoint(
            pipeline=pipeline,
            stream_id=stream_id,
            user_context_id=user_context_id,
            next_sample_index=next_sample_index,
            attack_turn_count=attack_turn_count,
            benign_turn_count=benign_turn_count,
            benign_refusal_count=benign_refusal_count,
            stream_events=stream_events,
            attack_results=attack_results,
            active={},
            rng=rng,
            completed=True,
        )
        return GlobalMixedStreamEvaluation(
            stream_id=stream_id,
            user_context_id=user_context_id,
            attack_results=attack_results,
            stream_events=stream_events,
            benign_turn_count=benign_turn_count,
            benign_refusal_count=benign_refusal_count,
        )

    def _can_activate_more(self, active: Dict[str, _ActiveAttackChain]) -> bool:
        if self.max_active_attack_chains is None:
            return True
        return len(active) < self.max_active_attack_chains

    def _finalize_attack_state(
        self,
        state: _ActiveAttackChain,
        user_context_id: str,
    ) -> SequentialAttackResult:
        return SequentialAttackResult(
            sample_id=state.sample.sample_id,
            session_id=state.session_ids[0] if state.session_ids else "",
            context_id=user_context_id,
            task_count=len(state.sample.tasks),
            outcome=state.outcome or "bypass",
            stopped_at_turn=state.stopped_at_turn,
            turns=list(state.turns),
            metadata={
                **dict(state.sample.metadata),
                "session_ids": list(dict.fromkeys(state.session_ids)),
                "first_stream_turn_index": state.turns[0].stream_turn_index if state.turns else None,
                "last_stream_turn_index": state.turns[-1].stream_turn_index if state.turns else None,
            },
        )

    def _stream_id(self) -> str:
        return "stream-%s" % uuid.uuid4().hex[:10]

    def _user_context_id(self, stream_id: str) -> str:
        return "user-context-%s" % stream_id.replace("stream-", "")

    def _session_id_for_stream_turn(self, stream_turn_index: int) -> str:
        session_bucket = (stream_turn_index // self.rotate_session_every) + 1
        return "session-user-%03d" % session_bucket

    def _maybe_write_checkpoint(
        self,
        *,
        pipeline: CoGuardPipeline,
        stream_id: str,
        user_context_id: str,
        next_sample_index: int,
        attack_turn_count: int,
        benign_turn_count: int,
        benign_refusal_count: int,
        stream_events: Sequence[GlobalStreamEvent],
        attack_results: Sequence[SequentialAttackResult],
        active: Dict[str, _ActiveAttackChain],
        rng: random.Random,
    ) -> None:
        if self.checkpoint_path is None or self.checkpoint_every <= 0:
            return
        stream_turn_count = len(stream_events)
        if stream_turn_count == 0 or stream_turn_count % self.checkpoint_every != 0:
            return
        try:
            self._write_checkpoint(
                pipeline=pipeline,
                stream_id=stream_id,
                user_context_id=user_context_id,
                next_sample_index=next_sample_index,
                attack_turn_count=attack_turn_count,
                benign_turn_count=benign_turn_count,
                benign_refusal_count=benign_refusal_count,
                stream_events=stream_events,
                attack_results=attack_results,
                active=active,
                rng=rng,
                completed=False,
            )
            logger.info(
                "[stream=%s] checkpoint saved path=%s stream_turn=%d"
                % (stream_id, self.checkpoint_path, stream_turn_count)
            )
        except Exception as exc:
            logger.info("[stream=%s] checkpoint skipped: %s" % (stream_id, exc))

    def _write_checkpoint(
        self,
        *,
        pipeline: CoGuardPipeline,
        stream_id: str,
        user_context_id: str,
        next_sample_index: int,
        attack_turn_count: int,
        benign_turn_count: int,
        benign_refusal_count: int,
        stream_events: Sequence[GlobalStreamEvent],
        attack_results: Sequence[SequentialAttackResult],
        active: Dict[str, _ActiveAttackChain],
        rng: random.Random,
        completed: bool,
    ) -> None:
        if self.checkpoint_path is None:
            return
        checkpoint_payload = self._serialize_checkpoint(
            pipeline=pipeline,
            stream_id=stream_id,
            user_context_id=user_context_id,
            next_sample_index=next_sample_index,
            attack_turn_count=attack_turn_count,
            benign_turn_count=benign_turn_count,
            benign_refusal_count=benign_refusal_count,
            stream_events=stream_events,
            attack_results=attack_results,
            active=active,
            rng=rng,
            completed=completed,
        )
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.checkpoint_path.with_suffix(self.checkpoint_path.suffix + ".tmp")
        temp_path.write_text(
            json.dumps(checkpoint_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temp_path.replace(self.checkpoint_path)

    def _serialize_checkpoint(
        self,
        *,
        pipeline: CoGuardPipeline,
        stream_id: str,
        user_context_id: str,
        next_sample_index: int,
        attack_turn_count: int,
        benign_turn_count: int,
        benign_refusal_count: int,
        stream_events: Sequence[GlobalStreamEvent],
        attack_results: Sequence[SequentialAttackResult],
        active: Dict[str, _ActiveAttackChain],
        rng: random.Random,
        completed: bool,
    ) -> Dict[str, object]:
        graph_state = pipeline.graph_store.export_state() if not completed else {}
        return {
            "version": 1,
            "stream_id": stream_id,
            "user_context_id": user_context_id,
            "next_sample_index": next_sample_index,
            "attack_turn_count": attack_turn_count,
            "benign_turn_count": benign_turn_count,
            "benign_refusal_count": benign_refusal_count,
            "completed": completed,
            "stream_events": [_serialize_stream_event(event) for event in stream_events],
            "attack_results": [_serialize_attack_result(result) for result in attack_results],
            "active_states": {
                sample_id: _serialize_active_state(state)
                for sample_id, state in active.items()
            },
            "rng_state": self._encode_rng_state(rng.getstate()),
            "graph_state": graph_state,
        }

    def _load_checkpoint(
        self,
        checkpoint_path: Path,
        samples: Sequence[SequentialAttackSample],
    ) -> _Scenario3CheckpointState:
        payload = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        sample_lookup = {sample.sample_id: sample for sample in samples}
        return _Scenario3CheckpointState(
            stream_id=str(payload.get("stream_id", self._stream_id())),
            user_context_id=str(payload.get("user_context_id", "")),
            next_sample_index=int(payload.get("next_sample_index", 0)),
            attack_turn_count=int(payload.get("attack_turn_count", 0)),
            benign_turn_count=int(payload.get("benign_turn_count", 0)),
            benign_refusal_count=int(payload.get("benign_refusal_count", 0)),
            completed=bool(payload.get("completed", False)),
            stream_events=[
                _deserialize_stream_event(item)
                for item in payload.get("stream_events", []) or []
                if isinstance(item, dict)
            ],
            attack_results=[
                _deserialize_attack_result(item)
                for item in payload.get("attack_results", []) or []
                if isinstance(item, dict)
            ],
            active_states={
                sample_id: _deserialize_active_state(state_payload, sample_lookup)
                for sample_id, state_payload in (payload.get("active_states", {}) or {}).items()
                if isinstance(state_payload, dict)
            },
            rng_state=str(payload.get("rng_state", "")),
            graph_state=dict(payload.get("graph_state", {}) or {}),
        )

    def _encode_rng_state(self, state: object) -> str:
        return base64.b64encode(pickle.dumps(state)).decode("ascii")

    def _decode_rng_state(self, payload: str) -> object:
        if not payload:
            return random.Random(self.seed).getstate()
        return pickle.loads(base64.b64decode(payload.encode("ascii")))

    def _maybe_log_progress(
        self,
        *,
        stream_id: str,
        stream_events: Sequence[GlobalStreamEvent],
        attack_results: Sequence[SequentialAttackResult],
        active: Dict[str, _ActiveAttackChain],
        total_samples: int,
        benign_turn_count: int,
    ) -> None:
        if self.progress_every <= 0:
            return
        stream_turn_count = len(stream_events)
        if stream_turn_count == 0 or stream_turn_count % self.progress_every != 0:
            return
        attack_turn_count = len(
            [event for event in stream_events if event.turn_role == "attack"]
        )
        logger.info(
            "[stream=%s] progress stream_turn=%d attack_turns=%d benign_turns=%d active_goals=%d finished_goals=%d loaded_goals=%d/%d"
            % (
                stream_id,
                stream_turn_count,
                attack_turn_count,
                benign_turn_count,
                len(active),
                len(attack_results),
                len(active) + len(attack_results),
                total_samples,
            )
        )


def compute_sequential_summary(
    results: Sequence[SequentialAttackResult],
) -> SequentialEvaluationSummary:
    sample_count = len(results)
    defended = [result for result in results if result.outcome == "defended"]
    bypassed = [result for result in results if result.outcome == "bypass"]
    first_turn_stops = [result for result in defended if result.stopped_at_turn == 1]
    stop_turns = [result.stopped_at_turn for result in defended if result.stopped_at_turn]
    processed_turns = [len(result.turns) for result in results]

    max_turns = max([0] + [result.task_count for result in results])
    cumulative_detection_curve = []
    for turn_index in range(1, max_turns + 1):
        eligible = [result for result in results if result.task_count >= turn_index]
        if not eligible:
            continue
        detected = [
            result
            for result in eligible
            if result.stopped_at_turn is not None and result.stopped_at_turn <= turn_index
        ]
        cumulative_detection_curve.append(
            {
                "turn_index": turn_index,
                "eligible_samples": len(eligible),
                "detected_samples": len(detected),
                "detection_rate": _safe_div(len(detected), len(eligible)),
            }
        )

    return SequentialEvaluationSummary(
        sample_count=sample_count,
        defended_count=len(defended),
        bypass_count=len(bypassed),
        defense_success_rate=_safe_div(len(defended), sample_count),
        bypass_rate=_safe_div(len(bypassed), sample_count),
        first_turn_stop_rate=_safe_div(len(first_turn_stops), sample_count),
        average_stop_turn=_mean(stop_turns),
        average_turns_processed=_mean(processed_turns),
        cumulative_detection_curve=cumulative_detection_curve,
    )


def write_sequential_results_json(
    output_path: str | Path,
    results: Sequence[SequentialAttackResult],
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = [
        {
            "sample_id": result.sample_id,
            "session_id": result.session_id,
            "context_id": result.context_id,
            "task_count": result.task_count,
            "outcome": result.outcome,
            "stopped_at_turn": result.stopped_at_turn,
            "turns": [
                {
                    "turn_index": turn.turn_index,
                    "stream_turn_index": turn.stream_turn_index,
                    "session_id": turn.session_id,
                    "context_id": turn.context_id,
                    "turn_role": turn.turn_role,
                    "attack_turn_index": turn.attack_turn_index,
                    "query_id": turn.query_id,
                    "decision": turn.decision,
                    "malicious": turn.malicious,
                    "score": turn.score,
                    "adequacy": turn.adequacy,
                    "reasoning_mode": turn.reasoning_mode,
                    "reasons": list(turn.reasons),
                    "assembly_chain_score": turn.assembly_chain_score,
                    "assembly_current_advances_chain": turn.assembly_current_advances_chain,
                    "assembly_current_closes_chain": turn.assembly_current_closes_chain,
                    "assembly_current_phases": list(turn.assembly_current_phases),
                    "assembly_historical_phases": list(turn.assembly_historical_phases),
                    "assembly_current_topics": list(turn.assembly_current_topics),
                    "assembly_historical_topics": list(turn.assembly_historical_topics),
                    "assembly_shared_topics": list(turn.assembly_shared_topics),
                    "assembly_reasons": list(turn.assembly_reasons),
                    "warnings": list(turn.warnings),
                }
                for turn in result.turns
            ],
            "metadata": dict(result.metadata),
        }
        for result in results
    ]
    path.write_text(json.dumps(serialized, ensure_ascii=False, indent=2), encoding="utf-8")


def write_turn_log_csv(
    output_path: str | Path,
    results: Sequence[SequentialAttackResult],
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "sample_id",
                "session_id",
                "context_id",
                "task_count",
                "outcome",
                "stopped_at_turn",
                "turn_index",
                "stream_turn_index",
                "turn_role",
                "attack_turn_index",
                "decision",
                "malicious",
                "score",
                "adequacy",
                "reasoning_mode",
                "reasons",
                "query_id",
                "query",
                "assembly_chain_score",
                "assembly_current_advances_chain",
                "assembly_current_closes_chain",
                "assembly_current_phases",
                "assembly_historical_phases",
                "assembly_current_topics",
                "assembly_historical_topics",
                "assembly_shared_topics",
                "assembly_reasons",
                "warnings",
            ],
        )
        writer.writeheader()
        for result in results:
            for turn in result.turns:
                writer.writerow(
                    {
                        "sample_id": result.sample_id,
                        "session_id": turn.session_id or result.session_id,
                        "context_id": turn.context_id or result.context_id,
                        "task_count": result.task_count,
                        "outcome": result.outcome,
                        "stopped_at_turn": result.stopped_at_turn or "",
                        "turn_index": turn.turn_index,
                        "stream_turn_index": turn.stream_turn_index or "",
                        "turn_role": turn.turn_role,
                        "attack_turn_index": turn.attack_turn_index or "",
                        "decision": turn.decision,
                        "malicious": turn.malicious,
                        "score": "%.4f" % turn.score,
                        "adequacy": turn.adequacy,
                        "reasoning_mode": turn.reasoning_mode,
                        "reasons": " | ".join(turn.reasons),
                        "query_id": turn.query_id,
                        "query": turn.query,
                        "assembly_chain_score": "%.4f" % turn.assembly_chain_score,
                        "assembly_current_advances_chain": turn.assembly_current_advances_chain,
                        "assembly_current_closes_chain": turn.assembly_current_closes_chain,
                        "assembly_current_phases": " | ".join(turn.assembly_current_phases),
                        "assembly_historical_phases": " | ".join(turn.assembly_historical_phases),
                        "assembly_current_topics": " | ".join(turn.assembly_current_topics),
                        "assembly_historical_topics": " | ".join(turn.assembly_historical_topics),
                        "assembly_shared_topics": " | ".join(turn.assembly_shared_topics),
                        "assembly_reasons": " | ".join(turn.assembly_reasons),
                        "warnings": " | ".join(turn.warnings),
                    }
                )


def write_global_stream_events_json(
    output_path: str | Path,
    evaluation: GlobalMixedStreamEvaluation,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = {
        "stream_id": evaluation.stream_id,
        "user_context_id": evaluation.user_context_id,
        "benign_turn_count": evaluation.benign_turn_count,
        "benign_refusal_count": evaluation.benign_refusal_count,
        "stream_events": [
            {
                "stream_turn_index": event.stream_turn_index,
                "sample_id": event.sample_id,
                "hidden_goal_id": event.sample_id,
                "session_id": event.session_id,
                "context_id": event.context_id,
                "turn_role": event.turn_role,
                "attack_turn_index": event.attack_turn_index,
                "query_id": event.query_id,
                "query": event.query,
                "decision": event.decision,
                "malicious": event.malicious,
                "score": event.score,
                "adequacy": event.adequacy,
                "reasoning_mode": event.reasoning_mode,
                "reasons": list(event.reasons),
                "assembly_chain_score": event.assembly_chain_score,
                "assembly_current_advances_chain": event.assembly_current_advances_chain,
                "assembly_current_closes_chain": event.assembly_current_closes_chain,
                "assembly_current_phases": list(event.assembly_current_phases),
                "assembly_historical_phases": list(event.assembly_historical_phases),
                "assembly_current_topics": list(event.assembly_current_topics),
                "assembly_historical_topics": list(event.assembly_historical_topics),
                "assembly_shared_topics": list(event.assembly_shared_topics),
                "assembly_reasons": list(event.assembly_reasons),
                "warnings": list(event.warnings),
            }
            for event in evaluation.stream_events
        ],
    }
    path.write_text(json.dumps(serialized, ensure_ascii=False, indent=2), encoding="utf-8")


def write_global_stream_log_csv(
    output_path: str | Path,
    events: Sequence[GlobalStreamEvent],
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "stream_turn_index",
                "sample_id",
                "hidden_goal_id",
                "session_id",
                "context_id",
                "turn_role",
                "attack_turn_index",
                "decision",
                "malicious",
                "score",
                "adequacy",
                "reasoning_mode",
                "reasons",
                "query_id",
                "query",
                "assembly_chain_score",
                "assembly_current_advances_chain",
                "assembly_current_closes_chain",
                "assembly_current_phases",
                "assembly_historical_phases",
                "assembly_current_topics",
                "assembly_historical_topics",
                "assembly_shared_topics",
                "assembly_reasons",
                "warnings",
            ],
        )
        writer.writeheader()
        for event in events:
            writer.writerow(
                {
                    "stream_turn_index": event.stream_turn_index,
                    "sample_id": event.sample_id,
                    "hidden_goal_id": event.sample_id,
                    "session_id": event.session_id,
                    "context_id": event.context_id,
                    "turn_role": event.turn_role,
                    "attack_turn_index": event.attack_turn_index or "",
                    "decision": event.decision,
                    "malicious": event.malicious,
                    "score": "%.4f" % event.score,
                    "adequacy": event.adequacy,
                    "reasoning_mode": event.reasoning_mode,
                    "reasons": " | ".join(event.reasons),
                    "query_id": event.query_id,
                    "query": event.query,
                    "assembly_chain_score": "%.4f" % event.assembly_chain_score,
                    "assembly_current_advances_chain": event.assembly_current_advances_chain,
                    "assembly_current_closes_chain": event.assembly_current_closes_chain,
                    "assembly_current_phases": " | ".join(event.assembly_current_phases),
                    "assembly_historical_phases": " | ".join(event.assembly_historical_phases),
                    "assembly_current_topics": " | ".join(event.assembly_current_topics),
                    "assembly_historical_topics": " | ".join(event.assembly_historical_topics),
                    "assembly_shared_topics": " | ".join(event.assembly_shared_topics),
                    "assembly_reasons": " | ".join(event.assembly_reasons),
                    "warnings": " | ".join(event.warnings),
                }
            )


def write_sequential_summary_json(
    output_path: str | Path,
    summary: SequentialEvaluationSummary,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(summary.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_sequential_summary_markdown(
    output_path: str | Path,
    summary: SequentialEvaluationSummary,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Co-Guard 顺序注入评估报告",
        "",
        "生成时间：%s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "",
        "## 核心结果",
        "",
        "- 样本数：%d" % summary.sample_count,
        "- 防御成功数：%d" % summary.defended_count,
        "- 攻击穿透数：%d" % summary.bypass_count,
        "- 防御成功率：%.4f" % summary.defense_success_rate,
        "- 穿透率：%.4f" % summary.bypass_rate,
        "- 第 1 轮即熔断比例：%.4f" % summary.first_turn_stop_rate,
        "- 平均触发熔断轮次：%.4f" % summary.average_stop_turn,
        "- 平均处理轮次数：%.4f" % summary.average_turns_processed,
        "",
        "## 图表文件",
        "",
        "- `figures/outcome_breakdown.svg`：防御成功与攻击穿透的样本数",
        "- `figures/early_stop_histogram.svg`：熔断发生在第几轮的分布",
        "- `figures/cumulative_detection_curve.svg`：随着问题轮次增加的累计拦截率",
        "",
        "## 设计要点",
        "",
        "- 每一组攻击样本都会生成唯一 `session_id`。",
        "- 图节点、图边和查询节点都携带 `session_id`，推理查询只匹配该 session 的子图。",
        "- 每个样本处理完成后都会清理该 session 的图数据，保证后续样本沙盒干净。",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_sequential_plots(
    output_dir: str | Path,
    summary: SequentialEvaluationSummary,
    results: Sequence[SequentialAttackResult],
) -> None:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "outcome_breakdown.svg").write_text(
        _render_outcome_breakdown(summary),
        encoding="utf-8",
    )
    (directory / "early_stop_histogram.svg").write_text(
        _render_early_stop_histogram(results),
        encoding="utf-8",
    )
    (directory / "cumulative_detection_curve.svg").write_text(
        _render_cumulative_detection_curve(summary),
        encoding="utf-8",
    )


def _extract_task_list(payload: Dict[str, Any]) -> List[str]:
    for key in (
        "tasks",
        "subtasks",
        "questions",
        "sequence",
        "decomposed_results",
        "decomposed_questions",
    ):
        value = payload.get(key)
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
    return []


def _render_outcome_breakdown(summary: SequentialEvaluationSummary) -> str:
    peak = max(1, summary.defended_count, summary.bypass_count)
    bars = [
        ("Defended", summary.defended_count, 220, "#2C7FB8"),
        ("Bypass", summary.bypass_count, 520, "#D95F02"),
    ]
    elements = [_plot_title("Outcome Breakdown"), _axis(100, 120, 100, 430), _axis(100, 430, 820, 430)]
    for step in range(5):
        value = peak * step / 4.0
        y = 430 - 260 * (value / float(peak))
        elements.append(_grid_line(100, y, 820, y))
        elements.append(_text(60, y + 5, str(int(round(value))), size=14))
    for label, count, x, color in bars:
        height = 260 * (count / float(peak))
        y = 430 - height
        elements.append(_rect(x, y, 120, height, fill=color))
        elements.append(_text(x + 60, y - 10, str(count), size=16))
        elements.append(_text(x + 60, 458, label, size=16))
    return _svg(elements)


def _render_early_stop_histogram(results: Sequence[SequentialAttackResult]) -> str:
    stop_counts: Dict[int, int] = {}
    for result in results:
        if result.stopped_at_turn is None:
            continue
        stop_counts[result.stopped_at_turn] = stop_counts.get(result.stopped_at_turn, 0) + 1
    if not stop_counts:
        return _svg([_plot_title("Early Stop Histogram"), _text(450, 270, "No early stops", size=22)])

    peak = max(stop_counts.values())
    turn_indices = sorted(stop_counts)
    elements = [_plot_title("Early Stop Histogram"), _axis(100, 120, 100, 430), _axis(100, 430, 820, 430)]
    for step in range(5):
        value = peak * step / 4.0
        y = 430 - 260 * (value / float(peak))
        elements.append(_grid_line(100, y, 820, y))
        elements.append(_text(60, y + 5, str(int(round(value))), size=14))
    for index, turn_index in enumerate(turn_indices):
        x = 140 + index * 140
        count = stop_counts[turn_index]
        height = 260 * (count / float(peak))
        y = 430 - height
        elements.append(_rect(x, y, 90, height, fill="#756BB1"))
        elements.append(_text(x + 45, y - 10, str(count), size=16))
        elements.append(_text(x + 45, 458, "Turn %d" % turn_index, size=15))
    return _svg(elements)


def _render_cumulative_detection_curve(summary: SequentialEvaluationSummary) -> str:
    points = summary.cumulative_detection_curve
    if not points:
        return _svg([_plot_title("Cumulative Detection Curve"), _text(450, 270, "No data", size=22)])

    max_turn = max(point["turn_index"] for point in points)
    chart_left = 100
    chart_right = 820
    chart_top = 120
    chart_bottom = 430
    chart_width = chart_right - chart_left
    chart_height = chart_bottom - chart_top
    elements = [_plot_title("Cumulative Detection Curve"), _axis(chart_left, chart_top, chart_left, chart_bottom), _axis(chart_left, chart_bottom, chart_right, chart_bottom)]
    for step in range(6):
        value = step / 5.0
        y = chart_bottom - chart_height * value
        elements.append(_grid_line(chart_left, y, chart_right, y))
        elements.append(_text(60, y + 5, "%.1f" % value, size=14))
    polyline_points = []
    for point in points:
        ratio = 0.0 if max_turn == 1 else (point["turn_index"] - 1) / float(max_turn - 1)
        x = chart_left + chart_width * ratio
        y = chart_bottom - chart_height * point["detection_rate"]
        polyline_points.append("%.2f,%.2f" % (x, y))
        elements.append(_text(x, chart_bottom + 24, "Turn %d" % point["turn_index"], size=13))
    elements.append(
        '<polyline fill="none" stroke="#2C7FB8" stroke-width="3" points="%s"/>'
        % " ".join(polyline_points)
    )
    return _svg(elements)


def _svg(elements: Sequence[str]) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="900" height="540" viewBox="0 0 900 540">'
        '<rect x="0" y="0" width="900" height="540" fill="#FFFFFF"/>%s</svg>'
        % "".join(elements)
    )


def _plot_title(text: str) -> str:
    return _text(450, 42, text, size=26, weight="bold")


def _text(x: float, y: float, text: str, size: int = 16, weight: str = "normal") -> str:
    return (
        '<text x="%.2f" y="%.2f" font-size="%d" font-family="Helvetica, Arial, sans-serif" '
        'font-weight="%s" text-anchor="middle" fill="#222222">%s</text>'
        % (x, y, size, weight, html.escape(text))
    )


def _rect(x: float, y: float, width: float, height: float, fill: str) -> str:
    return (
        '<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="%s" rx="8" ry="8" stroke="#444444" stroke-width="1"/>'
        % (x, y, width, max(0.0, height), fill)
    )


def _axis(x1: float, y1: float, x2: float, y2: float) -> str:
    return '<line x1="%.2f" y1="%.2f" x2="%.2f" y2="%.2f" stroke="#444444" stroke-width="2"/>' % (
        x1,
        y1,
        x2,
        y2,
    )


def _grid_line(x1: float, y1: float, x2: float, y2: float) -> str:
    return '<line x1="%.2f" y1="%.2f" x2="%.2f" y2="%.2f" stroke="#E6E6E6" stroke-width="1"/>' % (
        x1,
        y1,
        x2,
        y2,
    )


def _mean(values: Sequence[int | float]) -> float:
    if not values:
        return 0.0
    return sum(values) / float(len(values))


def _safe_div(numerator: float, denominator: float) -> float:
    if not denominator:
        return 0.0
    return numerator / denominator
