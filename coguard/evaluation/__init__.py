"""Evaluation module for measuring Co-Guard's defensive performance."""

from .benchmark import BenchmarkSample, load_default_benchmark
from .concat_baseline import (
    ConcatBaselineEvaluation,
    ConcatBaselineRecord,
    ConcatBaselineSummary,
    compute_concat_baseline_summary,
)
from .metrics import SecurityEvaluationSummary, compute_summary
from .runner import DefenseEvaluator, EvaluationRecord
from .scenario1 import (
    ScenarioOneSummary,
    compute_scenario1_summary,
    load_scenario1_samples,
)
from .scenario3 import ScenarioThreeSummary, compute_scenario3_summary
from .sequential import (
    GlobalMixedStreamEvaluation,
    GlobalMixedStreamEvaluator,
    InterleavedContextEvaluator,
    SequentialAttackResult,
    SequentialAttackSample,
    SequentialEvaluationSummary,
    SequentialSessionEvaluator,
    compute_sequential_summary,
    load_attack_sequences,
)

__all__ = [
    "BenchmarkSample",
    "ConcatBaselineEvaluation",
    "ConcatBaselineRecord",
    "ConcatBaselineSummary",
    "DefenseEvaluator",
    "EvaluationRecord",
    "GlobalMixedStreamEvaluation",
    "GlobalMixedStreamEvaluator",
    "ScenarioOneSummary",
    "ScenarioThreeSummary",
    "InterleavedContextEvaluator",
    "SequentialAttackSample",
    "SequentialAttackResult",
    "SequentialEvaluationSummary",
    "SequentialSessionEvaluator",
    "compute_scenario1_summary",
    "compute_scenario3_summary",
    "compute_concat_baseline_summary",
    "SecurityEvaluationSummary",
    "compute_sequential_summary",
    "compute_summary",
    "load_attack_sequences",
    "load_default_benchmark",
    "load_scenario1_samples",
]
