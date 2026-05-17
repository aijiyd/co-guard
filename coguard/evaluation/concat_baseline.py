from __future__ import annotations

import csv
import json
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Sequence

from ..config import AppConfig
from ..pipeline import CoGuardPipeline
from .benchmark import BenchmarkSample
from .sequential import SequentialAttackSample


@dataclass
class ConcatBaselineRecord:
    """Single-shot prediction for one concatenated attack or benign sequence."""

    record_id: str
    label: str
    query: str
    source_count: int
    malicious: bool
    decision: str
    score: float
    reasoning_mode: str
    adequacy: str
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "label": self.label,
            "query": self.query,
            "source_count": self.source_count,
            "malicious": self.malicious,
            "decision": self.decision,
            "score": self.score,
            "reasoning_mode": self.reasoning_mode,
            "adequacy": self.adequacy,
            "warnings": list(self.warnings),
        }


@dataclass
class ConcatBaselineEvaluation:
    """Complete output of the concatenation baseline."""

    attack_records: List[ConcatBaselineRecord]
    benign_records: List[ConcatBaselineRecord]


@dataclass
class ConcatBaselineSummary:
    attack_sample_count: int
    defended_count: int
    bypass_count: int
    defense_success_rate: float
    bypass_rate: float
    benign_chain_count: int
    benign_refusal_count: int
    benign_false_positive_rate: float
    average_attack_task_count: float
    average_benign_chain_size: float
    average_attack_query_chars: float
    average_benign_query_chars: float
    attack_warning_count: int
    attack_warning_rate: float
    benign_warning_count: int
    benign_warning_rate: float
    attack_fallback_count: int
    attack_fallback_rate: float
    benign_fallback_count: int
    benign_fallback_rate: float
    llm_runtime_stable: bool

    def to_dict(self) -> dict:
        return {
            "attack_sample_count": self.attack_sample_count,
            "defended_count": self.defended_count,
            "bypass_count": self.bypass_count,
            "defense_success_rate": self.defense_success_rate,
            "bypass_rate": self.bypass_rate,
            "benign_chain_count": self.benign_chain_count,
            "benign_refusal_count": self.benign_refusal_count,
            "benign_false_positive_rate": self.benign_false_positive_rate,
            "average_attack_task_count": self.average_attack_task_count,
            "average_benign_chain_size": self.average_benign_chain_size,
            "average_attack_query_chars": self.average_attack_query_chars,
            "average_benign_query_chars": self.average_benign_query_chars,
            "attack_warning_count": self.attack_warning_count,
            "attack_warning_rate": self.attack_warning_rate,
            "benign_warning_count": self.benign_warning_count,
            "benign_warning_rate": self.benign_warning_rate,
            "attack_fallback_count": self.attack_fallback_count,
            "attack_fallback_rate": self.attack_fallback_rate,
            "benign_fallback_count": self.benign_fallback_count,
            "benign_fallback_rate": self.benign_fallback_rate,
            "llm_runtime_stable": self.llm_runtime_stable,
        }


class ConcatBaselineEvaluator:
    """Evaluate a single-shot baseline by concatenating each multi-turn chain."""

    def __init__(
        self,
        config: AppConfig,
        pipeline_factory: Callable[[AppConfig], CoGuardPipeline] = CoGuardPipeline,
        separator: str = "\n",
    ) -> None:
        self.config = config
        self.pipeline = pipeline_factory(config)
        self.separator = separator

    def evaluate(
        self,
        attack_samples: Sequence[SequentialAttackSample],
        benign_samples: Sequence[BenchmarkSample],
        *,
        benign_chain_count: int | None = None,
        benign_chain_size: int = 4,
        seed: int = 7,
    ) -> ConcatBaselineEvaluation:
        attack_records = self.evaluate_attacks(attack_samples)
        benign_records = self.evaluate_benign(
            benign_samples,
            chain_count=benign_chain_count or len(attack_samples),
            chain_size=benign_chain_size,
            seed=seed,
        )
        return ConcatBaselineEvaluation(
            attack_records=attack_records,
            benign_records=benign_records,
        )

    def evaluate_attacks(
        self,
        samples: Sequence[SequentialAttackSample],
    ) -> List[ConcatBaselineRecord]:
        records = []
        for index, sample in enumerate(samples, start=1):
            query = build_concatenated_query(sample.tasks)
            records.append(
                self._run_record(
                    record_id=sample.sample_id or "attack-%04d" % index,
                    label="attack",
                    query=query,
                    source_count=len(sample.tasks),
                )
            )
        return records

    def evaluate_benign(
        self,
        samples: Sequence[BenchmarkSample],
        *,
        chain_count: int,
        chain_size: int,
        seed: int,
    ) -> List[ConcatBaselineRecord]:
        if not samples or chain_count <= 0 or chain_size <= 0:
            return []

        rng = random.Random(seed)
        queries = [sample.query for sample in samples if sample.query.strip()]
        if not queries:
            return []

        records = []
        for index in range(1, chain_count + 1):
            if len(queries) >= chain_size:
                chosen = rng.sample(queries, chain_size)
            else:
                chosen = [rng.choice(queries) for _ in range(chain_size)]
            query = build_concatenated_query(chosen)
            records.append(
                self._run_record(
                    record_id="benign-chain-%04d" % index,
                    label="benign",
                    query=query,
                    source_count=len(chosen),
                )
            )
        return records

    def _run_record(
        self,
        *,
        record_id: str,
        label: str,
        query: str,
        source_count: int,
    ) -> ConcatBaselineRecord:
        context_id = "concat-baseline-%s" % record_id
        result = self.pipeline.process_query(
            query,
            session_id=context_id,
            context_id=context_id,
        )
        self._clear_context(context_id)
        return ConcatBaselineRecord(
            record_id=record_id,
            label=label,
            query=query,
            source_count=source_count,
            malicious=result.malicious,
            decision=result.decision,
            score=result.score,
            reasoning_mode=result.reasoning_mode,
            adequacy=result.adequacy,
            warnings=list(result.warnings),
        )

    def _clear_context(self, context_id: str) -> None:
        graph_store = getattr(self.pipeline, "graph_store", None)
        if graph_store is None:
            return
        if hasattr(graph_store, "clear_context"):
            graph_store.clear_context(context_id)
            return
        if hasattr(graph_store, "clear_session"):
            graph_store.clear_session(context_id)


def build_concatenated_query(items: Sequence[str]) -> str:
    lines = ["Multi-turn user request sequence:"]
    for index, item in enumerate(items, start=1):
        text = " ".join(str(item).split())
        if text:
            lines.append("%d. %s" % (index, text))
    return "\n".join(lines)


def compute_concat_baseline_summary(
    evaluation: ConcatBaselineEvaluation,
) -> ConcatBaselineSummary:
    attacks = list(evaluation.attack_records)
    benign = list(evaluation.benign_records)
    defended_count = sum(1 for record in attacks if record.malicious)
    bypass_count = len(attacks) - defended_count
    benign_refusal_count = sum(1 for record in benign if record.malicious)
    attack_warning_count = sum(1 for record in attacks if record.warnings)
    benign_warning_count = sum(1 for record in benign if record.warnings)
    attack_fallback_count = sum(
        1 for record in attacks if _has_fallback_warning(record.warnings)
    )
    benign_fallback_count = sum(
        1 for record in benign if _has_fallback_warning(record.warnings)
    )
    connection_refused_count = sum(
        1
        for record in attacks + benign
        if _has_connection_refused_warning(record.warnings)
    )
    return ConcatBaselineSummary(
        attack_sample_count=len(attacks),
        defended_count=defended_count,
        bypass_count=bypass_count,
        defense_success_rate=defended_count / float(len(attacks)) if attacks else 0.0,
        bypass_rate=bypass_count / float(len(attacks)) if attacks else 0.0,
        benign_chain_count=len(benign),
        benign_refusal_count=benign_refusal_count,
        benign_false_positive_rate=(
            benign_refusal_count / float(len(benign)) if benign else 0.0
        ),
        average_attack_task_count=_average([record.source_count for record in attacks]),
        average_benign_chain_size=_average([record.source_count for record in benign]),
        average_attack_query_chars=_average([len(record.query) for record in attacks]),
        average_benign_query_chars=_average([len(record.query) for record in benign]),
        attack_warning_count=attack_warning_count,
        attack_warning_rate=attack_warning_count / float(len(attacks)) if attacks else 0.0,
        benign_warning_count=benign_warning_count,
        benign_warning_rate=benign_warning_count / float(len(benign)) if benign else 0.0,
        attack_fallback_count=attack_fallback_count,
        attack_fallback_rate=attack_fallback_count / float(len(attacks)) if attacks else 0.0,
        benign_fallback_count=benign_fallback_count,
        benign_fallback_rate=benign_fallback_count / float(len(benign)) if benign else 0.0,
        llm_runtime_stable=connection_refused_count == 0,
    )


def write_concat_baseline_summary_json(
    output_path: str | Path,
    summary: ConcatBaselineSummary,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")


def write_concat_baseline_summary_markdown(
    output_path: str | Path,
    summary: ConcatBaselineSummary,
    *,
    dataset_path: str | Path,
    benign_dataset_path: str | Path,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# 拼接式单次检测基线",
        "",
        "攻击数据集：`%s`" % Path(dataset_path),
        "良性数据集：`%s`" % Path(benign_dataset_path),
        "",
        "## 核心指标",
        "",
        "- 攻击链样本数：%d" % summary.attack_sample_count,
        "- 防御成功数：%d" % summary.defended_count,
        "- 攻击穿透数：%d" % summary.bypass_count,
        "- 防御成功率：%.4f" % summary.defense_success_rate,
        "- 穿透率：%.4f" % summary.bypass_rate,
        "- 良性拼接链数：%d" % summary.benign_chain_count,
        "- 良性误拒数：%d" % summary.benign_refusal_count,
        "- 良性误拒率：%.4f" % summary.benign_false_positive_rate,
        "- 平均攻击子任务数：%.4f" % summary.average_attack_task_count,
        "- 平均良性链长度：%.4f" % summary.average_benign_chain_size,
        "",
        "## 运行质量",
        "",
        "- 攻击样本 warning 数：%d" % summary.attack_warning_count,
        "- 攻击样本 warning 比例：%.4f" % summary.attack_warning_rate,
        "- 良性样本 warning 数：%d" % summary.benign_warning_count,
        "- 良性样本 warning 比例：%.4f" % summary.benign_warning_rate,
        "- 攻击样本 fallback 数：%d" % summary.attack_fallback_count,
        "- 攻击样本 fallback 比例：%.4f" % summary.attack_fallback_rate,
        "- 良性样本 fallback 数：%d" % summary.benign_fallback_count,
        "- 良性样本 fallback 比例：%.4f" % summary.benign_fallback_rate,
        "- 模型服务全程稳定：%s" % ("是" if summary.llm_runtime_stable else "否"),
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_concat_baseline_predictions_csv(
    output_path: str | Path,
    records: Sequence[ConcatBaselineRecord],
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "record_id",
                "label",
                "source_count",
                "decision",
                "malicious",
                "score",
                "reasoning_mode",
                "adequacy",
                "warning_count",
                "warnings",
                "query",
            ],
        )
        writer.writeheader()
        for record in records:
            writer.writerow(
                {
                    "record_id": record.record_id,
                    "label": record.label,
                    "source_count": record.source_count,
                    "decision": record.decision,
                    "malicious": int(record.malicious),
                    "score": "%.6f" % record.score,
                    "reasoning_mode": record.reasoning_mode,
                    "adequacy": record.adequacy,
                    "warning_count": len(record.warnings),
                    "warnings": " | ".join(record.warnings),
                    "query": record.query.replace("\n", "\\n"),
                }
            )


def write_concat_baseline_records_json(
    output_path: str | Path,
    records: Sequence[ConcatBaselineRecord],
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [record.to_dict() for record in records]
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _average(values: Sequence[int]) -> float:
    return sum(values) / float(len(values)) if values else 0.0


def _has_fallback_warning(warnings: Sequence[str]) -> bool:
    return any("falling back" in warning.lower() for warning in warnings)


def _has_connection_refused_warning(warnings: Sequence[str]) -> bool:
    return any("connection refused" in warning.lower() for warning in warnings)
