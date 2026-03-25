from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Callable, List, Sequence

from ..config import AppConfig
from ..pipeline import CoGuardPipeline
from .benchmark import BenchmarkSample

if TYPE_CHECKING:
    from .metrics import SecurityEvaluationSummary


@dataclass
class EvaluationRecord:
    """One pipeline run plus the labels and metadata needed for evaluation."""

    sample_id: str
    query: str
    true_label: int
    predicted_label: int
    source: str
    category: str = ""
    decision: str = "allow"
    malicious: bool = False
    score: float = 0.0
    adequacy: str = "insufficient"
    graph_backend: str = "memory"
    triple_count: int = 0
    evidence_path_count: int = 0
    counter_evidence_path_count: int = 0
    normalized_relations: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class DefenseEvaluator:
    """Run the Co-Guard pipeline over a labeled benchmark."""

    def __init__(
        self,
        config: AppConfig,
        pipeline_factory: Callable[[AppConfig], CoGuardPipeline] | None = None,
        isolate_samples: bool = True,
    ) -> None:
        self.config = config
        self.pipeline_factory = pipeline_factory or (lambda cfg: CoGuardPipeline(config=cfg))
        self.isolate_samples = isolate_samples

    def evaluate(self, samples: Sequence[BenchmarkSample]) -> List[EvaluationRecord]:
        records: List[EvaluationRecord] = []
        shared_pipeline = None
        if not self.isolate_samples:
            shared_pipeline = self.pipeline_factory(self.config)

        for sample in samples:
            pipeline = shared_pipeline or self.pipeline_factory(self.config)
            result = pipeline.process_query(sample.query)
            records.append(
                EvaluationRecord(
                    sample_id=sample.sample_id,
                    query=sample.query,
                    true_label=sample.label,
                    predicted_label=1 if result.malicious else 0,
                    source=sample.source,
                    category=sample.category,
                    decision=result.decision,
                    malicious=result.malicious,
                    score=result.score,
                    adequacy=result.adequacy,
                    graph_backend=result.graph_backend,
                    triple_count=len(result.triples),
                    evidence_path_count=len(result.evidence_paths),
                    counter_evidence_path_count=len(result.counter_evidence_paths),
                    normalized_relations=[
                        triple.normalized_relation for triple in result.triples
                    ],
                    reasons=list(result.reasons),
                    warnings=list(result.warnings),
                )
            )
        return records


def write_predictions_csv(
    output_path: str | Path,
    records: Sequence[EvaluationRecord],
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "sample_id",
                "source",
                "category",
                "true_label",
                "predicted_label",
                "decision",
                "score",
                "adequacy",
                "graph_backend",
                "triple_count",
                "evidence_path_count",
                "counter_evidence_path_count",
                "normalized_relations",
                "reasons",
                "warnings",
                "query",
            ],
        )
        writer.writeheader()
        for record in records:
            writer.writerow(
                {
                    "sample_id": record.sample_id,
                    "source": record.source,
                    "category": record.category,
                    "true_label": record.true_label,
                    "predicted_label": record.predicted_label,
                    "decision": record.decision,
                    "score": "%.4f" % record.score,
                    "adequacy": record.adequacy,
                    "graph_backend": record.graph_backend,
                    "triple_count": record.triple_count,
                    "evidence_path_count": record.evidence_path_count,
                    "counter_evidence_path_count": record.counter_evidence_path_count,
                    "normalized_relations": "|".join(record.normalized_relations),
                    "reasons": " | ".join(record.reasons),
                    "warnings": " | ".join(record.warnings),
                    "query": record.query,
                }
            )


def write_summary_json(
    output_path: str | Path,
    summary: SecurityEvaluationSummary,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(summary.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_summary_markdown(
    output_path: str | Path,
    summary: SecurityEvaluationSummary,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Co-Guard 安全评估报告",
        "",
        "生成时间：%s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "",
        "## 数据集概览",
        "",
        "- 总样本数：%d" % summary.sample_count,
        "- 有害样本数：%d" % summary.harmful_count,
        "- 良性样本数：%d" % summary.benign_count,
        "- 默认决策边界：使用系统原生 `allow/refuse` 输出",
        "",
        "## 核心指标",
        "",
        "- Accuracy：%.4f" % summary.accuracy,
        "- Precision：%.4f" % summary.precision,
        "- Recall：%.4f" % summary.recall,
        "- Specificity：%.4f" % summary.specificity,
        "- F1：%.4f" % summary.f1,
        "- Balanced Accuracy：%.4f" % summary.balanced_accuracy,
        "- FPR：%.4f" % summary.false_positive_rate,
        "- FNR：%.4f" % summary.false_negative_rate,
        "- Score AUC：%.4f" % summary.score_auc,
        "",
        "## 现象解读",
        "",
        "- 有害样本平均分：%.4f" % summary.mean_score_harmful,
        "- 良性样本平均分：%.4f" % summary.mean_score_benign,
        "- 平均风险证据路径数：%.4f" % summary.avg_evidence_paths,
        "- 平均良性反证路径数：%.4f" % summary.avg_counter_evidence_paths,
        "",
        "## 图表文件",
        "",
        "- `figures/confusion_matrix.svg`：原生系统决策的混淆矩阵",
        "- `figures/metrics_overview.svg`：Accuracy / Precision / Recall / Specificity / F1 / Balanced Accuracy",
        "- `figures/score_distribution.svg`：有害与良性样本的分数分布",
        "- `figures/threshold_curves.svg`：基于分数阈值扫描的 Precision / Recall / F1 曲线",
        "- `figures/adequacy_distribution.svg`：推理充分性分布",
        "",
        "## 备注",
        "",
        "- 为避免图上下文跨样本污染，评估模块默认对每个样本独立创建新的 pipeline。",
        "- 如果要做多轮攻击实验，可在后续扩展中关闭隔离模式并按会话组织样本。",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
