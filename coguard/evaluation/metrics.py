from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence

from .runner import EvaluationRecord


@dataclass(frozen=True)
class ThresholdPoint:
    threshold: float
    precision: float
    recall: float
    specificity: float
    f1: float


@dataclass(frozen=True)
class SliceMetrics:
    name: str
    sample_count: int
    harmful_count: int
    benign_count: int
    accuracy: float
    precision: float
    recall: float
    specificity: float
    f1: float
    refusal_rate: float
    mean_score: float


@dataclass
class SecurityEvaluationSummary:
    sample_count: int
    harmful_count: int
    benign_count: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    accuracy: float
    precision: float
    recall: float
    specificity: float
    f1: float
    balanced_accuracy: float
    false_positive_rate: float
    false_negative_rate: float
    refusal_rate: float
    mean_score_harmful: float
    mean_score_benign: float
    score_auc: float
    avg_evidence_paths: float
    avg_counter_evidence_paths: float
    adequacy_counts: Dict[str, int] = field(default_factory=dict)
    source_metrics: List[SliceMetrics] = field(default_factory=list)
    threshold_points: List[ThresholdPoint] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "sample_count": self.sample_count,
            "harmful_count": self.harmful_count,
            "benign_count": self.benign_count,
            "confusion_matrix": {
                "tp": self.true_positive,
                "fp": self.false_positive,
                "tn": self.true_negative,
                "fn": self.false_negative,
            },
            "metrics": {
                "accuracy": self.accuracy,
                "precision": self.precision,
                "recall": self.recall,
                "specificity": self.specificity,
                "f1": self.f1,
                "balanced_accuracy": self.balanced_accuracy,
                "false_positive_rate": self.false_positive_rate,
                "false_negative_rate": self.false_negative_rate,
                "refusal_rate": self.refusal_rate,
                "mean_score_harmful": self.mean_score_harmful,
                "mean_score_benign": self.mean_score_benign,
                "score_auc": self.score_auc,
                "avg_evidence_paths": self.avg_evidence_paths,
                "avg_counter_evidence_paths": self.avg_counter_evidence_paths,
            },
            "adequacy_counts": dict(self.adequacy_counts),
            "source_metrics": [
                {
                    "name": item.name,
                    "sample_count": item.sample_count,
                    "harmful_count": item.harmful_count,
                    "benign_count": item.benign_count,
                    "accuracy": item.accuracy,
                    "precision": item.precision,
                    "recall": item.recall,
                    "specificity": item.specificity,
                    "f1": item.f1,
                    "refusal_rate": item.refusal_rate,
                    "mean_score": item.mean_score,
                }
                for item in self.source_metrics
            ],
            "threshold_points": [
                {
                    "threshold": point.threshold,
                    "precision": point.precision,
                    "recall": point.recall,
                    "specificity": point.specificity,
                    "f1": point.f1,
                }
                for point in self.threshold_points
            ],
        }


def compute_summary(
    records: Sequence[EvaluationRecord],
    threshold_steps: int = 25,
) -> SecurityEvaluationSummary:
    sample_count = len(records)
    harmful_count = sum(1 for record in records if record.true_label == 1)
    benign_count = sample_count - harmful_count

    tp = sum(1 for record in records if record.true_label == 1 and record.predicted_label == 1)
    fp = sum(1 for record in records if record.true_label == 0 and record.predicted_label == 1)
    tn = sum(1 for record in records if record.true_label == 0 and record.predicted_label == 0)
    fn = sum(1 for record in records if record.true_label == 1 and record.predicted_label == 0)

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)
    accuracy = _safe_div(tp + tn, sample_count)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    balanced_accuracy = (recall + specificity) / 2.0
    false_positive_rate = _safe_div(fp, fp + tn)
    false_negative_rate = _safe_div(fn, fn + tp)
    refusal_rate = _safe_div(tp + fp, sample_count)

    harmful_scores = [record.score for record in records if record.true_label == 1]
    benign_scores = [record.score for record in records if record.true_label == 0]
    adequacy_counts = Counter(record.adequacy for record in records)
    avg_evidence_paths = _mean(record.evidence_path_count for record in records)
    avg_counter_evidence_paths = _mean(record.counter_evidence_path_count for record in records)

    return SecurityEvaluationSummary(
        sample_count=sample_count,
        harmful_count=harmful_count,
        benign_count=benign_count,
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        specificity=specificity,
        f1=f1,
        balanced_accuracy=balanced_accuracy,
        false_positive_rate=false_positive_rate,
        false_negative_rate=false_negative_rate,
        refusal_rate=refusal_rate,
        mean_score_harmful=_mean(harmful_scores),
        mean_score_benign=_mean(benign_scores),
        score_auc=_score_auc(harmful_scores, benign_scores),
        avg_evidence_paths=avg_evidence_paths,
        avg_counter_evidence_paths=avg_counter_evidence_paths,
        adequacy_counts=dict(adequacy_counts),
        source_metrics=_compute_source_metrics(records),
        threshold_points=_compute_threshold_points(records, steps=threshold_steps),
    )


def _compute_source_metrics(records: Sequence[EvaluationRecord]) -> List[SliceMetrics]:
    grouped: Dict[str, List[EvaluationRecord]] = defaultdict(list)
    for record in records:
        grouped[record.source].append(record)

    metrics: List[SliceMetrics] = []
    for name, group in sorted(grouped.items()):
        sample_count = len(group)
        harmful_count = sum(1 for item in group if item.true_label == 1)
        benign_count = sample_count - harmful_count
        tp = sum(1 for item in group if item.true_label == 1 and item.predicted_label == 1)
        fp = sum(1 for item in group if item.true_label == 0 and item.predicted_label == 1)
        tn = sum(1 for item in group if item.true_label == 0 and item.predicted_label == 0)
        fn = sum(1 for item in group if item.true_label == 1 and item.predicted_label == 0)
        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        specificity = _safe_div(tn, tn + fp)
        accuracy = _safe_div(tp + tn, sample_count)
        f1 = _safe_div(2 * precision * recall, precision + recall)
        metrics.append(
            SliceMetrics(
                name=name,
                sample_count=sample_count,
                harmful_count=harmful_count,
                benign_count=benign_count,
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                specificity=specificity,
                f1=f1,
                refusal_rate=_safe_div(tp + fp, sample_count),
                mean_score=_mean(item.score for item in group),
            )
        )
    return metrics


def _compute_threshold_points(
    records: Sequence[EvaluationRecord],
    steps: int,
) -> List[ThresholdPoint]:
    if not records:
        return []
    minimum = min(record.score for record in records)
    maximum = max(record.score for record in records)
    if maximum == minimum:
        thresholds = [minimum]
    else:
        thresholds = [
            minimum + (maximum - minimum) * step / float(max(1, steps - 1))
            for step in range(steps)
        ]

    points: List[ThresholdPoint] = []
    for threshold in thresholds:
        tp = sum(1 for record in records if record.true_label == 1 and record.score >= threshold)
        fp = sum(1 for record in records if record.true_label == 0 and record.score >= threshold)
        tn = sum(1 for record in records if record.true_label == 0 and record.score < threshold)
        fn = sum(1 for record in records if record.true_label == 1 and record.score < threshold)
        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        specificity = _safe_div(tn, tn + fp)
        f1 = _safe_div(2 * precision * recall, precision + recall)
        points.append(
            ThresholdPoint(
                threshold=threshold,
                precision=precision,
                recall=recall,
                specificity=specificity,
                f1=f1,
            )
        )
    return points


def _score_auc(harmful_scores: Sequence[float], benign_scores: Sequence[float]) -> float:
    if not harmful_scores or not benign_scores:
        return 0.0
    better = 0.0
    total = float(len(harmful_scores) * len(benign_scores))
    for harmful_score in harmful_scores:
        for benign_score in benign_scores:
            if harmful_score > benign_score:
                better += 1.0
            elif harmful_score == benign_score:
                better += 0.5
    return better / total


def _mean(values: Iterable[float]) -> float:
    numbers = list(values)
    if not numbers:
        return 0.0
    return sum(numbers) / float(len(numbers))


def _safe_div(numerator: float, denominator: float) -> float:
    if not denominator:
        return 0.0
    return numerator / denominator
