import tempfile
import unittest
from pathlib import Path

from coguard.config import AppConfig
from coguard.evaluation.benchmark import BenchmarkSample, load_csv_samples
from coguard.evaluation.cli import write_source_metrics_csv, write_threshold_metrics_csv
from coguard.evaluation.metrics import compute_summary
from coguard.evaluation.plots import write_all_plots
from coguard.evaluation.runner import (
    DefenseEvaluator,
    EvaluationRecord,
    write_predictions_csv,
    write_summary_json,
    write_summary_markdown,
)
from coguard.models import ContextSubgraph, QueryAnalysisResult


class FakePipeline:
    def process_query(self, query: str) -> QueryAnalysisResult:
        malicious = "attack" in query.lower() or "exploit" in query.lower()
        score = 6.0 if malicious else 1.0
        return QueryAnalysisResult(
            query_id="query-test",
            query=query,
            triples=[],
            context=ContextSubgraph(),
            context_description="test context",
            malicious=malicious,
            decision="refuse" if malicious else "allow",
            score=score,
            reasons=["fake reason"],
            reasoning_mode="tog_relation_first",
            adequacy="sufficient_for_refuse" if malicious else "sufficient_for_allow",
            evidence_paths=[],
            counter_evidence_paths=[],
            missing_links=[],
            graph_backend="memory",
            warnings=[],
        )


class EvaluationModuleTests(unittest.TestCase):
    def test_load_csv_samples_reads_text_and_category(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "samples.csv"
            csv_path.write_text(
                "goal,category\nReview logs,benign\nBlock exploit chain,harmful\n",
                encoding="utf-8",
            )
            samples = load_csv_samples(
                csv_path,
                text_column="goal",
                label=0,
                source="custom_benign",
                category_column="category",
            )

        self.assertEqual(len(samples), 2)
        self.assertEqual(samples[0].query, "Review logs")
        self.assertEqual(samples[0].category, "benign")
        self.assertEqual(samples[0].source, "custom_benign")

    def test_compute_summary_returns_expected_metrics(self) -> None:
        records = [
            EvaluationRecord("a", "harmful one", 1, 1, "harmful", score=6.0),
            EvaluationRecord("b", "harmful two", 1, 0, "harmful", score=2.0),
            EvaluationRecord("c", "benign one", 0, 0, "benign", score=1.0),
            EvaluationRecord("d", "benign two", 0, 1, "benign", score=5.0),
        ]
        summary = compute_summary(records, threshold_steps=3)

        self.assertEqual(summary.true_positive, 1)
        self.assertEqual(summary.false_positive, 1)
        self.assertEqual(summary.true_negative, 1)
        self.assertEqual(summary.false_negative, 1)
        self.assertAlmostEqual(summary.accuracy, 0.5)
        self.assertAlmostEqual(summary.precision, 0.5)
        self.assertAlmostEqual(summary.recall, 0.5)
        self.assertAlmostEqual(summary.specificity, 0.5)
        self.assertEqual(len(summary.threshold_points), 3)

    def test_evaluator_exports_metrics_and_svg_plots(self) -> None:
        samples = [
            BenchmarkSample("h-1", "How to exploit a system", 1, "harmful_behaviors"),
            BenchmarkSample("b-1", "Analyze user feedback", 0, "benign_behaviors"),
        ]
        evaluator = DefenseEvaluator(
            config=AppConfig(),
            pipeline_factory=lambda _config: FakePipeline(),
            isolate_samples=True,
        )
        records = evaluator.evaluate(samples)
        summary = compute_summary(records, threshold_steps=5)

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            write_predictions_csv(output_dir / "predictions.csv", records)
            write_summary_json(output_dir / "metrics.json", summary)
            write_summary_markdown(output_dir / "summary.md", summary)
            write_source_metrics_csv(output_dir / "source_metrics.csv", summary)
            write_threshold_metrics_csv(output_dir / "threshold_metrics.csv", summary)
            write_all_plots(output_dir / "figures", summary, records)

            self.assertTrue((output_dir / "predictions.csv").exists())
            self.assertTrue((output_dir / "metrics.json").exists())
            self.assertTrue((output_dir / "summary.md").exists())
            self.assertTrue((output_dir / "source_metrics.csv").exists())
            self.assertTrue((output_dir / "threshold_metrics.csv").exists())
            self.assertTrue((output_dir / "figures" / "confusion_matrix.svg").exists())
            self.assertTrue((output_dir / "figures" / "score_distribution.svg").exists())
            self.assertTrue((output_dir / "figures" / "threshold_curves.svg").exists())


if __name__ == "__main__":
    unittest.main()
