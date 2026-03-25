from __future__ import annotations

import argparse
import csv
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from ..config import AppConfig
from .benchmark import load_default_benchmark
from .metrics import SecurityEvaluationSummary, compute_summary
from .plots import write_all_plots
from .runner import (
    DefenseEvaluator,
    write_predictions_csv,
    write_summary_json,
    write_summary_markdown,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate Co-Guard on a labeled benchmark.")
    parser.add_argument(
        "--data-dir",
        default="data",
        help="Directory containing harmful_behaviors.csv and benign_behaviors.csv.",
    )
    parser.add_argument(
        "--harmful-limit",
        type=int,
        help="Optional cap for harmful_behaviors.csv rows.",
    )
    parser.add_argument(
        "--benign-limit",
        type=int,
        help="Optional cap for benign_behaviors.csv rows.",
    )
    parser.add_argument(
        "--include-harmful-strings",
        action="store_true",
        help="Also evaluate harmful_strings.csv as an out-of-domain harmful source.",
    )
    parser.add_argument(
        "--harmful-strings-limit",
        type=int,
        help="Optional cap for harmful_strings.csv rows.",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs/security_eval",
        help="Directory where metrics, predictions, and figures will be written.",
    )
    parser.add_argument(
        "--backend",
        choices=("memory", "neo4j"),
        default="memory",
        help="Graph backend to use during evaluation. Memory is recommended for isolation.",
    )
    parser.add_argument(
        "--llm-backend",
        choices=("rule", "local_openai"),
        help="Override the LLM backend.",
    )
    parser.add_argument(
        "--reuse-pipeline",
        action="store_true",
        help="Reuse one pipeline across all samples. Disabled by default to avoid graph leakage.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = AppConfig.from_env(
        graph_backend=args.backend,
        llm_backend=args.llm_backend,
    )
    samples = load_default_benchmark(
        data_dir=args.data_dir,
        harmful_limit=args.harmful_limit,
        benign_limit=args.benign_limit,
        include_harmful_strings=args.include_harmful_strings,
        harmful_strings_limit=args.harmful_strings_limit,
    )
    evaluator = DefenseEvaluator(
        config=config,
        isolate_samples=not args.reuse_pipeline,
    )
    records = evaluator.evaluate(samples)
    summary = compute_summary(records)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_root = Path(args.output_dir) / timestamp
    figures_dir = output_root / "figures"
    output_root.mkdir(parents=True, exist_ok=True)

    write_predictions_csv(output_root / "predictions.csv", records)
    write_summary_json(output_root / "metrics.json", summary)
    write_summary_markdown(output_root / "summary.md", summary)
    write_source_metrics_csv(output_root / "source_metrics.csv", summary)
    write_threshold_metrics_csv(output_root / "threshold_metrics.csv", summary)
    write_all_plots(figures_dir, summary, records)

    print("Evaluation complete.")
    print("Samples: %d (harmful=%d, benign=%d)" % (
        summary.sample_count,
        summary.harmful_count,
        summary.benign_count,
    ))
    print(
        "Accuracy=%.4f Precision=%.4f Recall=%.4f Specificity=%.4f F1=%.4f"
        % (
            summary.accuracy,
            summary.precision,
            summary.recall,
            summary.specificity,
            summary.f1,
        )
    )
    print("Outputs written to %s" % output_root)
    return 0


def write_source_metrics_csv(
    output_path: str | Path,
    summary: SecurityEvaluationSummary,
) -> None:
    path = Path(output_path)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "name",
                "sample_count",
                "harmful_count",
                "benign_count",
                "accuracy",
                "precision",
                "recall",
                "specificity",
                "f1",
                "refusal_rate",
                "mean_score",
            ],
        )
        writer.writeheader()
        for item in summary.source_metrics:
            writer.writerow(asdict(item))


def write_threshold_metrics_csv(
    output_path: str | Path,
    summary: SecurityEvaluationSummary,
) -> None:
    path = Path(output_path)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["threshold", "precision", "recall", "specificity", "f1"],
        )
        writer.writeheader()
        for point in summary.threshold_points:
            writer.writerow(asdict(point))


if __name__ == "__main__":
    raise SystemExit(main())
