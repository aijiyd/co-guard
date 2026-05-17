from __future__ import annotations

import argparse
import logging
from datetime import datetime
from pathlib import Path

from ..config import AppConfig
from .benchmark import DEFAULT_DATA_DIR, load_csv_samples
from .scenario1 import (
    DEFAULT_SCENARIO1_DATASET,
    compute_scenario1_summary,
    load_scenario1_samples,
    write_scenario1_summary_json,
    write_scenario1_summary_markdown,
)
from .sequential import (
    InterleavedContextEvaluator,
    write_sequential_plots,
    write_sequential_results_json,
    write_sequential_summary_json,
    write_sequential_summary_markdown,
    write_turn_log_csv,
)


logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Scenario 2: cross-session attack chains with benign noise interleaving."
    )
    parser.add_argument(
        "--input",
        default=str(DEFAULT_SCENARIO1_DATASET),
        help="Path to advbench_decomposed.jsonl or another compatible JSONL file.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Optional cap on the number of attack samples.",
    )
    parser.add_argument(
        "--benign-input",
        default=str(DEFAULT_DATA_DIR / "benign_behaviors.csv"),
        help="CSV file used as the benign noise pool.",
    )
    parser.add_argument(
        "--benign-limit",
        type=int,
        default=200,
        help="Optional cap on benign noise samples loaded from the CSV.",
    )
    parser.add_argument(
        "--min-noise-per-gap",
        type=int,
        default=1,
        help="Minimum benign noise turns inserted between adjacent attack turns.",
    )
    parser.add_argument(
        "--max-noise-per-gap",
        type=int,
        default=2,
        help="Maximum benign noise turns inserted between adjacent attack turns.",
    )
    parser.add_argument(
        "--rotate-session-every",
        type=int,
        default=1,
        help="Rotate to a new session after this many stream turns.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=7,
        help="Random seed for benign noise sampling.",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs/scenario2_eval",
        help="Directory where scenario-two outputs will be written.",
    )
    parser.add_argument(
        "--backend",
        choices=("memory", "neo4j"),
        default="memory",
        help="Graph backend used during the evaluation.",
    )
    parser.add_argument(
        "--llm-backend",
        choices=("auto", "rule", "local_model", "openai_compatible_local", "vllm_server"),
        help="Override the LLM backend.",
    )
    parser.add_argument(
        "--llm-model",
        help="Override the LLM model name.",
    )
    parser.add_argument(
        "--llm-model-path",
        help="Override the local model directory. Defaults to /model.",
    )
    parser.add_argument(
        "--reasoning-strategy",
        choices=("rules", "llm", "hybrid"),
        help="Override the graph reasoning strategy.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format="%(message)s")

    parser = build_parser()
    args = parser.parse_args(argv)

    config = AppConfig.from_env(
        graph_backend=args.backend,
        llm_backend=args.llm_backend,
        llm_model=args.llm_model,
        llm_model_path=args.llm_model_path,
        reasoning_strategy=args.reasoning_strategy,
    )

    samples = load_scenario1_samples(args.input, limit=args.limit)
    benign_samples = load_csv_samples(
        args.benign_input,
        text_column="goal",
        label=0,
        source="benign_noise",
        limit=args.benign_limit,
        category_column="category",
    )
    benign_queries = [sample.query for sample in benign_samples]
    evaluator = InterleavedContextEvaluator(
        config=config,
        benign_queries=benign_queries,
        min_noise_per_gap=args.min_noise_per_gap,
        max_noise_per_gap=args.max_noise_per_gap,
        rotate_session_every=args.rotate_session_every,
        seed=args.seed,
    )
    results = evaluator.evaluate(samples)
    summary = compute_scenario1_summary(results)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_root = Path(args.output_dir) / timestamp
    output_root.mkdir(parents=True, exist_ok=True)

    write_sequential_results_json(output_root / "results.json", results)
    write_turn_log_csv(output_root / "turn_log.csv", results)
    write_sequential_summary_json(output_root / "summary.json", summary)
    write_sequential_summary_markdown(output_root / "summary.md", summary)
    write_scenario1_summary_json(output_root / "scenario2_metrics.json", summary)
    write_scenario1_summary_markdown(
        output_root / "scenario2_summary.md",
        summary,
        dataset_path=args.input,
    )
    write_sequential_plots(output_root / "figures", summary, results)

    logger.info("Scenario 2 evaluation complete.")
    logger.info(
        "Samples=%d Defended=%d Bypass=%d SuccessRate=%.4f LateDetectionRate=%.4f"
        % (
            summary.sample_count,
            summary.defended_count,
            summary.bypass_count,
            summary.defense_success_rate,
            summary.late_detection_rate,
        )
    )
    logger.info("Outputs written to %s" % output_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
