from __future__ import annotations

import argparse
import logging
from datetime import datetime
from pathlib import Path

from ..config import AppConfig
from .scenario1 import (
    DEFAULT_SCENARIO1_DATASET,
    compute_scenario1_summary,
    load_scenario1_samples,
    write_scenario1_summary_json,
    write_scenario1_summary_markdown,
)
from .sequential import (
    SequentialSessionEvaluator,
    write_sequential_plots,
    write_sequential_results_json,
    write_sequential_summary_json,
    write_sequential_summary_markdown,
    write_turn_log_csv,
)


logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Scenario 1: continuous sequential injection on decomposed AdvBench samples."
    )
    parser.add_argument(
        "--input",
        default=str(DEFAULT_SCENARIO1_DATASET),
        help="Path to advbench_decomposed.jsonl or another compatible JSONL file.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Optional cap on the number of samples.",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs/scenario1_eval",
        help="Directory where scenario-one outputs will be written.",
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
    evaluator = SequentialSessionEvaluator(config=config)
    results = evaluator.evaluate(samples)
    sequential_summary = compute_scenario1_summary(results)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_root = Path(args.output_dir) / timestamp
    output_root.mkdir(parents=True, exist_ok=True)

    write_sequential_results_json(output_root / "results.json", results)
    write_turn_log_csv(output_root / "turn_log.csv", results)
    write_sequential_summary_json(output_root / "summary.json", sequential_summary)
    write_sequential_summary_markdown(output_root / "summary.md", sequential_summary)
    write_scenario1_summary_json(output_root / "scenario1_metrics.json", sequential_summary)
    write_scenario1_summary_markdown(
        output_root / "scenario1_summary.md",
        sequential_summary,
        dataset_path=args.input,
    )
    write_sequential_plots(output_root / "figures", sequential_summary, results)

    logger.info("Scenario 1 evaluation complete.")
    logger.info(
        "Samples=%d Defended=%d Bypass=%d SuccessRate=%.4f LateDetectionRate=%.4f"
        % (
            sequential_summary.sample_count,
            sequential_summary.defended_count,
            sequential_summary.bypass_count,
            sequential_summary.defense_success_rate,
            sequential_summary.late_detection_rate,
        )
    )
    logger.info("Outputs written to %s" % output_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
