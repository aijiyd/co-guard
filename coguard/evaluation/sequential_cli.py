from __future__ import annotations

import argparse
import logging
from datetime import datetime
from pathlib import Path

from ..config import AppConfig
from .sequential import (
    SequentialSessionEvaluator,
    compute_sequential_summary,
    load_attack_sequences,
    write_sequential_plots,
    write_sequential_results_json,
    write_sequential_summary_json,
    write_sequential_summary_markdown,
    write_turn_log_csv,
)


logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate multi-turn attack sequences with session-isolated graph sandboxes."
    )
    parser.add_argument("jsonl_path", help="Path to the JSONL file containing task sequences.")
    parser.add_argument(
        "--output-dir",
        default="outputs/sequential_security_eval",
        help="Directory where sequential metrics and plots will be written.",
    )
    parser.add_argument(
        "--backend",
        choices=("memory", "neo4j"),
        default="neo4j",
        help="Graph backend used during sequential evaluation.",
    )
    parser.add_argument(
        "--llm-backend",
        choices=("auto", "rule", "local_model", "openai_compatible_local", "vllm_server"),
        help="Override the LLM backend.",
    )
    parser.add_argument(
        "--llm-model",
        help="Override the local model name when using the local_model backend.",
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
    samples = load_attack_sequences(args.jsonl_path)
    evaluator = SequentialSessionEvaluator(config=config)
    results = evaluator.evaluate(samples)
    summary = compute_sequential_summary(results)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_root = Path(args.output_dir) / timestamp
    output_root.mkdir(parents=True, exist_ok=True)

    write_sequential_results_json(output_root / "results.json", results)
    write_turn_log_csv(output_root / "turn_log.csv", results)
    write_sequential_summary_json(output_root / "summary.json", summary)
    write_sequential_summary_markdown(output_root / "summary.md", summary)
    write_sequential_plots(output_root / "figures", summary, results)

    logger.info("Sequential evaluation complete.")
    logger.info(
        "Samples=%d Defended=%d Bypass=%d SuccessRate=%.4f"
        % (
            summary.sample_count,
            summary.defended_count,
            summary.bypass_count,
            summary.defense_success_rate,
        )
    )
    logger.info("Outputs written to %s" % output_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
