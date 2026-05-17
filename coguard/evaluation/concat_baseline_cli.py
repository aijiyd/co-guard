from __future__ import annotations

import argparse
import logging
import random
from datetime import datetime
from pathlib import Path

from ..config import AppConfig
from .benchmark import DEFAULT_DATA_DIR, load_csv_samples
from .concat_baseline import (
    ConcatBaselineEvaluator,
    compute_concat_baseline_summary,
    write_concat_baseline_predictions_csv,
    write_concat_baseline_records_json,
    write_concat_baseline_summary_json,
    write_concat_baseline_summary_markdown,
)
from .scenario1 import DEFAULT_SCENARIO1_DATASET, load_scenario1_samples


logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a single-shot concatenation baseline for decomposed attack chains."
    )
    parser.add_argument(
        "--input",
        default=str(DEFAULT_SCENARIO1_DATASET),
        help="Path to advbench_decomposed.jsonl or another compatible JSONL file.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Optional cap on attack samples. Omit it to evaluate all samples.",
    )
    parser.add_argument(
        "--selection",
        choices=("head", "random"),
        default="head",
        help="How to select attack samples when --limit is set.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=7,
        help="Random seed for sample selection and benign-chain construction.",
    )
    parser.add_argument(
        "--benign-input",
        default=str(DEFAULT_DATA_DIR / "benign_behaviors.csv"),
        help="CSV file used to construct benign concatenation chains.",
    )
    parser.add_argument(
        "--benign-limit",
        type=int,
        default=300,
        help="Optional cap on benign samples loaded from the CSV.",
    )
    parser.add_argument(
        "--benign-chain-count",
        type=int,
        help="Number of benign chains. Defaults to the selected attack sample count.",
    )
    parser.add_argument(
        "--benign-chain-size",
        type=int,
        default=4,
        help="Number of benign queries concatenated into each benign chain.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=10,
        help="Print one progress line after every N attack or benign records. Use 0 to disable.",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs/concat_baseline",
        help="Directory where baseline outputs will be written.",
    )
    parser.add_argument(
        "--backend",
        choices=("memory", "neo4j"),
        default="memory",
        help="Graph backend used during the baseline.",
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


class ProgressConcatBaselineEvaluator(ConcatBaselineEvaluator):
    def __init__(self, *args, progress_every: int = 0, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.progress_every = max(0, progress_every)
        self._processed = 0

    def _run_record(self, *, record_id: str, label: str, query: str, source_count: int):
        self._processed += 1
        if self.progress_every and (
            self._processed == 1 or self._processed % self.progress_every == 0
        ):
            logger.info(
                "[concat-baseline] start index=%d label=%s record_id=%s items=%d"
                % (self._processed, label, record_id, source_count)
            )
        record = super()._run_record(
            record_id=record_id,
            label=label,
            query=query,
            source_count=source_count,
        )
        if self.progress_every and (
            self._processed == 1 or self._processed % self.progress_every == 0
        ):
            logger.info(
                "[concat-baseline] done index=%d label=%s record_id=%s decision=%s score=%.4f warnings=%d"
                % (
                    self._processed,
                    label,
                    record_id,
                    record.decision,
                    record.score,
                    len(record.warnings),
                )
            )
        return record


def _select_attack_samples(samples, *, limit: int | None, selection: str, seed: int):
    if limit is None or limit <= 0 or limit >= len(samples):
        return list(samples)
    if selection == "random":
        indexed = list(enumerate(samples))
        rng = random.Random(seed)
        chosen = rng.sample(indexed, limit)
        chosen.sort(key=lambda item: item[0])
        return [sample for _, sample in chosen]
    return list(samples[:limit])


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
    all_attack_samples = load_scenario1_samples(args.input)
    attack_samples = _select_attack_samples(
        all_attack_samples,
        limit=args.limit,
        selection=args.selection,
        seed=args.seed,
    )
    benign_samples = load_csv_samples(
        args.benign_input,
        text_column="goal",
        label=0,
        source="benign_concat",
        limit=args.benign_limit,
        category_column="category",
    )

    benign_chain_count = args.benign_chain_count or len(attack_samples)
    logger.info(
        "Concat baseline config: attacks=%d selection=%s benign_pool=%d benign_chains=%d benign_chain_size=%d"
        % (
            len(attack_samples),
            args.selection,
            len(benign_samples),
            benign_chain_count,
            args.benign_chain_size,
        )
    )

    evaluator = ProgressConcatBaselineEvaluator(
        config=config,
        progress_every=args.progress_every,
    )
    evaluation = evaluator.evaluate(
        attack_samples,
        benign_samples,
        benign_chain_count=benign_chain_count,
        benign_chain_size=args.benign_chain_size,
        seed=args.seed,
    )
    summary = compute_concat_baseline_summary(evaluation)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_root = Path(args.output_dir) / timestamp
    output_root.mkdir(parents=True, exist_ok=True)

    write_concat_baseline_summary_json(output_root / "concat_baseline_summary.json", summary)
    write_concat_baseline_summary_markdown(
        output_root / "concat_baseline_summary.md",
        summary,
        dataset_path=args.input,
        benign_dataset_path=args.benign_input,
    )
    write_concat_baseline_records_json(
        output_root / "attack_predictions.json",
        evaluation.attack_records,
    )
    write_concat_baseline_records_json(
        output_root / "benign_predictions.json",
        evaluation.benign_records,
    )
    write_concat_baseline_predictions_csv(
        output_root / "attack_predictions.csv",
        evaluation.attack_records,
    )
    write_concat_baseline_predictions_csv(
        output_root / "benign_predictions.csv",
        evaluation.benign_records,
    )

    logger.info("Concat baseline evaluation complete.")
    logger.info(
        "AttackSamples=%d Defended=%d Bypass=%d SuccessRate=%.4f BenignFPR=%.4f"
        % (
            summary.attack_sample_count,
            summary.defended_count,
            summary.bypass_count,
            summary.defense_success_rate,
            summary.benign_false_positive_rate,
        )
    )
    logger.info("Outputs written to %s" % output_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
