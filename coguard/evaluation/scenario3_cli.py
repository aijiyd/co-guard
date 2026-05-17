from __future__ import annotations

import argparse
import json
import logging
import random
from datetime import datetime
from pathlib import Path
from urllib import error, request

from ..config import AppConfig
from .benchmark import DEFAULT_DATA_DIR, load_csv_samples
from .scenario1 import DEFAULT_SCENARIO1_DATASET, load_scenario1_samples
from .scenario3 import (
    compute_scenario3_summary,
    write_scenario3_summary_json,
    write_scenario3_summary_markdown,
)
from .sequential import (
    GlobalMixedStreamEvaluator,
    compute_sequential_summary,
    write_global_stream_events_json,
    write_global_stream_log_csv,
    write_sequential_plots,
    write_sequential_results_json,
    write_turn_log_csv,
)


logger = logging.getLogger(__name__)


OPENAI_COMPATIBLE_BACKENDS = {
    "openai_compatible_local",
    "openai_compatible",
    "vllm_server",
}


def _select_attack_samples(
    samples,
    *,
    limit: int | None,
    selection: str,
    seed: int,
):
    if limit is None or limit <= 0 or limit >= len(samples):
        return list(samples)
    if selection == "random":
        indexed = list(enumerate(samples))
        rng = random.Random(seed)
        chosen = rng.sample(indexed, limit)
        chosen.sort(key=lambda item: item[0])
        return [sample for _, sample in chosen]
    return list(samples[:limit])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Scenario 3: one user stream where hidden attack chains and benign tasks are interleaved."
    )
    parser.add_argument(
        "--profile",
        choices=("fast", "simplified", "thesis_main", "complex", "full"),
        default="simplified",
        help="Scenario-3 experiment profile. 'fast' is the quickest validation profile; 'simplified' is a lighter thesis profile; 'thesis_main' is the recommended main-paper profile; 'complex' increases chain concurrency and benign noise; 'full' runs the original full-scale setup.",
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
        help="CSV file used as the benign background pool.",
    )
    parser.add_argument(
        "--benign-limit",
        type=int,
        default=200,
        help="Optional cap on benign samples loaded from the CSV.",
    )
    parser.add_argument(
        "--min-noise-per-attack-turn",
        type=int,
        default=1,
        help="Minimum benign background turns inserted after each attack turn.",
    )
    parser.add_argument(
        "--max-noise-per-attack-turn",
        type=int,
        default=2,
        help="Maximum benign background turns inserted after each attack turn.",
    )
    parser.add_argument(
        "--noise-every-attack-turns",
        type=int,
        default=1,
        help="Insert benign noise only after every N attack turns.",
    )
    parser.add_argument(
        "--rotate-session-every",
        type=int,
        default=1,
        help="Rotate to a new session after this many global stream turns.",
    )
    parser.add_argument(
        "--max-active-attack-chains",
        type=int,
        default=0,
        help="Maximum number of attack chains active in the global stream at once. 0 means no cap.",
    )
    parser.add_argument(
        "--preserve-order",
        action="store_true",
        help="Preserve attack-sample order instead of shuffling active chains each round.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=7,
        help="Random seed for attack ordering and benign sampling.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=10,
        help="Print one progress line after every N global stream turns. Use 0 to disable.",
    )
    parser.add_argument(
        "--checkpoint-path",
        help="Path to the scenario-3 checkpoint JSON file. Defaults to <output-dir>/scenario3.checkpoint.json.",
    )
    parser.add_argument(
        "--checkpoint-every",
        type=int,
        default=20,
        help="Write one checkpoint after every N global stream turns. Use 0 to disable.",
    )
    parser.add_argument(
        "--resume-from",
        help="Resume from an existing scenario-3 checkpoint JSON file.",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs/scenario3_eval",
        help="Directory where scenario-three outputs will be written.",
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
    parser.add_argument(
        "--require-server-ready",
        action="store_true",
        help="Fail fast when OpenAI-compatible model services are not reachable and responsive before the evaluation starts.",
    )
    return parser


def _resolve_profile_settings(args: argparse.Namespace) -> tuple[int | None, str, int, int, int, int, int]:
    if args.profile == "fast":
        return (
            args.limit or 30,
            "random",
            1,
            1,
            16,
            min(args.max_active_attack_chains if args.max_active_attack_chains > 0 else 2, 2),
            max(args.benign_limit, 100),
        )
    if args.profile == "simplified":
        return (
            args.limit or 50,
            "random",
            1,
            1,
            8,
            min(args.max_active_attack_chains if args.max_active_attack_chains > 0 else 4, 4),
            max(args.benign_limit, 200),
        )
    if args.profile == "thesis_main":
        return (
            args.limit or 100,
            "random",
            1,
            1,
            8,
            min(args.max_active_attack_chains if args.max_active_attack_chains > 0 else 4, 4),
            max(args.benign_limit, 300),
        )
    if args.profile == "complex":
        return (
            args.limit or 60,
            "random",
            1,
            2,
            4,
            min(args.max_active_attack_chains if args.max_active_attack_chains > 0 else 6, 6),
            max(args.benign_limit, 200),
        )
    return (
        args.limit,
        "head",
        args.min_noise_per_attack_turn,
        args.max_noise_per_attack_turn,
        args.noise_every_attack_turns,
        args.max_active_attack_chains,
        args.benign_limit,
    )


def _probe_openai_compatible_server(
    *,
    label: str,
    base_url: str,
    model: str,
    api_key: str,
    timeout_seconds: float,
) -> None:
    normalized_base = (base_url or "http://127.0.0.1:8000/v1").rstrip("/")
    model_name = (model or "").strip()
    if not model_name:
        raise RuntimeError("%s readiness check failed: model name is empty." % label)
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = "Bearer %s" % api_key

    models_request = request.Request(
        "%s/models" % normalized_base,
        headers=headers,
        method="GET",
    )
    try:
        with request.urlopen(models_request, timeout=timeout_seconds) as response:
            models_payload = json.loads(response.read().decode("utf-8"))
    except error.URLError as exc:
        raise RuntimeError("%s readiness check failed on /models: %s" % (label, exc)) from exc

    available_models = {
        str(item.get("id", "")).strip()
        for item in models_payload.get("data", []) or []
        if isinstance(item, dict)
    }
    if available_models and model_name not in available_models:
        raise RuntimeError(
            "%s readiness check failed: model '%s' not found in /models (%s)."
            % (label, model_name, ", ".join(sorted(available_models)))
        )

    chat_payload = {
        "model": model_name,
        "temperature": 0.0,
        "max_tokens": 8,
        "messages": [
            {"role": "system", "content": "Return the single word READY."},
            {"role": "user", "content": "ping"},
        ],
    }
    chat_request = request.Request(
        "%s/chat/completions" % normalized_base,
        data=json.dumps(chat_payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with request.urlopen(chat_request, timeout=timeout_seconds) as response:
            completion_payload = json.loads(response.read().decode("utf-8"))
    except error.URLError as exc:
        raise RuntimeError(
            "%s readiness check failed on /chat/completions: %s" % (label, exc)
        ) from exc
    choices = completion_payload.get("choices", [])
    if not choices:
        raise RuntimeError(
            "%s readiness check failed: /chat/completions returned no choices." % label
        )


def _ensure_model_services_ready(config: AppConfig) -> None:
    timeout_seconds = min(max(config.llm_timeout_seconds, 5.0), 20.0)
    if config.llm_backend.lower() in OPENAI_COMPATIBLE_BACKENDS:
        _probe_openai_compatible_server(
            label="LLM backend",
            base_url=config.llm_base_url,
            model=config.llm_model,
            api_key=config.llm_api_key,
            timeout_seconds=timeout_seconds,
        )
    if config.local_agent_runtime_backend.lower() in OPENAI_COMPATIBLE_BACKENDS:
        _probe_openai_compatible_server(
            label="Local agent runtime",
            base_url=config.local_agent_base_url,
            model=config.local_agent_default_model or config.llm_model,
            api_key=config.local_agent_api_key,
            timeout_seconds=timeout_seconds,
        )


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

    (
        sample_limit,
        sample_selection,
        min_noise,
        max_noise,
        noise_every_attack_turns,
        max_active_attack_chains,
        benign_limit,
    ) = _resolve_profile_settings(args)

    all_samples = load_scenario1_samples(args.input)
    samples = _select_attack_samples(
        all_samples,
        limit=sample_limit,
        selection=sample_selection,
        seed=args.seed,
    )
    benign_samples = load_csv_samples(
        args.benign_input,
        text_column="goal",
        label=0,
        source="benign_background",
        limit=benign_limit,
        category_column="category",
    )
    benign_queries = [sample.query for sample in benign_samples]
    checkpoint_path = (
        Path(args.checkpoint_path)
        if args.checkpoint_path
        else (
            Path(args.resume_from)
            if args.resume_from
            else Path(args.output_dir) / "scenario3.checkpoint.json"
        )
    )
    require_server_ready = args.require_server_ready or args.profile == "thesis_main"
    if require_server_ready:
        _ensure_model_services_ready(config)

    evaluator = GlobalMixedStreamEvaluator(
        config=config,
        benign_queries=benign_queries,
        min_noise_per_attack_turn=min_noise,
        max_noise_per_attack_turn=max_noise,
        noise_every_attack_turns=noise_every_attack_turns,
        rotate_session_every=args.rotate_session_every,
        max_active_attack_chains=max_active_attack_chains,
        shuffle_attack_order=not args.preserve_order,
        progress_every=args.progress_every,
        checkpoint_path=checkpoint_path,
        checkpoint_every=args.checkpoint_every,
        seed=args.seed,
    )
    logger.info(
        "Scenario 3 config: profile=%s attack_samples=%d benign_pool=%d noise=%d-%d every=%d-attacks max_active=%s checkpoint_every=%d"
        % (
            args.profile,
            len(samples),
            len(benign_queries),
            min_noise,
            max_noise,
            noise_every_attack_turns,
            max_active_attack_chains if max_active_attack_chains else 0,
            args.checkpoint_every,
        )
    )
    evaluation = evaluator.evaluate(samples, resume_from=args.resume_from)
    summary = compute_scenario3_summary(evaluation)
    base_summary = compute_sequential_summary(evaluation.attack_results)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_root = Path(args.output_dir) / timestamp
    output_root.mkdir(parents=True, exist_ok=True)

    write_sequential_results_json(output_root / "attack_results.json", evaluation.attack_results)
    write_turn_log_csv(output_root / "attack_turn_log.csv", evaluation.attack_results)
    write_global_stream_events_json(output_root / "stream_events.json", evaluation)
    write_global_stream_log_csv(output_root / "stream_turn_log.csv", evaluation.stream_events)
    write_scenario3_summary_json(output_root / "scenario3_summary.json", summary)
    write_scenario3_summary_markdown(
        output_root / "scenario3_summary.md",
        summary,
        dataset_path=args.input,
        benign_dataset_path=args.benign_input,
    )
    write_sequential_plots(output_root / "figures", base_summary, evaluation.attack_results)

    logger.info("Scenario 3 evaluation complete.")
    logger.info(
        "AttackSamples=%d Defended=%d Bypass=%d SuccessRate=%.4f BenignFPR=%.4f StreamTurns=%d UserContext=%s"
        % (
            summary.attack_sample_count,
            summary.defended_count,
            summary.bypass_count,
            summary.defense_success_rate,
            summary.benign_false_positive_rate,
            summary.stream_turn_count,
            summary.user_context_id,
        )
    )
    logger.info(
        "Runtime quality: attack_warning_rate=%.4f attack_fallback_rate=%.4f benign_warning_rate=%.4f llm_runtime_stable=%s"
        % (
            summary.attack_warning_turn_rate,
            summary.attack_fallback_turn_rate,
            summary.benign_warning_turn_rate,
            "true" if summary.llm_runtime_stable else "false",
        )
    )
    logger.info("Outputs written to %s" % output_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
