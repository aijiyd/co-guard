from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ATTACK_INPUT = ROOT / "data" / "advbench_decomposed.jsonl"
DEFAULT_BENIGN_INPUT = ROOT / "data" / "benign_behaviors.csv"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the final Co-Guard experiment suite (scenario1/2/3)."
    )
    parser.add_argument("--input", default=str(DEFAULT_ATTACK_INPUT))
    parser.add_argument("--benign-input", default=str(DEFAULT_BENIGN_INPUT))
    parser.add_argument("--output-root", default="outputs/final_experiments")
    parser.add_argument("--backend", choices=("memory", "neo4j"), default="memory")
    parser.add_argument(
        "--llm-backend",
        choices=("auto", "rule", "local_model", "openai_compatible_local", "vllm_server"),
        help="Override the LLM backend for all scenarios.",
    )
    parser.add_argument("--llm-model", help="Override the LLM model name for all scenarios.")
    parser.add_argument("--llm-model-path", help="Override the local model directory for all scenarios.")
    parser.add_argument("--reasoning-strategy", choices=("rules", "llm", "hybrid"), default="hybrid")
    parser.add_argument("--scenario1-limit", type=int)
    parser.add_argument("--scenario2-limit", type=int)
    parser.add_argument("--scenario3-limit", type=int)
    parser.add_argument("--benign-limit", type=int, default=500)
    parser.add_argument("--scenario2-min-noise", type=int, default=1)
    parser.add_argument("--scenario2-max-noise", type=int, default=2)
    parser.add_argument("--scenario3-min-noise", type=int, default=1)
    parser.add_argument("--scenario3-max-noise", type=int, default=2)
    parser.add_argument("--scenario3-max-active-attack-chains", type=int, default=16)
    parser.add_argument("--scenario3-progress-every", type=int, default=10)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output_root = Path(args.output_root)
    output_root.mkdir(parents=True, exist_ok=True)

    base = [
        sys.executable,
        "-u",
    ]
    shared = [
        "--input",
        args.input,
        "--backend",
        args.backend,
        "--reasoning-strategy",
        args.reasoning_strategy,
    ]
    if args.llm_backend:
        shared.extend(["--llm-backend", args.llm_backend])
    if args.llm_model:
        shared.extend(["--llm-model", args.llm_model])
    if args.llm_model_path:
        shared.extend(["--llm-model-path", args.llm_model_path])

    commands = []

    scenario1 = base + [
        "-m",
        "coguard.evaluation.scenario1_cli",
        *shared,
        "--output-dir",
        str(output_root / "scenario1"),
    ]
    if args.scenario1_limit is not None:
        scenario1.extend(["--limit", str(args.scenario1_limit)])
    commands.append(("scenario1", scenario1))

    scenario2 = base + [
        "-m",
        "coguard.evaluation.scenario2_cli",
        *shared,
        "--benign-input",
        args.benign_input,
        "--benign-limit",
        str(args.benign_limit),
        "--min-noise-per-gap",
        str(args.scenario2_min_noise),
        "--max-noise-per-gap",
        str(args.scenario2_max_noise),
        "--output-dir",
        str(output_root / "scenario2"),
    ]
    if args.scenario2_limit is not None:
        scenario2.extend(["--limit", str(args.scenario2_limit)])
    commands.append(("scenario2", scenario2))

    scenario3 = base + [
        "-m",
        "coguard.evaluation.scenario3_cli",
        *shared,
        "--benign-input",
        args.benign_input,
        "--benign-limit",
        str(args.benign_limit),
        "--min-noise-per-attack-turn",
        str(args.scenario3_min_noise),
        "--max-noise-per-attack-turn",
        str(args.scenario3_max_noise),
        "--max-active-attack-chains",
        str(args.scenario3_max_active_attack_chains),
        "--progress-every",
        str(args.scenario3_progress_every),
        "--output-dir",
        str(output_root / "scenario3"),
    ]
    if args.scenario3_limit is not None:
        scenario3.extend(["--limit", str(args.scenario3_limit)])
    commands.append(("scenario3", scenario3))

    for name, command in commands:
        print("[suite] start %s" % name, flush=True)
        subprocess.run(command, cwd=str(ROOT), check=True)
        print("[suite] done %s" % name, flush=True)

    print("[suite] all evaluations complete -> %s" % output_root, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
