from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from typing import Optional

from .config import AppConfig
from .pipeline import CoGuardPipeline


def build_parser() -> argparse.ArgumentParser:
    # Keep the CLI thin: it only maps user input into config overrides.
    parser = argparse.ArgumentParser(description="Run the Co-Guard safety pipeline.")
    parser.add_argument("query", nargs="?", help="User query to analyze.")
    parser.add_argument("-q", "--query-text", dest="query_text", help="User query to analyze.")
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Start an interactive session.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the analysis result as JSON.",
    )
    parser.add_argument(
        "--backend",
        choices=("memory", "neo4j"),
        help="Override the graph backend.",
    )
    parser.add_argument(
        "--llm-backend",
        choices=("rule", "local_openai"),
        help="Override the LLM backend.",
    )
    parser.add_argument(
        "--llm-base-url",
        help="Override the local OpenAI-compatible LLM base URL.",
    )
    parser.add_argument(
        "--llm-model",
        help="Override the LLM model name.",
    )
    parser.add_argument(
        "--schema-retriever-backend",
        choices=("vector", "sentence_transformer", "openai_embedding"),
        help="Override the schema retriever backend.",
    )
    parser.add_argument(
        "--schema-retriever-model",
        help="Override the schema retriever model name or local path.",
    )
    parser.add_argument(
        "--schema-retriever-base-url",
        help="Override the schema retriever OpenAI-compatible embeddings base URL.",
    )
    parser.add_argument(
        "--refinement-iterations",
        type=int,
        help="Override the number of EDC refinement iterations.",
    )
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # All configuration precedence lives in AppConfig, so CLI, environment
    # variables, and .env defaults resolve through a single code path.
    config = AppConfig.from_env(
        graph_backend=args.backend,
        llm_backend=args.llm_backend,
        llm_base_url=args.llm_base_url,
        llm_model=args.llm_model,
        schema_retriever_backend=args.schema_retriever_backend,
        schema_retriever_model=args.schema_retriever_model,
        schema_retriever_base_url=args.schema_retriever_base_url,
        refinement_iterations=args.refinement_iterations,
    )
    pipeline = CoGuardPipeline(config=config)

    query = args.query_text or args.query
    if args.interactive:
        return _run_interactive(pipeline, as_json=args.json)
    if not query:
        parser.print_help()
        return 1
    return _run_once(pipeline, query, as_json=args.json)


def _run_once(pipeline: CoGuardPipeline, query: str, as_json: bool) -> int:
    result = pipeline.process_query(query)
    if as_json:
        print(json.dumps(asdict(result), ensure_ascii=False, indent=2))
    else:
        print(_render_text_result(result))
    return 0


def _run_interactive(pipeline: CoGuardPipeline, as_json: bool) -> int:
    print("Co-Guard interactive mode. Type 'exit' to quit.")
    while True:
        try:
            query = input("> ").strip()
        except EOFError:
            print()
            break
        if not query:
            continue
        if query.lower() in {"exit", "quit"}:
            break
        _run_once(pipeline, query, as_json=as_json)
    return 0


def _render_text_result(result) -> str:
    # Render output in pipeline order so terminal users can still see the
    # extraction, graph, and reasoning stages without opening the code.
    lines = [
        "Query ID: %s" % result.query_id,
        "Backend: %s" % result.graph_backend,
        "Decision: %s" % result.decision,
        "Malicious: %s" % ("yes" if result.malicious else "no"),
        "Score: %.2f" % result.score,
        "Reasoning: %s (%s)" % (result.reasoning_mode, result.adequacy),
        "Triples:",
    ]
    for triple in result.triples:
        lines.append(
            "  - %s --%s/%s--> %s (cluster=%s, confidence=%.2f)"
            % (
                triple.subject,
                triple.raw_relation,
                triple.normalized_relation,
                triple.object,
                triple.cluster_id,
                triple.confidence,
            )
        )
    lines.append("Context: %s" % result.context_description)
    lines.append("Reasons: %s" % "; ".join(result.reasons))
    if result.evidence_paths:
        lines.append("Evidence Paths:")
        for path in result.evidence_paths:
            lines.append(
                "  - [%s] %.2f %s"
                % (
                    path.label,
                    path.risk_score,
                    _render_reasoning_path(path),
                )
            )
    if result.counter_evidence_paths:
        lines.append("Counter Evidence Paths:")
        for path in result.counter_evidence_paths:
            lines.append(
                "  - [%s] %.2f %s"
                % (
                    path.label,
                    path.benign_score,
                    _render_reasoning_path(path),
                )
            )
    if result.missing_links:
        lines.append("Missing Links: %s" % "; ".join(result.missing_links))
    if result.warnings:
        lines.append("Warnings: %s" % "; ".join(result.warnings))
    return "\n".join(lines)


def _render_reasoning_path(path) -> str:
    if not path.steps:
        return path.seed_entity
    parts = []
    for step in path.steps:
        if step.direction == "incoming":
            parts.append("%s <--%s-- %s" % (step.target, step.relation, step.source))
        else:
            parts.append("%s --%s--> %s" % (step.source, step.relation, step.target))
    return " ; ".join(parts)
