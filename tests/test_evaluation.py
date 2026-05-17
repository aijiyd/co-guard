import tempfile
import unittest
from pathlib import Path
from typing import Optional

from coguard.config import AppConfig
from coguard.evaluation.benchmark import BenchmarkSample, load_csv_samples
from coguard.evaluation.cli import write_source_metrics_csv, write_threshold_metrics_csv
from coguard.evaluation.concat_baseline import (
    ConcatBaselineEvaluator,
    compute_concat_baseline_summary,
    write_concat_baseline_predictions_csv,
    write_concat_baseline_records_json,
    write_concat_baseline_summary_json,
    write_concat_baseline_summary_markdown,
)
from coguard.evaluation.metrics import compute_summary
from coguard.evaluation.plots import write_all_plots
from coguard.evaluation.sequential import (
    GlobalMixedStreamEvaluator,
    InterleavedContextEvaluator,
    SequentialAttackResult,
    SequentialAttackSample,
    SequentialSessionEvaluator,
    SequentialTurnResult,
    compute_sequential_summary,
    write_global_stream_events_json,
    write_global_stream_log_csv,
    write_sequential_plots,
    write_sequential_results_json,
    write_sequential_summary_json,
    write_sequential_summary_markdown,
    write_turn_log_csv,
)
from coguard.evaluation.scenario1 import compute_scenario1_summary, load_scenario1_samples
from coguard.evaluation.scenario3 import compute_scenario3_summary
from coguard.evaluation.scenario3_cli import build_parser as build_scenario3_parser
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


class FakeSequentialGraphStore:
    def __init__(self) -> None:
        self.cleared_sessions = []
        self.cleared_contexts = []
        self.export_calls = 0
        self.imported_states = []

    def clear_session(self, session_id: str) -> None:
        self.cleared_sessions.append(session_id)

    def clear_context(self, context_id: str) -> None:
        self.cleared_contexts.append(context_id)

    def export_state(self) -> dict:
        self.export_calls += 1
        return {"export_calls": self.export_calls}

    def import_state(self, state: dict) -> None:
        self.imported_states.append(dict(state))


class FakeSequentialPipeline:
    def __init__(self) -> None:
        self.graph_store = FakeSequentialGraphStore()
        self.call_index = 0

    def process_query(
        self,
        query: str,
        session_id: Optional[str] = None,
        context_id: Optional[str] = None,
    ) -> QueryAnalysisResult:
        self.call_index += 1
        should_refuse = "final" in query.lower()
        return QueryAnalysisResult(
            query_id="%s-query-%d" % (session_id or "global", self.call_index),
            query=query,
            triples=[],
            context=ContextSubgraph(),
            context_description="test context",
            malicious=should_refuse,
            decision="refuse" if should_refuse else "allow",
            score=7.0 if should_refuse else 1.0,
            reasons=["fake sequential reason"],
            reasoning_mode="tog_relation_first",
            adequacy="sufficient_for_refuse" if should_refuse else "uncertain",
            evidence_paths=[],
            counter_evidence_paths=[],
            missing_links=[],
            graph_backend="memory",
            warnings=[],
            session_id=session_id or "",
            context_id=context_id or session_id or "",
        )


class InterruptingFakeSequentialPipeline(FakeSequentialPipeline):
    def __init__(self, fail_after_calls: int) -> None:
        super().__init__()
        self.fail_after_calls = fail_after_calls

    def process_query(
        self,
        query: str,
        session_id: Optional[str] = None,
        context_id: Optional[str] = None,
    ) -> QueryAnalysisResult:
        if self.call_index >= self.fail_after_calls:
            raise RuntimeError("simulated interruption")
        return super().process_query(query, session_id=session_id, context_id=context_id)


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

    def test_sequential_evaluator_stops_early_and_clears_sessions(self) -> None:
        fake_pipeline = FakeSequentialPipeline()
        samples = [
            SequentialAttackSample(
                sample_id="attack-1",
                tasks=["step one", "final harmful step", "unused tail"],
            ),
            SequentialAttackSample(
                sample_id="attack-2",
                tasks=["step one", "step two"],
            ),
        ]
        evaluator = SequentialSessionEvaluator(
            config=AppConfig(),
            pipeline_factory=lambda _config: fake_pipeline,
        )
        results = evaluator.evaluate(samples)
        summary = compute_sequential_summary(results)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].outcome, "defended")
        self.assertEqual(results[0].stopped_at_turn, 2)
        self.assertEqual(len(results[0].turns), 2)
        self.assertEqual(results[1].outcome, "bypass")
        self.assertIsNone(results[1].stopped_at_turn)
        self.assertEqual(summary.defended_count, 1)
        self.assertEqual(summary.bypass_count, 1)
        self.assertEqual(len(fake_pipeline.graph_store.cleared_sessions), 2)

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            write_sequential_results_json(output_dir / "results.json", results)
            write_turn_log_csv(output_dir / "turn_log.csv", results)
            write_sequential_summary_json(output_dir / "summary.json", summary)
            write_sequential_summary_markdown(output_dir / "summary.md", summary)
            write_sequential_plots(output_dir / "figures", summary, results)

            self.assertTrue((output_dir / "results.json").exists())
            self.assertTrue((output_dir / "turn_log.csv").exists())
            self.assertTrue((output_dir / "summary.json").exists())
            self.assertTrue((output_dir / "summary.md").exists())
            self.assertTrue((output_dir / "figures" / "outcome_breakdown.svg").exists())
            turn_log = (output_dir / "turn_log.csv").read_text(encoding="utf-8")
            results_json = (output_dir / "results.json").read_text(encoding="utf-8")
            self.assertIn("reasoning_mode", turn_log)
            self.assertIn("fake sequential reason", turn_log)
            self.assertIn('"reasoning_mode"', results_json)
            self.assertIn("fake sequential reason", results_json)

    def test_interleaved_context_evaluator_inserts_noise_and_rotates_sessions(self) -> None:
        fake_pipeline = FakeSequentialPipeline()
        samples = [
            SequentialAttackSample(
                sample_id="attack-1",
                tasks=["step one", "final harmful step"],
            )
        ]
        evaluator = InterleavedContextEvaluator(
            config=AppConfig(),
            benign_queries=["benign noise"],
            pipeline_factory=lambda _config: fake_pipeline,
            min_noise_per_gap=1,
            max_noise_per_gap=1,
            rotate_session_every=1,
            seed=0,
        )

        results = evaluator.evaluate(samples)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].outcome, "defended")
        self.assertEqual(results[0].stopped_at_turn, 2)
        self.assertEqual(
            [turn.turn_role for turn in results[0].turns],
            ["attack", "noise", "attack"],
        )
        self.assertEqual(
            [turn.attack_turn_index for turn in results[0].turns],
            [1, None, 2],
        )
        self.assertEqual(
            len({turn.session_id for turn in results[0].turns}),
            3,
        )
        self.assertEqual(
            len({turn.context_id for turn in results[0].turns}),
            1,
        )
        self.assertEqual(len(fake_pipeline.graph_store.cleared_contexts), 1)

    def test_global_mixed_stream_evaluator_interleaves_attack_chains_and_benign_tasks(self) -> None:
        fake_pipeline = FakeSequentialPipeline()
        samples = [
            SequentialAttackSample(
                sample_id="attack-1",
                tasks=["step one", "final harmful step"],
            ),
            SequentialAttackSample(
                sample_id="attack-2",
                tasks=["prep step", "final payload"],
            ),
        ]
        evaluator = GlobalMixedStreamEvaluator(
            config=AppConfig(),
            benign_queries=["benign one"],
            pipeline_factory=lambda _config: fake_pipeline,
            min_noise_per_attack_turn=1,
            max_noise_per_attack_turn=1,
            rotate_session_every=1,
            max_active_attack_chains=2,
            shuffle_attack_order=False,
            progress_every=2,
            seed=0,
        )

        with self.assertLogs("coguard.evaluation.sequential", level="INFO") as captured_logs:
            evaluation = evaluator.evaluate(samples)
        summary = compute_scenario3_summary(evaluation)

        self.assertEqual(len(evaluation.attack_results), 2)
        self.assertEqual(summary.attack_sample_count, 2)
        self.assertEqual(summary.defended_count, 2)
        self.assertEqual(summary.benign_turn_count, 4)
        self.assertEqual(summary.benign_refusal_count, 0)
        self.assertAlmostEqual(summary.benign_false_positive_rate, 0.0)
        self.assertEqual(
            [event.turn_role for event in evaluation.stream_events],
            ["attack", "noise", "attack", "noise", "attack", "noise", "attack", "noise"],
        )
        self.assertEqual(
            [event.sample_id for event in evaluation.stream_events if event.turn_role == "attack"],
            ["attack-1", "attack-2", "attack-1", "attack-2"],
        )
        self.assertEqual(
            len({result.context_id for result in evaluation.attack_results}),
            1,
        )
        self.assertEqual(
            len({event.context_id for event in evaluation.stream_events}),
            1,
        )
        self.assertEqual(summary.user_context_id, evaluation.user_context_id)
        self.assertEqual(summary.hidden_goal_count, 2)
        self.assertEqual(summary.distinct_visible_context_count, 1)
        self.assertEqual(summary.distinct_session_count, 8)
        self.assertEqual(
            fake_pipeline.graph_store.cleared_contexts,
            [evaluation.user_context_id],
        )
        combined_logs = "\n".join(captured_logs.output)
        self.assertIn("progress stream_turn=2", combined_logs)
        self.assertIn("active_goals=", combined_logs)

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            write_global_stream_events_json(output_dir / "stream_events.json", evaluation)
            write_global_stream_log_csv(output_dir / "stream_turn_log.csv", evaluation.stream_events)
            self.assertTrue((output_dir / "stream_events.json").exists())
            self.assertTrue((output_dir / "stream_turn_log.csv").exists())
            stream_log = (output_dir / "stream_turn_log.csv").read_text(encoding="utf-8")
            stream_events = (output_dir / "stream_events.json").read_text(encoding="utf-8")
            self.assertIn("stream_turn_index", stream_log)
            self.assertIn("hidden_goal_id", stream_log)
            self.assertIn("attack-1", stream_log)
            self.assertIn('"stream_id"', stream_events)
            self.assertIn('"user_context_id"', stream_events)

    def test_global_mixed_stream_evaluator_can_insert_noise_every_n_attacks(self) -> None:
        fake_pipeline = FakeSequentialPipeline()
        samples = [
            SequentialAttackSample(sample_id="attack-1", tasks=["step one", "step two"]),
            SequentialAttackSample(sample_id="attack-2", tasks=["prep step", "prep two"]),
        ]
        evaluator = GlobalMixedStreamEvaluator(
            config=AppConfig(),
            benign_queries=["benign one"],
            pipeline_factory=lambda _config: fake_pipeline,
            min_noise_per_attack_turn=1,
            max_noise_per_attack_turn=1,
            noise_every_attack_turns=2,
            max_active_attack_chains=2,
            shuffle_attack_order=False,
            progress_every=0,
            seed=0,
        )

        evaluation = evaluator.evaluate(samples)

        self.assertEqual(
            [event.turn_role for event in evaluation.stream_events],
            ["attack", "attack", "noise", "attack", "attack", "noise"],
        )
        self.assertEqual(evaluation.benign_turn_count, 2)

    def test_compute_scenario3_summary_reports_warning_and_fallback_rates(self) -> None:
        fake_pipeline = FakeSequentialPipeline()
        samples = [
            SequentialAttackSample(sample_id="attack-1", tasks=["step one", "final harmful step"]),
        ]
        evaluator = GlobalMixedStreamEvaluator(
            config=AppConfig(),
            benign_queries=["benign one"],
            pipeline_factory=lambda _config: fake_pipeline,
            min_noise_per_attack_turn=1,
            max_noise_per_attack_turn=1,
            rotate_session_every=1,
            max_active_attack_chains=1,
            shuffle_attack_order=False,
            progress_every=0,
            seed=0,
        )

        evaluation = evaluator.evaluate(samples)
        evaluation.attack_results[0].turns[0].warnings = [
            "OpenAI-compatible OIE failed, falling back to rule-based extraction: <urlopen error [Errno 111] Connection refused>"
        ]
        for event in evaluation.stream_events:
            if event.turn_role == "attack" and event.attack_turn_index == 1:
                event.warnings = list(evaluation.attack_results[0].turns[0].warnings)
            if event.turn_role == "noise":
                event.warnings = [
                    "OpenAI-compatible graph judgment failed, falling back to rule-based reasoning: malformed json"
                ]

        summary = compute_scenario3_summary(evaluation)

        self.assertEqual(summary.attack_warning_turn_count, 1)
        self.assertAlmostEqual(summary.attack_warning_turn_rate, 0.5)
        self.assertEqual(summary.attack_fallback_turn_count, 1)
        self.assertEqual(summary.attack_connection_refused_turn_count, 1)
        self.assertEqual(summary.benign_warning_turn_count, 2)
        self.assertEqual(summary.benign_fallback_turn_count, 2)
        self.assertAlmostEqual(summary.benign_warning_turn_rate, 1.0)
        self.assertFalse(summary.llm_runtime_stable)

    def test_scenario3_parser_accepts_thesis_main_profile(self) -> None:
        parser = build_scenario3_parser()
        args = parser.parse_args(["--profile", "thesis_main"])

        self.assertEqual(args.profile, "thesis_main")

    def test_concat_baseline_evaluator_reports_attack_and_benign_metrics(self) -> None:
        fake_pipeline = FakeSequentialPipeline()
        attack_samples = [
            SequentialAttackSample(
                sample_id="attack-1",
                tasks=["step one", "final harmful step"],
            ),
            SequentialAttackSample(
                sample_id="attack-2",
                tasks=["step one", "step two"],
            ),
        ]
        benign_samples = [
            BenchmarkSample("benign-1", "summarize meeting notes", 0, "benign"),
            BenchmarkSample("benign-2", "explain database indexing", 0, "benign"),
            BenchmarkSample("benign-3", "write a travel plan", 0, "benign"),
        ]
        evaluator = ConcatBaselineEvaluator(
            config=AppConfig(),
            pipeline_factory=lambda _config: fake_pipeline,
        )

        evaluation = evaluator.evaluate(
            attack_samples,
            benign_samples,
            benign_chain_count=2,
            benign_chain_size=2,
            seed=1,
        )
        summary = compute_concat_baseline_summary(evaluation)

        self.assertEqual(summary.attack_sample_count, 2)
        self.assertEqual(summary.defended_count, 1)
        self.assertEqual(summary.bypass_count, 1)
        self.assertAlmostEqual(summary.defense_success_rate, 0.5)
        self.assertEqual(summary.benign_chain_count, 2)
        self.assertEqual(summary.benign_refusal_count, 0)
        self.assertAlmostEqual(summary.benign_false_positive_rate, 0.0)
        self.assertEqual(len(fake_pipeline.graph_store.cleared_contexts), 4)

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            write_concat_baseline_summary_json(output_dir / "summary.json", summary)
            write_concat_baseline_summary_markdown(
                output_dir / "summary.md",
                summary,
                dataset_path="attacks.jsonl",
                benign_dataset_path="benign.csv",
            )
            write_concat_baseline_records_json(
                output_dir / "attack_predictions.json",
                evaluation.attack_records,
            )
            write_concat_baseline_predictions_csv(
                output_dir / "attack_predictions.csv",
                evaluation.attack_records,
            )

            self.assertTrue((output_dir / "summary.json").exists())
            self.assertTrue((output_dir / "summary.md").exists())
            self.assertTrue((output_dir / "attack_predictions.json").exists())
            self.assertTrue((output_dir / "attack_predictions.csv").exists())
            csv_payload = (output_dir / "attack_predictions.csv").read_text(encoding="utf-8")
            self.assertIn("record_id,label,source_count", csv_payload)
            self.assertIn("attack-1", csv_payload)

    def test_global_mixed_stream_evaluator_resumes_from_checkpoint(self) -> None:
        samples = [
            SequentialAttackSample(sample_id="attack-1", tasks=["step one", "final harmful step"]),
            SequentialAttackSample(sample_id="attack-2", tasks=["prep step", "final payload"]),
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            checkpoint_path = Path(temp_dir) / "scenario3.checkpoint.json"
            interrupting_pipeline = InterruptingFakeSequentialPipeline(fail_after_calls=2)
            interrupting_evaluator = GlobalMixedStreamEvaluator(
                config=AppConfig(),
                benign_queries=[],
                pipeline_factory=lambda _config: interrupting_pipeline,
                max_active_attack_chains=2,
                shuffle_attack_order=False,
                checkpoint_path=checkpoint_path,
                checkpoint_every=1,
                seed=0,
            )

            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                interrupting_evaluator.evaluate(samples)

            self.assertTrue(checkpoint_path.exists())

            resumed_pipeline = FakeSequentialPipeline()
            resumed_evaluator = GlobalMixedStreamEvaluator(
                config=AppConfig(),
                benign_queries=[],
                pipeline_factory=lambda _config: resumed_pipeline,
                max_active_attack_chains=2,
                shuffle_attack_order=False,
                checkpoint_path=checkpoint_path,
                checkpoint_every=1,
                seed=0,
            )
            resumed = resumed_evaluator.evaluate(samples, resume_from=checkpoint_path)

            clean_pipeline = FakeSequentialPipeline()
            clean_evaluator = GlobalMixedStreamEvaluator(
                config=AppConfig(),
                benign_queries=[],
                pipeline_factory=lambda _config: clean_pipeline,
                max_active_attack_chains=2,
                shuffle_attack_order=False,
                checkpoint_path=None,
                checkpoint_every=0,
                seed=0,
            )
            clean = clean_evaluator.evaluate(samples)

            self.assertGreaterEqual(len(resumed_pipeline.graph_store.imported_states), 1)
            self.assertEqual(
                [(result.sample_id, result.outcome, result.stopped_at_turn) for result in resumed.attack_results],
                [(result.sample_id, result.outcome, result.stopped_at_turn) for result in clean.attack_results],
            )
            self.assertEqual(
                [(event.turn_role, event.sample_id, event.decision) for event in resumed.stream_events],
                [(event.turn_role, event.sample_id, event.decision) for event in clean.stream_events],
            )
            payload = checkpoint_path.read_text(encoding="utf-8")
            self.assertIn('"completed": true', payload)

    def test_load_scenario1_samples_supports_decomposed_results(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            jsonl_path = Path(temp_dir) / "advbench_decomposed.jsonl"
            jsonl_path.write_text(
                (
                    '{"id": 1, "original_query": "prompt", '
                    '"decomposed_results": ["q1", "q2"]}\n'
                ),
                encoding="utf-8",
            )
            samples = load_scenario1_samples(jsonl_path)

        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].sample_id, "1")
        self.assertEqual(samples[0].tasks, ["q1", "q2"])
        self.assertEqual(samples[0].metadata["original_query"], "prompt")

    def test_compute_scenario1_summary_reports_late_detection_rate(self) -> None:
        results = [
            SequentialAttackResult(
                sample_id="a",
                session_id="s-a",
                task_count=3,
                outcome="defended",
                stopped_at_turn=2,
                turns=[
                    SequentialTurnResult(
                        turn_index=1,
                        query="q1",
                        query_id="q1",
                        decision="allow",
                        malicious=False,
                        score=1.0,
                        adequacy="uncertain",
                    ),
                    SequentialTurnResult(
                        turn_index=2,
                        query="q2",
                        query_id="q2",
                        decision="refuse",
                        malicious=True,
                        score=7.0,
                        adequacy="sufficient_for_refuse",
                        assembly_chain_score=3.6,
                        assembly_current_advances_chain=True,
                        assembly_historical_topics=["explosive_weapon"],
                        assembly_current_phases=["execution_preparation"],
                        assembly_historical_phases=["target_scoping", "capability_building"],
                    ),
                ],
            ),
            SequentialAttackResult(
                sample_id="b",
                session_id="s-b",
                task_count=2,
                outcome="bypass",
                stopped_at_turn=None,
                turns=[
                    SequentialTurnResult(
                        turn_index=1,
                        query="q1",
                        query_id="q1",
                        decision="allow",
                        malicious=False,
                        score=0.5,
                        adequacy="uncertain",
                    ),
                    SequentialTurnResult(
                        turn_index=2,
                        query="q2",
                        query_id="q2",
                        decision="allow",
                        malicious=False,
                        score=0.2,
                        adequacy="uncertain",
                        assembly_chain_score=1.2,
                    ),
                ],
            ),
        ]
        summary = compute_scenario1_summary(results)

        self.assertEqual(summary.sample_count, 2)
        self.assertAlmostEqual(summary.late_detection_rate, 0.5)
        self.assertAlmostEqual(summary.average_task_count, 2.5)
        self.assertAlmostEqual(summary.assembly_driven_detection_rate, 1.0)
        self.assertAlmostEqual(summary.information_loss_bypass_rate, 1.0)


if __name__ == "__main__":
    unittest.main()
