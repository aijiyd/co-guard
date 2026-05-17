import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from coguard.decompose import batch_process_advbench, process_single_query
import coguard.decompose.decompose as decompose_module


class DecomposeModuleTests(unittest.TestCase):
    def test_run_decomposition_returns_question_list(self) -> None:
        with patch.object(
            decompose_module,
            "_resolve_model_path",
            return_value=Path("/tmp/model"),
        ) as resolve_mock, patch.object(
            decompose_module,
            "_create_local_generator_cached",
            return_value=lambda _prompt: [
                {
                    "generated_text": "1. Analyze intent\n2. Extract entities"
                }
            ],
        ) as cached_mock:
            result = decompose_module.run_decomposition("review incident notes", model_path="~/model")

        self.assertEqual(result, ["Analyze intent", "Extract entities"])
        resolve_mock.assert_called_once_with(model_path="~/model")
        cached_mock.assert_called_once_with("/tmp/model")

    def test_process_single_query_can_optionally_write_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "single.jsonl"
            record = process_single_query(
                harmful_query="review incident notes",
                output_filename=output_path,
                decompose_fn=lambda query: ["Inspect: %s" % query],
            )

            self.assertEqual(record.entry_id, 0)
            self.assertEqual(record.status, "ok")
            self.assertEqual(record.decomposed_results, ["Inspect: review incident notes"])
            payload = json.loads(output_path.read_text(encoding="utf-8").strip())
            self.assertEqual(payload["original_query"], "review incident notes")
            self.assertEqual(payload["decomposed_results"], ["Inspect: review incident notes"])

    def test_batch_process_advbench_reads_goal_column_and_isolates_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "goals.csv"
            output_path = Path(temp_dir) / "batch.jsonl"
            error_path = Path(temp_dir) / "errors.jsonl"

            with csv_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["goal"])
                writer.writeheader()
                writer.writerow({"goal": "first prompt"})
                writer.writerow({"goal": "second prompt"})

            def fake_decompose(query: str) -> list[str]:
                if query == "second prompt":
                    raise RuntimeError("boom")
                return ["Analyze %s" % query]

            records = batch_process_advbench(
                output_filename=output_path,
                csv_path=csv_path,
                error_filename=error_path,
                delay_seconds=0.0,
                show_progress=False,
                decompose_fn=fake_decompose,
            )

            self.assertEqual(len(records), 2)
            self.assertEqual(records[0].status, "ok")
            self.assertEqual(records[1].status, "error")
            self.assertEqual(records[0].decomposed_results, ["Analyze first prompt"])
            self.assertEqual(records[1].decomposed_results, ["ERROR: boom"])

            output_lines = output_path.read_text(encoding="utf-8").strip().splitlines()
            error_lines = error_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(output_lines), 1)
            self.assertEqual(len(error_lines), 1)


if __name__ == "__main__":
    unittest.main()
