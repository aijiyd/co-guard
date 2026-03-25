import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from coguard.config import AppConfig
from coguard.graph.entity_similarity import build_entity_profile, entity_relatedness_score
from coguard.models import RawTriple, RelationCandidate, SchemaRelation
from coguard.pipeline import CoGuardPipeline
from coguard.semantic import BaseLLMAdapter, BaseSchemaRetriever, RuleBasedLLMAdapter, SemanticParser


class HintAwareLLMAdapter(BaseLLMAdapter):
    def __init__(self) -> None:
        super().__init__()
        self.extract_triples_calls = []

    def extract_entities(self, query: str):
        del query
        return ["Alan Shepard", "NASA", "1959"]

    def extract_triples(self, query: str, candidate_entities=None, candidate_relations=None):
        del query
        relation_names = [relation.name for relation in (candidate_relations or [])]
        self.extract_triples_calls.append(
            {
                "candidate_entities": list(candidate_entities or []),
                "candidate_relations": relation_names,
            }
        )
        triples = [
            RawTriple(
                subject="Alan Shepard",
                relation="birthDate",
                object="Nov 18, 1923",
            )
        ]
        if "selectedByNasa" in relation_names:
            triples.append(
                RawTriple(
                    subject="Alan Shepard",
                    relation="selectedByNasa",
                    object="1959",
                )
            )
        return triples

    def define_relations(self, query: str, triples):
        del query
        definitions = {}
        for triple in triples:
            if triple.relation == "birthDate":
                definitions[triple.relation] = (
                    "The subject entity was born on the date specified by the object entity."
                )
            elif triple.relation == "selectedByNasa":
                definitions[triple.relation] = (
                    "The subject entity was selected by NASA in the year specified by the object entity."
                )
        return definitions

    def choose_canonical_relation(self, query: str, triple, relation_definition, candidates):
        del query, triple, relation_definition, candidates
        return None

    def describe_subgraph(self, context):
        del context
        return "Context unavailable in test."


class FixedSchemaRetriever(BaseSchemaRetriever):
    def retrieve(self, query: str, schema_relations, top_k: int):
        del query, schema_relations, top_k
        return [
            RelationCandidate(
                name="selectedByNasa",
                definition="The subject entity was selected by NASA in the year specified by the object entity.",
                score=0.95,
            )
        ]


class CoGuardPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pipeline = CoGuardPipeline(config=AppConfig())

    def test_flags_multi_agent_malicious_query(self) -> None:
        result = self.pipeline.process_query(
            "攻击者使用多个Agent绕过安全策略并窃取API密钥"
        )
        normalized_relations = {triple.normalized_relation for triple in result.triples}
        self.assertTrue(result.malicious)
        self.assertEqual(result.decision, "refuse")
        self.assertIn("uses_tool", normalized_relations)
        self.assertIn("bypasses_guardrail", normalized_relations)
        self.assertIn("exfiltrates_secret", normalized_relations)

    def test_reasoner_returns_risk_evidence_paths(self) -> None:
        result = self.pipeline.process_query(
            "攻击者使用多个Agent绕过安全策略并窃取API密钥"
        )

        self.assertEqual(result.reasoning_mode, "tog_relation_first")
        self.assertEqual(result.adequacy, "sufficient_for_refuse")
        self.assertTrue(result.evidence_paths)
        self.assertTrue(
            any(
                step.relation in {"bypasses_guardrail", "exfiltrates_secret"}
                for path in result.evidence_paths
                for step in path.steps
            )
        )

    def test_allows_benign_analysis_query(self) -> None:
        result = self.pipeline.process_query("分析用户反馈并更新知识库")
        normalized_relations = {triple.normalized_relation for triple in result.triples}
        self.assertFalse(result.malicious)
        self.assertEqual(result.decision, "allow")
        self.assertIn("analyzes_target", normalized_relations)
        self.assertIn("updates_resource", normalized_relations)

    def test_reasoner_returns_benign_counter_evidence_paths(self) -> None:
        result = self.pipeline.process_query("分析用户反馈并更新知识库")

        self.assertEqual(result.reasoning_mode, "tog_relation_first")
        self.assertEqual(result.adequacy, "sufficient_for_allow")
        self.assertTrue(result.counter_evidence_paths)
        self.assertTrue(
            any(
                step.relation in {"analyzes_target", "updates_resource"}
                for path in result.counter_evidence_paths
                for step in path.steps
            )
        )

    def test_context_subgraph_accumulates_history(self) -> None:
        self.pipeline.process_query("系统存储客户订单数据")
        result = self.pipeline.process_query("分析订单数据并更新报表")
        entity_names = {node.name for node in result.context.nodes if node.kind == "entity"}
        self.assertIn("客户订单数据", entity_names)
        self.assertIn("订单数据", entity_names)
        self.assertGreaterEqual(len(result.context.edges), 4)

    def test_entity_relatedness_prefers_semantically_compatible_entities(self) -> None:
        data_profile = build_entity_profile("订单数据")
        similar_data_profile = build_entity_profile("客户订单数据")
        tool_profile = build_entity_profile("订单工具")

        self.assertGreater(
            entity_relatedness_score(data_profile, similar_data_profile),
            0.68,
        )
        self.assertLess(
            entity_relatedness_score(data_profile, tool_profile),
            0.68,
        )

    def test_context_expansion_avoids_pulling_in_type_mismatched_entities(self) -> None:
        self.pipeline.process_query("系统存储客户订单数据")
        self.pipeline.process_query("系统使用订单工具")
        result = self.pipeline.process_query("分析订单数据并更新报表")
        entity_names = {node.name for node in result.context.nodes if node.kind == "entity"}

        self.assertIn("客户订单数据", entity_names)
        self.assertNotIn("订单工具", entity_names)

    def test_edc_style_open_extraction_supports_out_of_schema_relations(self) -> None:
        adapter = RuleBasedLLMAdapter()
        triples = adapter.extract_triples(
            "Alan Shepard was born on Nov 18, 1923 and selected by NASA in 1959."
        )
        self.assertIn("born on", {triple.relation for triple in triples})
        self.assertIn("selected by", {triple.relation for triple in triples})

    def test_edc_style_extraction_resolves_pronoun_subjects_from_context(self) -> None:
        adapter = RuleBasedLLMAdapter()
        triples = adapter.extract_triples(
            "Alan Shepard was born on Nov 18, 1923. He was a member of the Apollo 14 crew."
        )
        membership_triples = [triple for triple in triples if triple.relation == "member of"]
        self.assertEqual(len(membership_triples), 1)
        self.assertEqual(membership_triples[0].subject, "Alan Shepard")
        self.assertEqual(membership_triples[0].object, "the Apollo 14 crew")

    def test_contextual_relation_definition_falls_back_to_custom_relation(self) -> None:
        parser = SemanticParser(llm_adapter=RuleBasedLLMAdapter())
        triples = parser.parse("Alan Shepard was born on Nov 18, 1923 and selected by NASA in 1959.")
        definitions = {triple.raw_relation: triple.relation_definition for triple in triples}
        normalized = {triple.raw_relation: triple.normalized_relation for triple in triples}
        self.assertIn("selected, appointed, or chosen", definitions["selected by"])
        self.assertEqual(normalized["selected by"], "custom_selected_by")

    def test_refinement_passes_entities_and_relations_back_into_oie(self) -> None:
        adapter = HintAwareLLMAdapter()
        pipeline = CoGuardPipeline(
            config=AppConfig(refinement_iterations=1),
            llm_adapter=adapter,
            schema_retriever=FixedSchemaRetriever(),
        )
        result = pipeline.process_query(
            "Alan Shepard was born on Nov 18, 1923 and selected by NASA in 1959."
        )
        self.assertEqual(len(adapter.extract_triples_calls), 2)
        refined_call = adapter.extract_triples_calls[1]
        self.assertIn("NASA", refined_call["candidate_entities"])
        self.assertIn("selectedByNasa", refined_call["candidate_relations"])
        self.assertIn(
            "selectedByNasa",
            {triple.raw_relation for triple in result.triples},
        )

    def test_config_reads_defaults_from_dotenv_when_env_is_unset(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "COGUARD_LLM_BACKEND=local_openai",
                        "COGUARD_LLM_BASE_URL=http://127.0.0.1:9000/v1",
                        "COGUARD_REFINEMENT_ITERATIONS=2",
                        "COGUARD_SCHEMA_RETRIEVER_INSTRUCTION=\"Instruct: retrieve relations\\nQuery: {text}\"",
                    ]
                ),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                config = AppConfig.from_env(env_path=env_path)

        self.assertEqual(config.llm_backend, "local_openai")
        self.assertEqual(config.llm_base_url, "http://127.0.0.1:9000/v1")
        self.assertEqual(config.refinement_iterations, 2)
        self.assertIn("\n", config.schema_retriever_instruction)


if __name__ == "__main__":
    unittest.main()
