from __future__ import annotations

import json
from typing import Iterable, Sequence

from ..models import RawTriple, RelationCandidate, SchemaRelation


# Keep few-shot examples next to prompt builders so local LLM experiments and
# fallback implementations share one prompt source of truth.
OIE_EXAMPLES = (
    {
        "text": "The 17068.8 millimeter long ALCO RS-3 has a diesel-electric transmission.",
        "entities": ["ALCO RS-3", "17068.8 (millimetres)", "diesel-electric transmission"],
        "triples": [
            {
                "subject": "ALCO RS-3",
                "relation": "length",
                "object": "17068.8 (millimetres)",
            },
            {
                "subject": "ALCO RS-3",
                "relation": "powerType",
                "object": "diesel-electric transmission",
            },
        ],
    },
    {
        "text": "Alan Shepard was born on Nov 18, 1923 and selected by NASA in 1959. He was a member of the Apollo 14 crew.",
        "entities": ["Alan Shepard", "Nov 18, 1923", "NASA", "1959", "Apollo 14"],
        "triples": [
            {
                "subject": "Alan Shepard",
                "relation": "birthDate",
                "object": "Nov 18, 1923",
            },
            {
                "subject": "Alan Shepard",
                "relation": "selectedByNasa",
                "object": "1959",
            },
            {
                "subject": "Alan Shepard",
                "relation": "mission",
                "object": "Apollo 14",
            },
        ],
    },
    {
        "text": "攻击者使用多个Agent绕过安全策略并窃取API密钥。",
        "entities": ["攻击者", "多个Agent", "安全策略", "API密钥"],
        "triples": [
            {
                "subject": "攻击者",
                "relation": "uses_tool",
                "object": "多个Agent",
            },
            {
                "subject": "多个Agent",
                "relation": "bypasses_guardrail",
                "object": "安全策略",
            },
            {
                "subject": "多个Agent",
                "relation": "exfiltrates_secret",
                "object": "API密钥",
            },
        ],
    },
)


ENTITY_EXAMPLES = tuple(
    {"text": example["text"], "entities": example["entities"]} for example in OIE_EXAMPLES
)


DEFINITION_EXAMPLES = (
    {
        "text": "The 17068.8 millimeter long ALCO RS-3 has a diesel-electric transmission.",
        "triples": [
            {
                "subject": "ALCO RS-3",
                "relation": "powerType",
                "object": "diesel-electric transmission",
            },
            {
                "subject": "ALCO RS-3",
                "relation": "length",
                "object": "17068.8 (millimetres)",
            },
        ],
        "definitions": {
            "powerType": "The subject entity uses the type of power or energy source specified by the object entity.",
            "length": "The subject entity has the length or size measurement specified by the object entity.",
        },
    },
    {
        "text": "Alan Shepard was born on Nov 18, 1923 and selected by NASA in 1959. He was a member of the Apollo 14 crew.",
        "triples": [
            {
                "subject": "Alan Shepard",
                "relation": "birthDate",
                "object": "Nov 18, 1923",
            },
            {
                "subject": "Alan Shepard",
                "relation": "selectedByNasa",
                "object": "1959",
            },
            {
                "subject": "Alan Shepard",
                "relation": "mission",
                "object": "Apollo 14",
            },
        ],
        "definitions": {
            "birthDate": "The subject entity was born on the date specified by the object entity.",
            "selectedByNasa": "The subject entity was selected by NASA in the year specified by the object entity.",
            "mission": "The subject entity participated in the event or operation specified by the object entity.",
        },
    },
)


CANONICALIZATION_EXAMPLES = (
    {
        "text": "Alan Shepard was born on Nov 18, 1923 and selected by NASA in 1959. He was a member of the Apollo 14 crew.",
        "triple": {
            "subject": "Alan Shepard",
            "relation": "participatedIn",
            "object": "Apollo 14",
        },
        "definition": "The subject entity took part in the event or mission specified by the object entity.",
        "choices": [
            {
                "name": "mission",
                "definition": "The subject entity participated in the event or operation specified by the object entity.",
            },
            {
                "name": "season",
                "definition": "The subject entity participated in the season of a series specified by the object entity.",
            },
        ],
        "choice": "mission",
        "reason": "The relation refers to participation in a mission, which matches the context of Apollo 14.",
    },
    {
        "text": "Alan Shepard was born on Nov 18, 1923 and selected by NASA in 1959.",
        "triple": {
            "subject": "Alan Shepard",
            "relation": "selectedByAgency",
            "object": "1959",
        },
        "definition": "The subject entity was selected by a specific agency in the year specified by the object entity.",
        "choices": [
            {
                "name": "communicates_with",
                "definition": "The subject communicates with, requests, or connects to another entity.",
            },
            {
                "name": "requests_information",
                "definition": "The subject asks for explanatory or descriptive information about a target.",
            },
        ],
        "choice": None,
        "reason": "Neither candidate captures the meaning of being selected by an agency.",
    },
)


def build_entity_extraction_prompt(text: str) -> str:
    prompt_lines = [
        "Given a piece of text, extract a list of entities from it.",
        "Return JSON only in the form {\"entities\": [\"...\"]}.",
        "",
    ]
    for index, example in enumerate(ENTITY_EXAMPLES, start=1):
        prompt_lines.append("Example %d Text: %s" % (index, example["text"]))
        prompt_lines.append(
            "Example %d Output: %s"
            % (
                index,
                json.dumps({"entities": example["entities"]}, ensure_ascii=False),
            )
        )
        prompt_lines.append("")
    prompt_lines.append("Now extract entities from the following text:")
    prompt_lines.append(text)
    return "\n".join(prompt_lines)


def build_oie_prompt(
    text: str,
    candidate_entities: Sequence[str] | None = None,
    candidate_relations: Sequence[SchemaRelation] | None = None,
) -> str:
    # Candidate hints are advisory only; the model may still surface unseen
    # entities or relations when the text requires them.
    prompt_lines = [
        "Given a piece of text, extract relational triplets in the form of [Subject, Relation, Object] from it.",
        "Return JSON only in the form {\"triples\": [{\"subject\": \"...\", \"relation\": \"...\", \"object\": \"...\"}]}",
        "Use concise but semantically meaningful relation phrases. You may use the candidate entities and candidate relations as hints, but you are not limited to them.",
        "",
    ]
    for index, example in enumerate(OIE_EXAMPLES, start=1):
        prompt_lines.append("Example %d Text: %s" % (index, example["text"]))
        prompt_lines.append(
            "Example %d Output: %s"
            % (
                index,
                json.dumps({"triples": example["triples"]}, ensure_ascii=False),
            )
        )
        prompt_lines.append("")
    prompt_lines.append("Text:")
    prompt_lines.append(text)
    if candidate_entities:
        prompt_lines.append("Candidate Entities:")
        prompt_lines.append(json.dumps(list(candidate_entities), ensure_ascii=False))
    if candidate_relations:
        prompt_lines.append("Potential Relations and Definitions:")
        prompt_lines.append(
            json.dumps(
                [
                    {"name": relation.name, "definition": relation.definition}
                    for relation in candidate_relations
                ],
                ensure_ascii=False,
            )
        )
    return "\n".join(prompt_lines)


def build_relation_definition_prompt(text: str, triples: Sequence[RawTriple]) -> str:
    prompt_lines = [
        "Given a piece of text and a list of relational triplets extracted from it, write a definition for each distinct relation present.",
        "Return JSON only in the form {\"definitions\": {\"relation\": \"definition\"}}.",
        "",
    ]
    for index, example in enumerate(DEFINITION_EXAMPLES, start=1):
        prompt_lines.append("Example %d Text: %s" % (index, example["text"]))
        prompt_lines.append(
            "Example %d Triples: %s"
            % (index, json.dumps(example["triples"], ensure_ascii=False))
        )
        prompt_lines.append(
            "Example %d Output: %s"
            % (
                index,
                json.dumps(
                    {"definitions": example["definitions"]},
                    ensure_ascii=False,
                ),
            )
        )
        prompt_lines.append("")
    prompt_lines.append("Text:")
    prompt_lines.append(text)
    prompt_lines.append("Triples:")
    prompt_lines.append(
        json.dumps(
            [_triple_to_dict(triple) for triple in triples],
            ensure_ascii=False,
        )
    )
    return "\n".join(prompt_lines)


def build_canonicalization_prompt(
    text: str,
    triple: RawTriple,
    relation_definition: str,
    candidates: Sequence[RelationCandidate],
) -> str:
    # Canonicalization is framed as a faithfulness check, not a forced label
    # assignment, so returning null remains a valid answer.
    prompt_lines = [
        "Given a piece of text, a relational triplet extracted from it, and the definition of the relation in it, choose the most appropriate relation to replace it in this context if there is any.",
        "Return JSON only in the form {\"choice\": \"candidate_name_or_null\", \"reason\": \"...\"}.",
        "If none of the candidates preserves the meaning faithfully, return null.",
        "",
    ]
    for index, example in enumerate(CANONICALIZATION_EXAMPLES, start=1):
        prompt_lines.append("Example %d Text: %s" % (index, example["text"]))
        prompt_lines.append(
            "Example %d Triplet: %s"
            % (index, json.dumps(example["triple"], ensure_ascii=False))
        )
        prompt_lines.append(
            "Example %d Definition: %s" % (index, example["definition"])
        )
        prompt_lines.append(
            "Example %d Choices: %s"
            % (index, json.dumps(example["choices"], ensure_ascii=False))
        )
        prompt_lines.append(
            "Example %d Output: %s"
            % (
                index,
                json.dumps(
                    {"choice": example["choice"], "reason": example["reason"]},
                    ensure_ascii=False,
                ),
            )
        )
        prompt_lines.append("")
    prompt_lines.append("Text:")
    prompt_lines.append(text)
    prompt_lines.append("Triplet:")
    prompt_lines.append(json.dumps(_triple_to_dict(triple), ensure_ascii=False))
    prompt_lines.append("Definition:")
    prompt_lines.append(relation_definition)
    prompt_lines.append("Choices:")
    prompt_lines.append(
        json.dumps(
            [
                {"name": candidate.name, "definition": candidate.definition}
                for candidate in candidates
            ],
            ensure_ascii=False,
        )
    )
    return "\n".join(prompt_lines)


def build_retriever_query(text: str, instruction_template: str) -> str:
    return instruction_template.format(text=text)


def schema_relation_texts(relations: Iterable[SchemaRelation]) -> list[str]:
    return [
        "%s: %s" % (relation.name, relation.definition)
        for relation in relations
    ]


def _triple_to_dict(triple: RawTriple) -> dict:
    return {
        "subject": triple.subject,
        "relation": triple.relation,
        "object": triple.object,
    }
