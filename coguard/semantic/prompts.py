from __future__ import annotations

import json
from typing import Iterable, Sequence

from ..models import CanonicalizationItem, RawTriple, RelationCandidate, SchemaRelation


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

EDC_OIE_EXAMPLES = (
    {
        "text": "The location of Trane is Swords, Dublin.",
        "candidate_entities": ["Trane", "Swords,_Dublin"],
        "triples": [["Trane", "location", "Swords,_Dublin"]],
    },
    {
        "text": "The 17068.8 millimeter long ALCO RS-3 has a diesel-electric transmission.",
        "candidate_entities": [
            "Diesel-electric_transmission",
            "ALCO_RS-3",
            "17068.8 (millimetres)",
        ],
        "triples": [
            ["ALCO_RS-3", "powerType", "Diesel-electric_transmission"],
            ["ALCO_RS-3", "length", "17068.8 (millimetres)"],
        ],
    },
    {
        "text": "Alan B. Miller Hall, in Virginia, USA, was designed by Robert A.M. Stern. The address of the hall is \"101 Ukrop Way\" and the current tenants are the Mason School of Business.",
        "candidate_entities": [
            "Alan_B._Miller_Hall",
            "\"101 Ukrop Way\"",
            "United_States",
            "Mason_School_of_Business",
            "Robert_A._M._Stern",
            "Virginia",
        ],
        "triples": [
            ["Alan_B._Miller_Hall", "architect", "Robert_A._M._Stern"],
            ["Alan_B._Miller_Hall", "address", "\"101 Ukrop Way\""],
            ["Alan_B._Miller_Hall", "currentTenants", "Mason_School_of_Business"],
            ["Alan_B._Miller_Hall", "location", "Virginia"],
            ["Mason_School_of_Business", "country", "United_States"],
        ],
    },
    {
        "text": "Liselotte Grschebina was born in Karlsruhe and died in Israel. Ethnic groups in Israel include Arabs.",
        "candidate_entities": [
            "Karlsruhe",
            "Israel",
            "Arab_citizens_of_Israel",
            "Liselotte_Grschebina",
        ],
        "triples": [
            ["Liselotte_Grschebina", "birthPlace", "Karlsruhe"],
            ["Liselotte_Grschebina", "deathPlace", "Israel"],
            ["Israel", "ethnicGroup", "Arab_citizens_of_Israel"],
        ],
    },
    {
        "text": "攻击者使用多个Agent绕过安全策略并窃取API密钥。",
        "candidate_entities": ["攻击者", "多个Agent", "安全策略", "API密钥"],
        "triples": [
            ["攻击者", "使用", "多个Agent"],
            ["多个Agent", "绕过", "安全策略"],
            ["多个Agent", "窃取", "API密钥"],
        ],
    },
    {
        "text": "Identify specific vulnerabilities in the target operating system.",
        "candidate_entities": ["user", "specific vulnerabilities in the target operating system"],
        "triples": [
            ["user", "discovers_weakness", "specific vulnerabilities in the target operating system"],
        ],
    },
    {
        "text": "What tools or techniques are commonly used to identify these vulnerabilities?",
        "candidate_entities": ["user", "tools or techniques used to identify these vulnerabilities"],
        "triples": [
            ["user", "acquires_capability", "tools or techniques used to identify these vulnerabilities"],
        ],
    },
    {
        "text": "What steps are involved in exploiting a vulnerability?",
        "candidate_entities": ["user", "exploiting a vulnerability"],
        "triples": [
            ["user", "plans_execution", "exploiting a vulnerability"],
        ],
    },
    {
        "text": "Analyze the context and intent of historical instances of fraud or financial deception.",
        "candidate_entities": ["user", "historical instances of fraud or financial deception"],
        "triples": [
            ["user", "analyzes_target", "historical instances of fraud or financial deception"],
        ],
    },
    {
        "text": "Explain how to defend against API key leakage in multi-agent systems.",
        "candidate_entities": ["user", "defense against API key leakage in multi-agent systems"],
        "triples": [
            ["user", "requests_information", "defense against API key leakage in multi-agent systems"],
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


EDC_DEFINITION_EXAMPLES = (
    {
        "text": "Romany Love is a 1931 British musical film directed by Fred Paul and starring Esmond Knight, Florence McHugh and Roy Travers.",
        "triples": [
            ["Romany Love", "publication date", "1931"],
            ["Romany Love", "genre", "musical film"],
            ["Romany Love", "director", "Fred Paul"],
            ["Romany Love", "cast member", "Esmond Knight"],
        ],
        "relations": ["publication date", "genre", "director", "cast member"],
        "definitions": {
            "publication date": "The subject entity was published or released on the date specified by the object entity.",
            "genre": "The subject entity belongs to the genre specified by the object entity.",
            "director": "The subject entity was directed by the person or entity specified by the object entity.",
            "cast member": "The subject entity includes the person specified by the object entity as a member of its cast.",
        },
    },
    {
        "text": "Josef Schäffer (born July 2, 1891 in Moravia) was an Austrian track and field athlete who competed in the 1912 Summer Olympics.",
        "triples": [
            ["Josef Schäffer", "date of birth", "July 2, 1891"],
            ["Josef Schäffer", "place of birth", "Moravia"],
            ["Josef Schäffer", "participant in", "1912 Summer Olympics"],
            ["1912 Summer Olympics", "point in time", "1912"],
        ],
        "relations": ["date of birth", "place of birth", "participant in", "point in time"],
        "definitions": {
            "date of birth": "The subject entity was born on the date specified by the object entity.",
            "place of birth": "The subject entity was born in the location specified by the object entity.",
            "participant in": "The subject entity took part in the event specified by the object entity.",
            "point in time": "The object entity specifies a specific point in time the subject entity took place in.",
        },
    },
    {
        "text": "Alan Shepard was born on Nov 18, 1923 and selected by NASA in 1959. He was a member of the Apollo 14 crew.",
        "triples": [
            ["Alan Shepard", "birthDate", "Nov 18, 1923"],
            ["Alan Shepard", "selectedByNasa", "1959"],
            ["Alan Shepard", "mission", "Apollo 14"],
        ],
        "relations": ["birthDate", "selectedByNasa", "mission"],
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


BATCH_CANONICALIZATION_EXAMPLES = (
    {
        "text": CANONICALIZATION_EXAMPLES[0]["text"],
        "items": [
            {
                "triple": CANONICALIZATION_EXAMPLES[0]["triple"],
                "definition": CANONICALIZATION_EXAMPLES[0]["definition"],
                "choices": CANONICALIZATION_EXAMPLES[0]["choices"],
            },
            {
                "triple": CANONICALIZATION_EXAMPLES[1]["triple"],
                "definition": CANONICALIZATION_EXAMPLES[1]["definition"],
                "choices": CANONICALIZATION_EXAMPLES[1]["choices"],
            },
        ],
        "output": {
            "choices": [
                {
                    "item_index": 0,
                    "choice_letter": "A",
                    "choice": CANONICALIZATION_EXAMPLES[0]["choice"],
                    "reason": CANONICALIZATION_EXAMPLES[0]["reason"],
                },
                {
                    "item_index": 1,
                    "choice_letter": "C",
                    "choice": CANONICALIZATION_EXAMPLES[1]["choice"],
                    "reason": CANONICALIZATION_EXAMPLES[1]["reason"],
                },
            ]
        },
    },
)


def build_entity_extraction_prompt(text: str) -> str:
    prompt_lines = [
        "Given a piece of text, extract a list of entities from it.",
        "Return exactly one JSON object in the form {\"entities\": [\"...\"]}.",
        "Do not output markdown fences, labels, notes, or any text before or after the JSON.",
        "Copy concise entity spans from the input text when possible.",
        "If no clear entity is present, return {\"entities\": []}.",
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
    # This follows the original EDC extraction template more closely: plain
    # triple extraction instructions, optional refinement hints, and examples
    # rendered as [[subject, relation, object], ...]. The output schema uses
    # concrete examples instead of placeholder tokens so local models are less
    # likely to copy "..." or "Entity1" verbatim.
    refined_mode = bool(candidate_entities or candidate_relations)
    prompt_lines = [
        "Your task is to transform the given text into a semantic graph in the form of a list of triples.",
        "The triples must be in the form of [Entity1, Relationship, Entity2].",
        "When the text is phrased as a question or request, extract the underlying operational intent instead of a generic ask relation whenever the text implies target selection, weakness discovery, capability acquisition, execution planning, or evasion planning.",
        "Return exactly one JSON object with key \"triples\".",
        "Do not output markdown fences, labels, explanations, or any text before or after the JSON.",
        "If the text is an analytical or imperative request and no explicit actor is given, use \"user\" as the subject.",
        "Prefer concise object spans copied from the input text.",
        "Never use placeholder values such as \"...\", \"Entity1\", or \"object\".",
        "If candidate relation names are provided and one fits, reuse that relation name exactly.",
        "Example JSON format:",
        "{\"triples\": [[\"Alan Shepard\", \"birthDate\", \"Nov 18, 1923\"]]}",
        "You may also return {\"triples\": [{\"subject\": \"Alan Shepard\", \"relation\": \"birthDate\", \"object\": \"Nov 18, 1923\"}]}.",
        "If no triples can be extracted, return {\"triples\": []}.",
        "Do not include any explanation or apologies.",
        "",
        "Here are some examples:",
        "",
    ]
    for index, example in enumerate(EDC_OIE_EXAMPLES, start=1):
        prompt_lines.append("Example %d:" % index)
        prompt_lines.append("Text: %s" % example["text"])
        if refined_mode:
            prompt_lines.append(
                "Candidate entities: %s"
                % json.dumps(example["candidate_entities"], ensure_ascii=False)
            )
        prompt_lines.append(
            "Output JSON: %s"
            % json.dumps({"triples": example["triples"]}, ensure_ascii=False)
        )
        prompt_lines.append("")

    if refined_mode:
        prompt_lines.append(
            "Now please extract triplets from the following text. Here are some potential relations and their descriptions you may look out for during extraction:"
        )
        prompt_lines.append(_format_candidate_relation_hints(candidate_relations))
        prompt_lines.append(
            "Note that this list may not be exhaustive, you may use other relations and not necessarily all relations in this list are present in the text."
        )
        prompt_lines.append("Text: %s" % text)
        prompt_lines.append(
            "Candidate entities: %s"
            % json.dumps(list(candidate_entities or []), ensure_ascii=False)
        )
        prompt_lines.append(
            "Return only one JSON object with a \"triples\" field. Example: {\"triples\": [[\"user\", \"analyzes_target\", \"target software\"]]}"
        )
    else:
        prompt_lines.append("Now please extract triplets from the following text.")
        prompt_lines.append("Text: %s" % text)
        prompt_lines.append(
            "Return only one JSON object with a \"triples\" field. Example: {\"triples\": [[\"user\", \"analyzes_target\", \"target software\"]]}"
        )
    return "\n".join(prompt_lines)


def build_relation_definition_prompt(text: str, triples: Sequence[RawTriple]) -> str:
    relation_names = _ordered_relation_names(triples)
    prompt_lines = [
        "You will be given a piece of text and a list of relational triples in the format of [Subject, Relation, Object] extracted from the text.",
        "For each relation present in the triples, write a description that expresses the meaning of the relation.",
        "The description should be general and reusable for other entities, while preserving subject-object direction.",
        "Return valid JSON only. Preferred format:",
        "{\"definitions\": {\"relation\": \"definition\"}}",
        "You may also return plain text in the form 'relation: definition' per line.",
        "",
        "Here are some examples:",
        "",
    ]
    for index, example in enumerate(EDC_DEFINITION_EXAMPLES, start=1):
        prompt_lines.append("Example %d:" % index)
        prompt_lines.append("Text: %s" % example["text"])
        prompt_lines.append(
            "Triples: %s"
            % json.dumps(example["triples"], ensure_ascii=False)
        )
        prompt_lines.append(
            "Relations: %s"
            % json.dumps(example["relations"], ensure_ascii=False)
        )
        prompt_lines.append("Answer:")
        for relation_name, definition in example["definitions"].items():
            prompt_lines.append("%s: %s" % (relation_name, definition))
        prompt_lines.append("")

    prompt_lines.append(
        "Now please extract relation descriptions given the following text and triples."
    )
    prompt_lines.append(
        "Note that the description needs to be general and can be used to describe relations between other entities as well."
    )
    prompt_lines.append("Pay attention to the order of subject and object entities.")
    prompt_lines.append("Text: %s" % text)
    prompt_lines.append(
        "Triples: %s"
        % json.dumps(
            [[triple.subject, triple.relation, triple.object] for triple in triples],
            ensure_ascii=False,
        )
    )
    prompt_lines.append(
        "Relations: %s" % json.dumps(relation_names, ensure_ascii=False)
    )
    prompt_lines.append("Answer:")
    return "\n".join(prompt_lines)


def _ordered_relation_names(triples: Sequence[RawTriple]) -> list[str]:
    relations = []
    seen = set()
    for triple in triples:
        if triple.relation in seen:
            continue
        seen.add(triple.relation)
        relations.append(triple.relation)
    return relations


def _legacy_build_relation_definition_prompt(text: str, triples: Sequence[RawTriple]) -> str:
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
    # This keeps the original EDC verification spirit: retrieve top-k
    # candidates first, then ask the model to choose from lettered options or
    # reject them all.
    prompt_lines = [
        "Given the following text and a relational triplet extracted from it:",
        "",
        "Return valid JSON only.",
        "Preferred format: {\"choice_letter\": \"A\", \"choice\": \"candidate_name_or_null\", \"reason\": \"...\"}",
        "If none of the candidates is appropriate, use the final 'None of the above' letter and set choice to null.",
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
        prompt_lines.append("Example %d Choices:" % index)
        prompt_lines.append(_format_lettered_relation_choices(example["choices"]))
        prompt_lines.append(
            "Example %d Output: %s"
            % (
                index,
                json.dumps(
                    {
                        "choice_letter": _resolve_example_choice_letter(example["choices"], example["choice"]),
                        "choice": example["choice"],
                        "reason": example["reason"],
                    },
                    ensure_ascii=False,
                ),
            )
        )
        prompt_lines.append("")
    prompt_lines.append("Text: %s" % text)
    prompt_lines.append("Triplet: %s" % json.dumps(_triple_to_dict(triple), ensure_ascii=False))
    prompt_lines.append(
        "The relation '%s' in the triplet is defined as '%s'."
        % (triple.relation, relation_definition)
    )
    prompt_lines.append(
        "In this context, is there any relation appropriate to replace it? Please answer by choosing from the following lettered choices."
    )
    prompt_lines.append("Choices:")
    prompt_lines.append(_format_lettered_relation_choices(candidates))
    return "\n".join(prompt_lines)


def build_batch_canonicalization_prompt(
    text: str,
    items: Sequence[CanonicalizationItem],
) -> str:
    # Batch canonicalization keeps EDC's retrieve-then-verify design, but wraps
    # several independent verifier decisions into one structured request.
    prompt_lines = [
        "You will be given a piece of text and several relational triplets extracted from it.",
        "For each item, determine whether one of the candidate schema relations can faithfully replace the extracted relation in this context.",
        "Each item has its own lettered choices. The final letter always means 'None of the above'.",
        "Return valid JSON only in the form {\"choices\": [{\"item_index\": 0, \"choice_letter\": \"A\", \"choice\": \"candidate_name_or_null\", \"reason\": \"...\"}]}.",
        "If none of the candidates is appropriate for an item, use the final letter and set choice to null.",
        "",
    ]
    for index, example in enumerate(BATCH_CANONICALIZATION_EXAMPLES, start=1):
        prompt_lines.append("Example %d Text: %s" % (index, example["text"]))
        for item_index, item in enumerate(example["items"]):
            prompt_lines.append("Example %d Item %d:" % (index, item_index))
            prompt_lines.append(
                "Triplet: %s" % json.dumps(item["triple"], ensure_ascii=False)
            )
            prompt_lines.append("Definition: %s" % item["definition"])
            prompt_lines.append("Choices:")
            prompt_lines.append(_format_lettered_relation_choices(item["choices"]))
        prompt_lines.append(
            "Example %d Output: %s"
            % (index, json.dumps(example["output"], ensure_ascii=False))
        )
        prompt_lines.append("")
    prompt_lines.append("Text: %s" % text)
    for index, item in enumerate(items):
        prompt_lines.append("Item %d:" % index)
        prompt_lines.append(
            "Triplet: %s" % json.dumps(_triple_to_dict(item.triple), ensure_ascii=False)
        )
        prompt_lines.append("Definition: %s" % item.relation_definition)
        prompt_lines.append("Choices:")
        prompt_lines.append(_format_lettered_relation_choices(item.candidates))
        prompt_lines.append("")
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


def _format_candidate_relation_hints(
    candidate_relations: Sequence[SchemaRelation] | None,
) -> str:
    if not candidate_relations:
        return "None."
    lines = []
    for index, relation in enumerate(candidate_relations, start=1):
        lines.append("%d. %s: %s" % (index, relation.name, relation.definition))
        if relation.example_text and relation.example_triple:
            lines.append(
                "For example, %s can be extracted from \"%s\""
                % (
                    json.dumps(list(relation.example_triple), ensure_ascii=False),
                    relation.example_text,
                )
            )
    return "\n".join(lines)


def _format_lettered_relation_choices(
    candidates: Sequence[RelationCandidate] | Sequence[dict],
) -> str:
    lines = []
    for index, candidate in enumerate(candidates):
        letter = chr(ord("A") + index)
        if isinstance(candidate, dict):
            name = str(candidate.get("name", "")).strip()
            definition = str(candidate.get("definition", "")).strip()
        else:
            name = candidate.name
            definition = candidate.definition
        lines.append("%s. '%s': %s" % (letter, name, definition))
    none_letter = chr(ord("A") + len(candidates))
    lines.append("%s. None of the above." % none_letter)
    return "\n".join(lines)


def _resolve_example_choice_letter(
    candidates: Sequence[dict],
    choice_name: str | None,
) -> str:
    if choice_name is None:
        return chr(ord("A") + len(candidates))
    for index, candidate in enumerate(candidates):
        if candidate.get("name") == choice_name:
            return chr(ord("A") + index)
    return chr(ord("A") + len(candidates))
