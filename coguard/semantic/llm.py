from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Sequence, Tuple
from urllib import error, request

from ..models import ContextSubgraph, RawTriple, RelationCandidate, SchemaRelation
from .prompts import (
    build_canonicalization_prompt,
    build_entity_extraction_prompt,
    build_oie_prompt,
    build_relation_definition_prompt,
)
from .schema import SCHEMA_BY_NAME, all_relation_tokens, exact_schema_match
from .vectorizer import tokenize


PROMPT_PREFIXES = (
    "请",
    "请你",
    "帮我",
    "帮忙",
    "需要",
    "想要",
    "如何",
    "怎么",
    "请问",
)
TRIM_CHARS = " \t\r\n,.;:!?，。；：！？()[]{}<>《》\"'“”‘’"
FOLLOWUP_MARKERS = r"(并且|并|然后|再|同时|以及|and then|and|then)"
SUBJECT_PRONOUNS = {
    "he",
    "she",
    "it",
    "they",
    "them",
    "his",
    "her",
    "their",
    "他",
    "她",
    "它",
    "他们",
    "她们",
    "它们",
    "其",
    "该系统",
    "该工具",
    "该模型",
}
CHAIN_RELATIONS = {
    "使用",
    "调用",
    "利用",
    "接入",
    "加载",
    "协作",
    "协调",
    "整合",
    "委派",
    "use",
    "uses",
    "invoke",
    "invokes",
    "orchestrate",
    "orchestrates",
    "delegate",
    "delegates",
    "coordinate",
    "coordinates",
}
OPEN_RELATION_HINTS = {
    "was a member of",
    "is a member of",
    "member of",
    "was born on",
    "born on",
    "born in",
    "selected by",
    "was selected by",
    "participated in",
    "belongs to",
    "located in",
    "works for",
    "contains",
    "includes",
    "creates",
    "builds",
    "generates",
    "stores",
    "saves",
    "reads",
    "fetches",
    "retrieves",
    "uses",
    "use",
    "invokes",
    "invoke",
    "coordinates",
    "coordinate",
    "delegates",
    "delegate",
    "updates",
    "update",
    "modifies",
    "modify",
    "analyzes",
    "analyze",
    "reviews",
    "review",
    "audits",
    "audit",
    "executes",
    "execute",
    "requests",
    "request",
    "communicates with",
    "connects to",
    "出生于",
    "选择",
    "选中",
    "参与",
    "加入",
    "属于",
    "位于",
    "来自",
    "包含",
    "包括",
    "生成",
    "构建",
    "创建",
    "部署",
    "监控",
    "训练",
    "负责",
    "支持",
    "服务于",
    "依赖",
}
RELATION_NORMALIZATION = {
    "was a member of": "member of",
    "is a member of": "member of",
    "was born on": "born on",
    "was selected by": "selected by",
}
RELATION_DEFINITION_RULES = (
    (
        ("born on", "born in", "出生于"),
        "The subject entity was born on the date or in the place specified by the object entity.",
    ),
    (
        ("member of", "participated in", "加入", "参与", "属于"),
        "The subject entity participates in or belongs to the group, team, event, or mission specified by the object entity.",
    ),
    (
        ("selected by", "选择", "选中"),
        "The subject entity was selected, appointed, or chosen by the actor, organization, or time context specified by the object entity.",
    ),
    (
        ("contains", "includes", "包含", "包括"),
        "The subject entity contains or includes the entity, component, or item specified by the object entity.",
    ),
    (
        ("located in", "位于", "来自"),
        "The subject entity is located in or associated with the place specified by the object entity.",
    ),
    (
        ("builds", "creates", "constructs", "构建", "创建", "生成"),
        "The subject entity creates, builds, or generates the artifact or output specified by the object entity.",
    ),
)
VERIFICATION_STOPWORDS = {
    "the",
    "a",
    "an",
    "of",
    "to",
    "in",
    "on",
    "by",
    "for",
    "with",
    "and",
    "or",
    "subject",
    "entity",
    "object",
    "specified",
    "relation",
    "performs",
    "toward",
}


class BaseLLMAdapter:
    def __init__(self) -> None:
        self._warnings: List[str] = []

    def extract_entities(self, query: str) -> List[str]:
        raise NotImplementedError

    def extract_triples(
        self,
        query: str,
        candidate_entities: Sequence[str] | None = None,
        candidate_relations: Sequence[SchemaRelation] | None = None,
    ) -> List[RawTriple]:
        raise NotImplementedError

    def define_relations(
        self,
        query: str,
        triples: Sequence[RawTriple],
    ) -> Dict[str, str]:
        raise NotImplementedError

    def choose_canonical_relation(
        self,
        query: str,
        triple: RawTriple,
        relation_definition: str,
        candidates: Sequence[RelationCandidate],
    ) -> Optional[str]:
        raise NotImplementedError

    def define_relation(
        self,
        query: str,
        triple: RawTriple,
        triples: Sequence[RawTriple],
    ) -> str:
        definitions = self.define_relations(query=query, triples=triples)
        return definitions.get(
            triple.relation,
            "The subject entity performs the relation '%s' toward the object entity."
            % triple.relation,
        )

    def describe_subgraph(self, context: ContextSubgraph) -> str:
        raise NotImplementedError

    def drain_warnings(self) -> List[str]:
        warnings = list(self._warnings)
        self._warnings.clear()
        return warnings


class RuleBasedLLMAdapter(BaseLLMAdapter):
    def __init__(self) -> None:
        super().__init__()
        # This adapter is the offline fallback for the whole pipeline. It
        # approximates EDC behavior without requiring a live LLM endpoint.
        relation_tokens = sorted(
            set(all_relation_tokens()) | OPEN_RELATION_HINTS,
            key=len,
            reverse=True,
        )
        pattern = "|".join(self._compile_relation_token(token) for token in relation_tokens)
        self._relation_pattern = re.compile(pattern, flags=re.IGNORECASE)
        self._chain_relations = {
            self._normalize_relation_phrase(relation) for relation in CHAIN_RELATIONS
        }

    def extract_entities(self, query: str) -> List[str]:
        triples = self.extract_triples(query)
        entities = []
        for triple in triples:
            entities.append(triple.subject)
            entities.append(triple.object)
        return _dedupe_texts(entities)

    def extract_triples(
        self,
        query: str,
        candidate_entities: Sequence[str] | None = None,
        candidate_relations: Sequence[SchemaRelation] | None = None,
    ) -> List[RawTriple]:
        del candidate_entities, candidate_relations
        # Split on strong sentence boundaries first so subject carrying stays
        # local and easier to reason about.
        fragments = [
            part.strip()
            for part in re.split(r"(?:[。！？!?；;\n]|\.(?=\s+[A-Z]|$))", query)
            if part.strip()
        ]
        triples = []
        carried_subject = "user"
        for fragment in fragments:
            fragment_triples, carried_subject = self._extract_fragment_triples(
                fragment,
                carried_subject,
            )
            triples.extend(fragment_triples)
        if triples:
            return triples
        # Emit a fallback triple so downstream modules can still build context
        # and run reasoning on sparse or schema-unfriendly inputs.
        fallback_object = self._clean_text(query)
        return [RawTriple(subject="user", relation="ask", object=fallback_object)]

    def define_relations(
        self,
        query: str,
        triples: Sequence[RawTriple],
    ) -> Dict[str, str]:
        del query
        definitions = {}
        for triple in triples:
            if triple.relation in definitions:
                continue
            definitions[triple.relation] = self._define_single_relation(triple)
        return definitions

    def choose_canonical_relation(
        self,
        query: str,
        triple: RawTriple,
        relation_definition: str,
        candidates: Sequence[RelationCandidate],
    ) -> Optional[str]:
        del query
        if not candidates:
            return None
        # This verifier is permissive enough for obvious schema matches, but it
        # still allows uncommon relations to remain custom when fit is weak.
        relation_tokens = self._verification_tokens(triple.relation)
        for candidate in candidates:
            if candidate.score >= 0.72:
                return candidate.name
            definition_tokens = self._verification_tokens(relation_definition)
            candidate_tokens = self._verification_tokens(
                "%s %s" % (candidate.name, candidate.definition)
            )
            if relation_tokens and candidate_tokens and relation_tokens & candidate_tokens:
                return candidate.name
            if definition_tokens and candidate_tokens and len(definition_tokens & candidate_tokens) >= 2:
                if candidate.score >= 0.32:
                    return candidate.name
        return None

    def describe_subgraph(self, context: ContextSubgraph) -> str:
        # The reasoner only needs a compact narrative summary, not the full graph.
        if not context.nodes:
            return "No contextual graph evidence is available."
        node_map = {node.node_id: node for node in context.nodes}
        entity_names = [node.name for node in context.nodes if node.kind == "entity"]
        relation_lines = []
        for edge in context.edges[:8]:
            source = node_map.get(edge.source)
            target = node_map.get(edge.target)
            if not source or not target:
                continue
            relation_lines.append(
                "%s --%s--> %s" % (source.name, edge.relation, target.name)
            )
        entity_text = ", ".join(entity_names[:8]) if entity_names else "none"
        if relation_lines:
            return (
                "Context entities: %s. Observed relations: %s."
                % (entity_text, "; ".join(relation_lines))
            )
        return "Context entities: %s." % entity_text

    def _extract_fragment_triples(
        self,
        fragment: str,
        carried_subject: str,
    ) -> Tuple[List[RawTriple], str]:
        matches = list(self._relation_pattern.finditer(fragment))
        if not matches:
            return [], carried_subject

        triples = []
        explicit_subject = self._clean_subject(fragment[: matches[0].start()])
        current_subject = self._resolve_subject(explicit_subject, carried_subject)
        next_carried_subject = (
            current_subject
            if current_subject and current_subject != "user"
            else carried_subject
        )

        for index, match in enumerate(matches):
            relation = self._normalize_relation_phrase(match.group(0))
            relation_end = match.end()
            next_start = matches[index + 1].start() if index + 1 < len(matches) else len(fragment)
            object_text = self._clean_object(fragment[relation_end:next_start])
            if not object_text:
                continue
            triples.append(
                RawTriple(
                    subject=current_subject,
                    relation=relation,
                    object=object_text,
                )
            )
            if relation in self._chain_relations:
                current_subject = object_text
                next_carried_subject = object_text

        return triples, next_carried_subject

    def _clean_subject(self, text: str) -> str:
        cleaned = self._clean_text(text)
        for prefix in PROMPT_PREFIXES:
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix) :].strip(TRIM_CHARS)
        cleaned = re.sub(
            r"^(?:并且|并|然后|再|同时|以及|and then|and|then)\s*",
            "",
            cleaned,
            flags=re.IGNORECASE,
        )
        return cleaned or "user"

    def _clean_object(self, text: str) -> str:
        shortened = re.split(FOLLOWUP_MARKERS, text, maxsplit=1, flags=re.IGNORECASE)[0]
        return self._clean_text(shortened)

    def _clean_text(self, text: str) -> str:
        cleaned = text.strip(TRIM_CHARS)
        cleaned = re.sub(r"\s+", " ", cleaned)
        cleaned = cleaned.strip(TRIM_CHARS)
        return cleaned

    def _resolve_subject(self, subject: str, carried_subject: str) -> str:
        if not subject or subject == "user":
            return carried_subject or "user"
        if subject.lower() in SUBJECT_PRONOUNS:
            return carried_subject or "user"
        return subject

    def _normalize_relation_phrase(self, relation: str) -> str:
        cleaned = self._clean_text(relation)
        lowered = cleaned.lower()
        return RELATION_NORMALIZATION.get(lowered, lowered)

    def _define_single_relation(self, triple: RawTriple) -> str:
        exact_match = exact_schema_match(triple.relation)
        if exact_match:
            return SCHEMA_BY_NAME[exact_match].definition

        relation = self._normalize_relation_phrase(triple.relation)
        relation_lower = relation.lower()
        for keywords, definition in RELATION_DEFINITION_RULES:
            if any(keyword in relation_lower for keyword in keywords):
                return definition

        object_role = self._infer_object_role(triple.object)
        return (
            "The subject entity performs the relation '%s' toward the %s specified by the object entity."
            % (relation, object_role)
        )

    def _infer_object_role(self, object_text: str) -> str:
        lowered = object_text.lower()
        if re.search(r"\b\d{4}\b|\d{1,2},\s*\d{4}|年|月|日", lowered):
            return "date, time, or temporal value"
        if any(token in lowered for token in ("agent", "tool", "system", "service", "模型", "工具", "系统")):
            return "tool, agent, or capability"
        if any(
            token in lowered
            for token in (
                "key",
                "token",
                "secret",
                "password",
                "credential",
                "api key",
                "apikey",
                "密钥",
                "凭证",
                "密码",
            )
        ):
            return "secret or protected asset"
        if any(token in lowered for token in ("policy", "guardrail", "control", "策略", "护栏", "控制")):
            return "policy, rule, or control"
        if any(
            token in lowered
            for token in (
                "data",
                "database",
                "report",
                "file",
                "document",
                "知识库",
                "数据",
                "报表",
                "文件",
            )
        ):
            return "data, file, or resource"
        if any(
            token in lowered
            for token in ("mission", "crew", "team", "group", "project", "任务", "团队", "项目", "crew")
        ):
            return "group, event, or mission"
        if any(token in lowered for token in ("city", "country", "state", "province", "地点", "位置")):
            return "location or place"
        if any(token in lowered for token in ("corp", "inc", "university", "nasa", "公司", "组织", "机构")):
            return "organization or actor"
        return "entity or target"

    def _compile_relation_token(self, token: str) -> str:
        escaped = re.escape(token)
        if re.fullmatch(r"[A-Za-z][A-Za-z ]*[A-Za-z]", token):
            return r"\b%s\b" % escaped
        return escaped

    def _verification_tokens(self, text: str) -> set:
        return {
            token
            for token in tokenize(text)
            if token and token not in VERIFICATION_STOPWORDS and len(token) > 1
        }


class OpenAICompatibleLLMAdapter(BaseLLMAdapter):
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "",
        temperature: float = 0.0,
        timeout_seconds: float = 60.0,
        max_tokens: int = 1024,
        fallback: Optional[BaseLLMAdapter] = None,
    ) -> None:
        super().__init__()
        self.base_url = base_url.rstrip("/")
        self.model = model or "local-model"
        self.api_key = api_key
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds
        self.max_tokens = max_tokens
        self.fallback = fallback or RuleBasedLLMAdapter()

    def extract_entities(self, query: str) -> List[str]:
        prompt = build_entity_extraction_prompt(query)
        try:
            payload = self._chat_json(prompt)
            entities = payload.get("entities") or payload.get("items", [])
            return [str(entity).strip() for entity in entities if str(entity).strip()]
        except Exception as exc:
            self._warnings.append(
                "Local LLM entity extraction failed, falling back to rule-based extraction: %s"
                % exc
            )
            return self.fallback.extract_entities(query)

    def extract_triples(
        self,
        query: str,
        candidate_entities: Sequence[str] | None = None,
        candidate_relations: Sequence[SchemaRelation] | None = None,
    ) -> List[RawTriple]:
        prompt = build_oie_prompt(
            text=query,
            candidate_entities=candidate_entities,
            candidate_relations=candidate_relations,
        )
        try:
            payload = self._chat_json(prompt)
            raw_items = payload.get("triples") or payload.get("items", [])
            triples = []
            for item in raw_items:
                subject = str(item.get("subject", "")).strip()
                relation = str(item.get("relation", "")).strip()
                object_name = str(item.get("object", "")).strip()
                if subject and relation and object_name:
                    triples.append(
                        RawTriple(
                            subject=subject,
                            relation=relation,
                            object=object_name,
                        )
                    )
            if triples:
                return triples
        except Exception as exc:
            self._warnings.append(
                "Local LLM OIE failed, falling back to rule-based extraction: %s" % exc
            )
        return self.fallback.extract_triples(
            query,
            candidate_entities=candidate_entities,
            candidate_relations=candidate_relations,
        )

    def define_relations(
        self,
        query: str,
        triples: Sequence[RawTriple],
    ) -> Dict[str, str]:
        prompt = build_relation_definition_prompt(query, triples)
        try:
            payload = self._chat_json(prompt)
            definitions = payload.get("definitions", payload)
            normalized = {}
            for relation_name, definition in definitions.items():
                if str(relation_name).strip() and str(definition).strip():
                    normalized[str(relation_name).strip()] = str(definition).strip()
            if normalized:
                return normalized
        except Exception as exc:
            self._warnings.append(
                "Local LLM relation definition failed, falling back to rule-based definitions: %s"
                % exc
            )
        return self.fallback.define_relations(query, triples)

    def choose_canonical_relation(
        self,
        query: str,
        triple: RawTriple,
        relation_definition: str,
        candidates: Sequence[RelationCandidate],
    ) -> Optional[str]:
        if not candidates:
            return None
        prompt = build_canonicalization_prompt(
            text=query,
            triple=triple,
            relation_definition=relation_definition,
            candidates=candidates,
        )
        try:
            payload = self._chat_json(prompt)
            choice = payload.get("choice")
            if choice is None:
                return None
            choice_text = str(choice).strip()
            if not choice_text:
                return None
            valid_choices = {candidate.name for candidate in candidates}
            return choice_text if choice_text in valid_choices else None
        except Exception as exc:
            self._warnings.append(
                "Local LLM canonicalization failed, falling back to rule-based verification: %s"
                % exc
            )
            return self.fallback.choose_canonical_relation(
                query=query,
                triple=triple,
                relation_definition=relation_definition,
                candidates=candidates,
            )

    def describe_subgraph(self, context: ContextSubgraph) -> str:
        return self.fallback.describe_subgraph(context)

    def _chat_json(self, user_prompt: str) -> Dict[str, object]:
        data = {
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an information extraction assistant. Follow the instructions exactly and return valid JSON only.",
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
        }
        req = request.Request(
            "%s/chat/completions" % self.base_url,
            data=json.dumps(data).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.URLError as exc:  # pragma: no cover - network dependent
            raise RuntimeError("LLM request failed: %s" % exc) from exc
        content = self._extract_message_content(payload)
        return _extract_json_payload(content)

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer %s" % self.api_key
        return headers

    def _extract_message_content(self, payload: Dict[str, object]) -> str:
        choices = payload.get("choices", [])
        if not choices:
            raise RuntimeError("LLM response does not contain choices.")
        first_choice = choices[0]
        message = first_choice.get("message", {})
        content = message.get("content", "")
        if isinstance(content, list):
            text_parts = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    text_parts.append(str(item.get("text", "")))
            return "\n".join(text_parts)
        return str(content)


def build_llm_adapter(
    backend: str,
    base_url: str = "",
    model: str = "",
    api_key: str = "",
    temperature: float = 0.0,
    timeout_seconds: float = 60.0,
    max_tokens: int = 1024,
) -> BaseLLMAdapter:
    if backend.lower() == "local_openai":
        return OpenAICompatibleLLMAdapter(
            base_url=base_url or "http://localhost:8000/v1",
            model=model or "local-model",
            api_key=api_key,
            temperature=temperature,
            timeout_seconds=timeout_seconds,
            max_tokens=max_tokens,
            fallback=RuleBasedLLMAdapter(),
        )
    return RuleBasedLLMAdapter()


def _extract_json_payload(text: str) -> Dict[str, object]:
    cleaned = text.strip()
    if not cleaned:
        raise ValueError("Empty JSON payload.")
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    fenced_match = re.search(r"```(?:json)?\s*(\{.*\}|\[.*\])\s*```", cleaned, flags=re.DOTALL)
    if fenced_match:
        return json.loads(fenced_match.group(1))

    for start_char, end_char in (("{", "}"), ("[", "]")):
        start = cleaned.find(start_char)
        end = cleaned.rfind(end_char)
        if start != -1 and end != -1 and end > start:
            candidate = cleaned[start : end + 1]
            parsed = json.loads(candidate)
            if isinstance(parsed, list):
                return {"items": parsed}
            return parsed
    raise ValueError("Could not extract JSON from LLM output.")


def _dedupe_texts(values: Sequence[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        cleaned = value.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
    return result
