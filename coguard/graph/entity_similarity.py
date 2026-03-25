from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, FrozenSet

from ..semantic.vectorizer import cosine_similarity, tokenize, vectorize


NORMALIZE_PATTERN = re.compile(r"[^0-9a-zA-Z\u4e00-\u9fff]+")
LEADING_ARTICLE_PATTERN = re.compile(r"^(?:the|a|an)\s+", flags=re.IGNORECASE)
TIME_PATTERN = re.compile(
    r"(\b\d{4}\b|\b\d{1,2}[:/-]\d{1,2}(?:[:/-]\d{2,4})?\b|年|月|日|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)",
    flags=re.IGNORECASE,
)
GENERIC_SUFFIXES = (
    "dataset",
    "database",
    "records",
    "record",
    "service",
    "system",
    "module",
    "platform",
    "report",
    "resource",
    "content",
    "document",
    "service",
    "数据集",
    "数据库",
    "记录",
    "系统",
    "模块",
    "平台",
    "报表",
    "资源",
    "内容",
    "文档",
    "文件",
)
TOKEN_STOPWORDS = {
    "service",
    "system",
    "module",
    "platform",
    "resource",
    "document",
    "content",
    "report",
    "dataset",
    "database",
    "records",
    "record",
    "系统",
    "模块",
    "平台",
    "资源",
    "文档",
    "内容",
    "报表",
    "文件",
    "数据",
    "信息",
    "记录",
}
ORG_KEYWORDS = {
    "inc",
    "corp",
    "company",
    "co",
    "university",
    "institute",
    "lab",
    "labs",
    "foundation",
    "agency",
    "org",
    "organization",
    "公司",
    "大学",
    "学院",
    "机构",
    "组织",
    "实验室",
    "协会",
}
TOOL_KEYWORDS = {
    "agent",
    "tool",
    "model",
    "service",
    "api",
    "sdk",
    "workflow",
    "pipeline",
    "script",
    "机器人",
    "工具",
    "模型",
    "服务",
    "接口",
    "脚本",
    "流程",
    "代理",
}
DATA_KEYWORDS = {
    "data",
    "dataset",
    "database",
    "table",
    "report",
    "document",
    "file",
    "record",
    "records",
    "日志",
    "数据",
    "数据集",
    "数据库",
    "报表",
    "文档",
    "文件",
    "记录",
    "日志",
    "知识库",
}
LOCATION_KEYWORDS = {
    "city",
    "country",
    "province",
    "state",
    "street",
    "road",
    "district",
    "park",
    "城",
    "市",
    "省",
    "区",
    "县",
    "路",
    "街",
    "园区",
}
GROUP_KEYWORDS = {
    "team",
    "crew",
    "group",
    "mission",
    "project",
    "department",
    "committee",
    "团队",
    "小组",
    "任务",
    "项目",
    "部门",
    "委员会",
}


@dataclass(frozen=True)
class EntityProfile:
    """Normalized entity view used for soft matching during context expansion."""

    name: str
    normalized: str
    compact: str
    core_normalized: str
    core_compact: str
    tokens: FrozenSet[str]
    vector: Dict[str, float]
    entity_type: str


def build_entity_profile(name: str) -> EntityProfile:
    # Profiles let us improve relatedness logic without changing persisted node
    # ids in either the in-memory or Neo4j backend.
    normalized = _normalize_text(name)
    compact = normalized.replace(" ", "")
    core_normalized = _strip_generic_suffixes(normalized)
    core_compact = core_normalized.replace(" ", "")
    token_source = "%s %s" % (normalized, core_normalized)
    tokens = frozenset(_entity_tokens(token_source))
    vector_source = core_normalized or normalized
    return EntityProfile(
        name=name,
        normalized=normalized,
        compact=compact,
        core_normalized=core_normalized,
        core_compact=core_compact,
        tokens=tokens,
        vector=vectorize(vector_source),
        entity_type=infer_entity_type(normalized),
    )


def entity_relatedness_score(left: EntityProfile, right: EntityProfile) -> float:
    # Medium-strength matching combines lexical overlap, vector similarity, and
    # type compatibility. It expands context without hard-merging entities.
    if not left.compact or not right.compact:
        return 0.0
    if left.compact == right.compact:
        return 1.0

    type_score = _type_compatibility_score(left.entity_type, right.entity_type)
    if type_score <= 0.0:
        return 0.0

    if _is_contained_alias(left, right):
        return 0.9 + 0.1 * type_score

    token_overlap = _overlap_score(left.tokens, right.tokens)
    vector_similarity = cosine_similarity(left.vector, right.vector)
    if max(token_overlap, vector_similarity) < 0.25:
        return 0.0

    return (
        0.45 * token_overlap
        + 0.35 * vector_similarity
        + 0.20 * type_score
    )


def infer_entity_type(normalized_name: str) -> str:
    # Types are coarse on purpose: they only suppress obviously bad matches.
    if not normalized_name:
        return "generic"
    if TIME_PATTERN.search(normalized_name):
        return "time"
    if _contains_keyword(normalized_name, LOCATION_KEYWORDS):
        return "location"
    if _contains_keyword(normalized_name, ORG_KEYWORDS):
        return "org"
    if _contains_keyword(normalized_name, TOOL_KEYWORDS):
        return "tool"
    if _contains_keyword(normalized_name, DATA_KEYWORDS):
        return "data"
    if _contains_keyword(normalized_name, GROUP_KEYWORDS):
        return "group"
    return "generic"


def _normalize_text(text: str) -> str:
    cleaned = LEADING_ARTICLE_PATTERN.sub("", text.strip())
    cleaned = cleaned.lower()
    cleaned = NORMALIZE_PATTERN.sub(" ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def _strip_generic_suffixes(text: str) -> str:
    result = text
    changed = True
    while changed and result:
        changed = False
        for suffix in GENERIC_SUFFIXES:
            if not result.endswith(suffix):
                continue
            candidate = result[: -len(suffix)].rstrip()
            if len(candidate.replace(" ", "")) < 2:
                continue
            result = candidate
            changed = True
            break
    return result or text


def _entity_tokens(text: str) -> list[str]:
    tokens = []
    for token in tokenize(text):
        normalized_token = token.strip().lower()
        if not normalized_token:
            continue
        if normalized_token in TOKEN_STOPWORDS:
            continue
        if len(normalized_token) <= 1 and not normalized_token.isdigit():
            continue
        tokens.append(normalized_token)
    return tokens


def _overlap_score(left: FrozenSet[str], right: FrozenSet[str]) -> float:
    if not left or not right:
        return 0.0
    intersection = len(left & right)
    if intersection == 0:
        return 0.0
    return intersection / float(min(len(left), len(right)))


def _type_compatibility_score(left_type: str, right_type: str) -> float:
    if left_type == right_type:
        return 1.0
    if "generic" in {left_type, right_type}:
        return 0.7
    compatible_pairs = {
        ("org", "group"),
        ("group", "org"),
        ("tool", "group"),
        ("group", "tool"),
    }
    if (left_type, right_type) in compatible_pairs:
        return 0.4
    return 0.0


def _is_contained_alias(left: EntityProfile, right: EntityProfile) -> bool:
    left_core = left.core_compact
    right_core = right.core_compact
    minimum = min(len(left_core), len(right_core))
    if minimum < 3:
        return False
    return left_core in right_core or right_core in left_core


def _contains_keyword(text: str, keywords: set[str]) -> bool:
    compact = text.replace(" ", "")
    tokens = set(text.split()) | set(_entity_tokens(text))
    return any(keyword in compact or keyword in tokens for keyword in keywords)
