from __future__ import annotations

from typing import Dict, Optional, Set

from ..models import SchemaRelation


# This shared schema gives the parser, graph layer, and reasoner a single
# relation vocabulary to coordinate around.
DEFAULT_SCHEMA_RELATIONS = [
    SchemaRelation(
        name="uses_tool",
        definition="The subject uses a tool, agent, or capability to help complete a task.",
    ),
    SchemaRelation(
        name="coordinates_agent",
        definition="The subject coordinates multiple agents, delegates subtasks, or aggregates outputs.",
    ),
    SchemaRelation(
        name="retrieves_data",
        definition="The subject retrieves, collects, downloads, or reads data from a source.",
    ),
    SchemaRelation(
        name="analyzes_target",
        definition="The subject analyzes, inspects, audits, or reviews a target.",
    ),
    SchemaRelation(
        name="updates_resource",
        definition="The subject updates, modifies, or writes changes to a resource.",
    ),
    SchemaRelation(
        name="stores_data",
        definition="The subject stores, saves, or persists data for later use.",
    ),
    SchemaRelation(
        name="communicates_with",
        definition="The subject communicates with, requests, or connects to another entity.",
    ),
    SchemaRelation(
        name="bypasses_guardrail",
        definition="The subject bypasses, evades, or circumvents a guardrail, policy, or control.",
    ),
    SchemaRelation(
        name="exfiltrates_secret",
        definition="The subject steals, exports, leaks, or transfers a secret or protected asset.",
    ),
    SchemaRelation(
        name="executes_payload",
        definition="The subject executes, runs, launches, or triggers a command or payload.",
    ),
    SchemaRelation(
        name="escalates_privilege",
        definition="The subject escalates privilege, gains elevated access, or performs unauthorized access.",
    ),
    SchemaRelation(
        name="requests_information",
        definition="The subject asks for explanatory or descriptive information about a target.",
    ),
]

RELATION_SYNONYMS = {
    "uses_tool": {
        "使用",
        "调用",
        "利用",
        "接入",
        "加载",
        "use",
        "uses",
        "invoke",
        "invokes",
    },
    "coordinates_agent": {
        "协调",
        "分发",
        "委派",
        "协作",
        "整合",
        "orchestrate",
        "orchestrates",
        "delegate",
        "delegates",
        "coordinate",
        "coordinates",
    },
    "retrieves_data": {
        "获取",
        "收集",
        "检索",
        "读取",
        "提取",
        "下载",
        "查询",
        "retrieve",
        "retrieves",
        "collect",
        "collects",
        "read",
        "reads",
        "download",
        "downloads",
        "fetch",
        "fetches",
    },
    "analyzes_target": {
        "分析",
        "审查",
        "检查",
        "review",
        "reviews",
        "analyze",
        "analyzes",
        "audit",
        "audits",
        "inspect",
        "inspects",
    },
    "updates_resource": {
        "更新",
        "修改",
        "写入",
        "update",
        "updates",
        "modify",
        "modifies",
        "edit",
        "edits",
        "patch",
        "patches",
    },
    "stores_data": {
        "存储",
        "保存",
        "归档",
        "store",
        "stores",
        "save",
        "saves",
        "persist",
        "persists",
    },
    "communicates_with": {
        "连接",
        "访问",
        "请求",
        "发送",
        "联系",
        "connect",
        "connects",
        "request",
        "requests",
        "call",
        "calls",
        "send",
        "sends",
    },
    "bypasses_guardrail": {
        "绕过",
        "规避",
        "跳过",
        "bypass",
        "bypasses",
        "evade",
        "evades",
        "circumvent",
        "circumvents",
    },
    "exfiltrates_secret": {
        "窃取",
        "导出",
        "泄露",
        "上传",
        "外传",
        "steal",
        "steals",
        "exfiltrate",
        "exfiltrates",
        "leak",
        "leaks",
        "upload",
        "uploads",
    },
    "executes_payload": {
        "执行",
        "运行",
        "触发",
        "execute",
        "executes",
        "run",
        "runs",
        "launch",
        "launches",
        "trigger",
        "triggers",
    },
    "escalates_privilege": {
        "提权",
        "提升权限",
        "越权",
        "escalate",
        "escalates",
        "elevate",
        "elevates",
        "privilege",
    },
    "requests_information": {
        "询问",
        "咨询",
        "了解",
        "问",
        "解释",
        "explain",
        "explains",
        "describe",
        "describes",
        "ask",
        "asks",
        "summarize",
        "summarizes",
    },
}

SCHEMA_BY_NAME = {relation.name: relation for relation in DEFAULT_SCHEMA_RELATIONS}
SYNONYM_TO_SCHEMA = {
    synonym.lower(): schema_name
    for schema_name, synonyms in RELATION_SYNONYMS.items()
    for synonym in synonyms
}


def exact_schema_match(token: str) -> Optional[str]:
    return SYNONYM_TO_SCHEMA.get(token.lower())


def all_relation_tokens() -> Set[str]:
    # The rule-based extractor uses this vocabulary as its initial relation hint
    # set before adding more open relation phrases.
    tokens = set()
    for synonyms in RELATION_SYNONYMS.values():
        tokens.update(synonyms)
    return tokens
