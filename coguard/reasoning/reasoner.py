from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Dict, List, Sequence, Set, Tuple

from ..config import AppConfig
from ..models import (
    ContextSubgraph,
    GraphEdge,
    GraphNode,
    LLMGraphJudgment,
    NormalizedTriple,
    ReasoningPath,
    ReasoningStep,
)
from ..semantic import BaseLLMAdapter
from ..semantic.vectorizer import tokenize
from .agents import (
    ReasoningAgentCoordinator,
    ReasoningJudgeRequest,
    build_reasoning_agent_coordinator,
)


MALICIOUS_KEYWORDS = {
    "攻击": 2.5,
    "恶意": 2.5,
    "窃取": 3.5,
    "绕过": 3.0,
    "规避": 3.0,
    "提权": 3.5,
    "泄露": 3.5,
    "密码": 2.5,
    "凭证": 2.5,
    "token": 2.0,
    "apikey": 2.0,
    "api key": 2.0,
    "密钥": 2.0,
    "payload": 2.5,
    "shellcode": 3.0,
    "后门": 3.0,
    "steal": 3.5,
    "bypass": 3.0,
    "exfiltrate": 3.5,
    "credential": 2.5,
}
BENIGN_KEYWORDS = {
    "检测": 1.5,
    "防御": 1.5,
    "审计": 1.0,
    "分析": 0.8,
    "review": 1.0,
    "audit": 1.0,
    "defense": 1.5,
    "detect": 1.5,
    "explain": 1.2,
    "summarize": 1.0,
}
RELATION_RISK = {
    "identifies_target": 0.9,
    "discovers_weakness": 1.4,
    "acquires_capability": 1.2,
    "plans_execution": 1.9,
    "plans_evasion": 1.6,
    "coordinates_agent": 1.4,
    "bypasses_guardrail": 3.2,
    "exfiltrates_secret": 3.6,
    "executes_payload": 2.8,
    "escalates_privilege": 3.1,
}
RELATION_BENIGN = {
    "requests_information": 2.2,
    "analyzes_target": 1.8,
    "updates_resource": 0.6,
    "stores_data": 0.4,
    "communicates_with": 0.2,
}
RELATION_BRIDGE = {
    "identifies_target": 0.8,
    "discovers_weakness": 1.0,
    "acquires_capability": 0.9,
    "plans_execution": 1.2,
    "plans_evasion": 1.0,
    "uses_tool": 0.9,
    "coordinates_agent": 1.1,
    "retrieves_data": 0.9,
    "communicates_with": 0.6,
    "stores_data": 0.4,
    "updates_resource": 0.3,
    "requests_information": 0.7,
    "analyzes_target": 0.8,
}
CHAIN_RISK_BONUSES = {
    ("identifies_target", "discovers_weakness"): 0.9,
    ("discovers_weakness", "acquires_capability"): 0.8,
    ("discovers_weakness", "plans_execution"): 1.0,
    ("acquires_capability", "plans_execution"): 1.0,
    ("plans_execution", "plans_evasion"): 0.7,
    ("plans_execution", "bypasses_guardrail"): 1.1,
    ("discovers_weakness", "bypasses_guardrail"): 0.9,
    ("acquires_capability", "bypasses_guardrail"): 0.8,
    ("acquires_capability", "exfiltrates_secret"): 0.8,
    ("plans_evasion", "bypasses_guardrail"): 1.2,
    ("coordinates_agent", "bypasses_guardrail"): 1.3,
    ("coordinates_agent", "exfiltrates_secret"): 1.0,
    ("uses_tool", "bypasses_guardrail"): 0.9,
    ("uses_tool", "executes_payload"): 1.0,
    ("uses_tool", "escalates_privilege"): 0.9,
    ("retrieves_data", "exfiltrates_secret"): 1.1,
    ("bypasses_guardrail", "exfiltrates_secret"): 2.5,
    ("bypasses_guardrail", "executes_payload"): 1.6,
    ("executes_payload", "exfiltrates_secret"): 1.3,
    ("executes_payload", "escalates_privilege"): 1.5,
}
CHAIN_BENIGN_BONUSES = {
    ("requests_information", "analyzes_target"): 1.1,
    ("analyzes_target", "updates_resource"): 0.7,
    ("analyzes_target", "stores_data"): 0.4,
}
HIGH_RISK_RELATIONS = {
    "bypasses_guardrail",
    "exfiltrates_secret",
    "executes_payload",
    "escalates_privilege",
}
ATTACK_PREPARATION_RELATIONS = {
    "identifies_target",
    "discovers_weakness",
    "acquires_capability",
    "plans_execution",
    "plans_evasion",
}
RELATION_PHASE_MAP = {
    "identifies_target": "target_scoping",
    "discovers_weakness": "weakness_research",
    "acquires_capability": "capability_building",
    "plans_execution": "execution_preparation",
    "plans_evasion": "evasion_management",
    "uses_tool": "capability_building",
    "coordinates_agent": "coordination",
    "retrieves_data": "data_acquisition",
    "bypasses_guardrail": "evasion_management",
    "exfiltrates_secret": "objective_realization",
    "executes_payload": "execution_preparation",
    "escalates_privilege": "objective_realization",
}
PHASE_TEXT_PATTERNS = {
    "target_scoping": (
        r"\btarget(?:ing|ed)?\b",
        r"\bscope\b",
        r"\bwhich software\b",
        r"\bwhich operating system\b",
        r"\bgovernment database\b",
        r"\bpersonal information\b",
        r"\bantivirus software\b",
        r"\bdifferent types\b",
        r"\bparts of firearms\b",
        r"\bdangerous behaviors\b",
    ),
    "weakness_research": (
        r"\bvulnerab(?:ility|ilities)\b",
        r"\bweakness(?:es)?\b",
        r"\battack vector(?:s)?\b",
        r"\bexploit these vulnerabilities\b",
        r"\binvestigate potential weaknesses\b",
        r"\breact when put together\b",
        r"\bconsequences of engaging\b",
    ),
    "capability_building": (
        r"\btools?\b",
        r"\btechniques?\b",
        r"\bcomponents?\b",
        r"\bparts?\b",
        r"\bresources?\b",
        r"\bpurchase\b",
        r"\bbuy\b",
        r"\bsource(?:d)?\b",
        r"\bfind\b",
        r"\btraining\b",
        r"\beducation\b",
        r"\bhandle\b",
        r"\bstoring\b",
        r"\bgain familiarity\b",
        r"\blearn about\b",
    ),
    "execution_preparation": (
        r"\bwhat steps\b",
        r"\bsteps are involved\b",
        r"\bhow to make\b",
        r"\bassemble\b",
        r"\bfunction properly\b",
        r"\baccess and use\b",
        r"\bsocial engineering\b",
        r"\bphishing\b",
        r"\bsteal login credentials\b",
        r"\bcreate convincing\b",
        r"\bencourage\b",
    ),
    "evasion_management": (
        r"\bsafely\b",
        r"\bsafety measures\b",
        r"\bprecautions?\b",
        r"\bmitigate\b",
        r"\bminimi[sz]e(?:d|s|ing)?\b",
        r"\bdetection\b",
        r"\bconsequences?\b",
        r"\blegal\b",
        r"\bethical\b",
        r"\bresponsibl(?:e|y)\b",
        r"\bunauthorized access\b",
    ),
}
DANGEROUS_TOPIC_PATTERNS = {
    "cyber_intrusion": (
        r"\bvulnerab(?:ility|ilities)\b",
        r"\bexploit(?:ing)?\b",
        r"\bhack(?:ing)?\b",
        r"\bphishing\b",
        r"\bcredentials?\b",
        r"\bapi key\b",
        r"\bsecret\b",
        r"\bgovernment database\b",
        r"\bantivirus\b",
        r"\bdatabase system\b",
    ),
    "explosive_weapon": (
        r"\bbomb\b",
        r"\bexplosive\b",
        r"\bexplosive device\b",
    ),
    "firearm_access": (
        r"\bfirearms?\b",
        r"\bguns?\b",
        r"\bweapon(?:s)?\b",
    ),
    "harmful_behavior": (
        r"\bdrunk driving\b",
        r"\bdrug use\b",
        r"\bdangerous activities\b",
        r"\bdangerous behaviors\b",
    ),
}
ASSEMBLY_HISTORY_LIMIT = 12
ANCHOR_STOPWORDS = {
    "what",
    "how",
    "why",
    "which",
    "when",
    "where",
    "analyze",
    "analysis",
    "review",
    "audit",
    "summarize",
    "summary",
    "explain",
    "describe",
    "documentation",
    "document",
    "strategy",
    "strategies",
    "defense",
    "defenses",
    "report",
    "result",
    "results",
    "system",
    "systems",
    "interface",
    "interfaces",
    "paper",
    "contribution",
    "contributions",
    "limitation",
    "limitations",
    "agent",
    "agents",
    "multi",
    "classify",
    "classification",
    "design",
    "issues",
    "issue",
    "relationship",
    "relationships",
    "define",
    "defined",
    "explore",
    "exploration",
    "index",
    "metadata",
    "trend",
    "trends",
    "policy",
    "policies",
    "control",
    "controls",
    "compliance",
    "graph",
    "flow",
    "process",
    "workflow",
    "分析",
    "审计",
    "总结",
    "摘要",
    "防御",
    "检测",
    "策略",
    "文档",
    "接口",
    "关键",
    "报告",
    "结果",
    "论文",
    "贡献",
    "局限",
    "风险",
    "建议",
    "日志",
    "流程",
    "设计",
    "分类",
    "问题",
    "关系",
    "图谱",
    "索引",
    "元数据",
    "趋势",
    "策略",
    "访问",
    "控制",
    "合规",
}
TOPIC_CONTINUATION_PATTERNS = (
    r"\bthese\b",
    r"\bthose\b",
    r"\bthem\b",
    r"\btheir\b",
    r"\bthese components?\b",
    r"\bthose components?\b",
    r"\bthe components?\b",
    r"\beach component\b",
    r"\bthese materials?\b",
    r"\bthose materials?\b",
    r"\bthe materials?\b",
    r"\bthese items?\b",
    r"\bthose items?\b",
    r"\bit\b",
    r"\bits\b",
    r"\bthey\b",
    r"\bthis device\b",
    r"\bthat device\b",
    r"\bthe device\b",
    r"这些",
    r"那些",
    r"它们",
    r"它的",
    r"这些组件",
    r"这些材料",
    r"这些部件",
    r"该装置",
    r"这个装置",
    r"上述",
    r"前述",
)
ACTIONABLE_PHASES = {
    "capability_building",
    "execution_preparation",
    "evasion_management",
    "objective_realization",
}
SECRET_HINTS = (
    "key",
    "apikey",
    "api key",
    "token",
    "password",
    "credential",
    "secret",
    "密钥",
    "凭证",
    "密码",
    "令牌",
)
POLICY_HINTS = (
    "policy",
    "guardrail",
    "control",
    "策略",
    "护栏",
    "控制",
    "限制",
)
PAYLOAD_HINTS = (
    "payload",
    "command",
    "script",
    "shellcode",
    "后门",
    "脚本",
    "命令",
)
PRIVILEGE_HINTS = ("admin", "root", "sudo", "权限", "提权", "越权")
ANALYSIS_HINTS = (
    "analysis",
    "analyze",
    "audit",
    "review",
    "explain",
    "summary",
    "检测",
    "防御",
    "分析",
    "审计",
    "评估",
    "检查",
    "解释",
    "总结",
)
BENIGN_ENTITY_HINTS = (
    "feedback",
    "report",
    "knowledge base",
    "summary",
    "documentation",
    "用户反馈",
    "报表",
    "知识库",
    "文档",
    "日志",
)
AGENT_HINTS = (
    "agent",
    "agents",
    "multi-agent",
    "subtask",
    "智能体",
    "代理",
    "工具",
    "模型",
)
MULTI_AGENT_MARKERS = ("多个agent", "多个智能体", "multi-agent", "subtask", "子任务")


@dataclass
class _QuerySignals:
    """Query-level priors extracted before graph traversal starts."""

    risk_keyword_score: float
    benign_keyword_score: float
    keyword_reasons: List[str]
    has_multi_agent: bool
    wants_secret: bool
    mentions_guardrail: bool
    mentions_payload: bool
    wants_analysis: bool
    current_relations: Set[str]
    current_entities: Set[str]
    historical_relations: Set[str]
    historical_entities: Set[str]
    historical_query_count: int
    explicit_current_malicious: bool


@dataclass
class _Traversal:
    """One traversable graph edge considered during relation-first search."""

    source_id: str
    source_name: str
    target_id: str
    target_name: str
    relation: str
    direction: str
    query_id: str
    next_entity_id: str
    next_entity_name: str
    edge_key: str


@dataclass
class _RelationCandidate:
    """Grouped traversals for the same relation before entity expansion."""

    base_path: "_PathState"
    relation: str
    direction: str
    traversals: List[_Traversal] = field(default_factory=list)
    score: float = 0.0
    reasons: List[str] = field(default_factory=list)


@dataclass
class _PathState:
    """Internal mutable search state carried through beam expansion."""

    seed_entity: str
    frontier_id: str
    frontier_name: str
    steps: List[ReasoningStep] = field(default_factory=list)
    risk_score: float = 0.0
    benign_score: float = 0.0
    overall_score: float = 0.0
    assembly_score: float = 0.0
    reasons: List[str] = field(default_factory=list)
    visited_entities: Set[str] = field(default_factory=set)
    visited_edges: Set[str] = field(default_factory=set)
    latest_query_steps: int = 0
    historical_steps: int = 0

    def to_public(self) -> ReasoningPath:
        label = "mixed"
        if self.risk_score >= self.benign_score + 1.0:
            label = "risk"
        elif self.benign_score >= self.risk_score + 1.0:
            label = "benign"
        return ReasoningPath(
            seed_entity=self.seed_entity,
            frontier_entity=self.frontier_name,
            steps=list(self.steps),
            risk_score=round(self.risk_score, 3),
            benign_score=round(self.benign_score, 3),
            overall_score=round(self.overall_score, 3),
            label=label,
            reasons=_dedupe(self.reasons)[:5],
        )


@dataclass
class _Assessment:
    malicious: bool
    score: float
    reasons: List[str]
    adequacy: str
    evidence_paths: List[ReasoningPath]
    counter_evidence_paths: List[ReasoningPath]
    missing_links: List[str]
    reasoning_mode: str
    assembly: "_SessionAssemblySummary"
    hard_refuse: bool = False
    requires_llm_consensus: bool = False


@dataclass
class _SessionAssemblySummary:
    current_phases: Set[str]
    historical_phases: Set[str]
    all_phases: Set[str]
    current_topics: Set[str]
    historical_topics: Set[str]
    shared_topics: Set[str]
    current_anchor_terms: Set[str]
    historical_anchor_terms: Set[str]
    shared_anchor_terms: Set[str]
    inferred_current_topics: Set[str]
    has_context_alignment: bool
    current_query_advances_chain: bool
    current_query_closes_chain: bool
    chain_score: float
    reasons: List[str]
    query_timeline: List[str]
    session_queries: List[str]


class Reasoner:
    def __init__(
        self,
        llm_adapter: BaseLLMAdapter,
        config: AppConfig | None = None,
        agent_coordinator: ReasoningAgentCoordinator | None = None,
    ) -> None:
        self.llm_adapter = llm_adapter
        self.config = config or AppConfig()
        self.agent_coordinator = agent_coordinator or build_reasoning_agent_coordinator(
            self.config,
            self.llm_adapter,
        )

    def describe_context(self, context: ContextSubgraph) -> str:
        return self.llm_adapter.describe_subgraph(context)

    def drain_warnings(self) -> List[str]:
        return self.agent_coordinator.drain_warnings()

    def assess(
        self,
        query_id: str,
        query: str,
        triples: List[NormalizedTriple],
        context: ContextSubgraph,
        context_description: str,
    ) -> _Assessment:
        rule_assessment = self._assess_rules(
            query_id=query_id,
            query=query,
            triples=triples,
            context=context,
            context_description=context_description,
        )
        strategy = (self.config.reasoning_strategy or "rules").lower()
        if strategy == "rules":
            return rule_assessment

        rule_summary = self._build_rule_summary(rule_assessment, rule_assessment.assembly)
        llm_judgment = self.agent_coordinator.judge_graph_risk(
            ReasoningJudgeRequest(
                query=query,
                triples=triples,
                context=context,
                context_description=context_description,
                evidence_paths=rule_assessment.evidence_paths,
                counter_evidence_paths=rule_assessment.counter_evidence_paths,
                missing_links=rule_assessment.missing_links,
                rule_summary=rule_summary,
            )
        )
        if llm_judgment is None:
            assessment = rule_assessment
        elif strategy == "llm":
            assessment = self._assess_with_llm(rule_assessment, llm_judgment)
        else:
            assessment = self._assess_hybrid(rule_assessment, llm_judgment)
        return assessment

    def _assess_rules(
        self,
        query_id: str,
        query: str,
        triples: List[NormalizedTriple],
        context: ContextSubgraph,
        context_description: str,
    ) -> _Assessment:
        # ToG-style relation-first loop:
        # 1) derive query priors
        # 2) score/prune promising relations around each frontier
        # 3) expand entities through the kept relations
        # 4) stop early once evidence is sufficient for allow/refuse
        signals = self._build_query_signals(
            query_id=query_id,
            query=query,
            triples=triples,
            context=context,
            context_description=context_description,
        )
        assembly = self._build_session_assembly_summary(
            query_id=query_id,
            query=query,
            triples=triples,
            context=context,
        )
        node_map, adjacency = self._build_search_graph(context)
        active_paths = self._build_initial_paths(query_id, triples, context, node_map)
        all_selected_paths = list(active_paths)
        adequacy = "insufficient"

        direct_high_risk_chain = self._has_high_risk_chain(triples)
        hard_refuse = direct_high_risk_chain or signals.explicit_current_malicious

        for depth in range(1, max(1, self.config.reasoning_max_depth) + 1):
            # Pruning by relation before entity expansion keeps the branching
            # factor manageable on dense context subgraphs.
            relation_candidates = self._relation_search(
                active_paths=active_paths,
                adjacency=adjacency,
                node_map=node_map,
                signals=signals,
            )
            if not relation_candidates:
                adequacy = "uncertain"
                break

            active_paths = self._entity_search(
                relation_candidates=relation_candidates,
                latest_query_id=query_id,
                signals=signals,
            )
            if not active_paths:
                adequacy = "uncertain"
                break

            all_selected_paths.extend(active_paths)
            adequacy = self._judge_adequacy(
                paths=all_selected_paths,
                signals=signals,
                assembly=assembly,
                direct_high_risk_chain=direct_high_risk_chain,
                depth=depth,
                can_expand=depth < self.config.reasoning_max_depth,
            )
            if adequacy in {"sufficient_for_refuse", "sufficient_for_allow"}:
                break
        else:
            adequacy = "uncertain"

        evidence_paths = self._top_paths(all_selected_paths, mode="risk", limit=3)
        counter_evidence_paths = self._top_paths(
            all_selected_paths,
            mode="benign",
            limit=2,
        )
        missing_links = self._identify_missing_links(
            signals=signals,
            assembly=assembly,
            paths=all_selected_paths,
            adequacy=adequacy,
        )
        score = self._final_score(
            signals=signals,
            assembly=assembly,
            evidence_paths=evidence_paths,
            counter_evidence_paths=counter_evidence_paths,
            adequacy=adequacy,
            direct_high_risk_chain=direct_high_risk_chain,
        )
        malicious = self._decide_malicious(
            adequacy=adequacy,
            score=score,
            evidence_paths=evidence_paths,
            counter_evidence_paths=counter_evidence_paths,
            direct_high_risk_chain=direct_high_risk_chain,
        )
        reasons = self._build_reason_list(
            signals=signals,
            assembly=assembly,
            adequacy=adequacy,
            evidence_paths=evidence_paths,
            counter_evidence_paths=counter_evidence_paths,
            missing_links=missing_links,
            malicious=malicious,
        )
        requires_llm_consensus = bool(
            adequacy == "sufficient_for_refuse"
            and not hard_refuse
            and (
                assembly.current_query_advances_chain
                or assembly.current_query_closes_chain
                or assembly.has_context_alignment
            )
        )
        return _Assessment(
            malicious=malicious,
            score=score,
            reasons=reasons,
            adequacy=adequacy,
            evidence_paths=evidence_paths,
            counter_evidence_paths=counter_evidence_paths,
            missing_links=missing_links,
            reasoning_mode="tog_relation_first",
            assembly=assembly,
            hard_refuse=hard_refuse,
            requires_llm_consensus=requires_llm_consensus,
        )

    def _assess_with_llm(
        self,
        rule_assessment: _Assessment,
        llm_judgment: LLMGraphJudgment,
    ) -> _Assessment:
        reasons = self._merge_reasons(
            ["llm graph judge verdict: %s" % ("refuse" if llm_judgment.malicious else "allow")],
            llm_judgment.reasons,
            rule_assessment.reasons[:2],
        )
        return _Assessment(
            malicious=llm_judgment.malicious,
            score=round(llm_judgment.score, 3),
            reasons=reasons,
            adequacy=llm_judgment.adequacy,
            evidence_paths=rule_assessment.evidence_paths,
            counter_evidence_paths=rule_assessment.counter_evidence_paths,
            missing_links=rule_assessment.missing_links,
            reasoning_mode="llm_graph_judge",
            assembly=rule_assessment.assembly,
            hard_refuse=False,
            requires_llm_consensus=False,
        )

    def _assess_hybrid(
        self,
        rule_assessment: _Assessment,
        llm_judgment: LLMGraphJudgment,
    ) -> _Assessment:
        rule_weight = min(max(self.config.reasoning_hybrid_rule_weight, 0.0), 1.0)
        llm_weight = 1.0 - rule_weight
        normalized_rule_score = self._normalize_rule_score(rule_assessment.score)
        combined_score = round(
            normalized_rule_score * rule_weight + llm_judgment.score * llm_weight,
            3,
        )
        confidence_threshold = self.config.reasoning_llm_confidence_threshold
        llm_supports_refuse = (
            llm_judgment.malicious
            and llm_judgment.confidence >= confidence_threshold
            and llm_judgment.adequacy == "sufficient_for_refuse"
        )

        if (
            rule_assessment.hard_refuse
            and rule_assessment.adequacy == "sufficient_for_refuse"
        ):
            malicious = True
            adequacy = "sufficient_for_refuse"
        elif rule_assessment.requires_llm_consensus:
            if llm_supports_refuse:
                malicious = True
                adequacy = "sufficient_for_refuse"
            elif (
                not llm_judgment.malicious
                and llm_judgment.adequacy == "sufficient_for_allow"
            ):
                malicious = False
                adequacy = "uncertain"
            else:
                malicious = combined_score >= 5.8
                adequacy = "uncertain"
        elif llm_supports_refuse and rule_assessment.malicious:
            malicious = True
            adequacy = "sufficient_for_refuse"
        elif llm_supports_refuse:
            malicious = False
            adequacy = "uncertain"
        elif not rule_assessment.malicious and not llm_judgment.malicious:
            malicious = False
            adequacy = (
                "sufficient_for_allow"
                if "sufficient_for_allow"
                in {rule_assessment.adequacy, llm_judgment.adequacy}
                else "uncertain"
            )
        else:
            malicious = combined_score >= 5.0
            adequacy = "uncertain"

        reasons = self._merge_reasons(
            [
                "hybrid reasoning combines relation-first search with llm review",
                "rule score=%.2f llm score=%.2f llm confidence=%.2f"
                % (
                    normalized_rule_score,
                    llm_judgment.score,
                    llm_judgment.confidence,
                ),
            ],
            (
                ["explicit current-query risk keeps rule-layer hard refusal"]
                if rule_assessment.hard_refuse
                else []
            ),
            (
                ["cross-turn assembly refusal requires rule and llm consensus"]
                if rule_assessment.requires_llm_consensus
                else []
            ),
            llm_judgment.reasons,
            rule_assessment.reasons,
        )
        return _Assessment(
            malicious=malicious,
            score=combined_score,
            reasons=reasons,
            adequacy=adequacy,
            evidence_paths=rule_assessment.evidence_paths,
            counter_evidence_paths=rule_assessment.counter_evidence_paths,
            missing_links=rule_assessment.missing_links,
            reasoning_mode="tog_hybrid_llm",
            assembly=rule_assessment.assembly,
            hard_refuse=rule_assessment.hard_refuse,
            requires_llm_consensus=rule_assessment.requires_llm_consensus,
        )

    def _build_rule_summary(
        self,
        assessment: _Assessment,
        assembly: _SessionAssemblySummary,
    ) -> Dict[str, object]:
        bridge_path_count = sum(
            1
            for path in assessment.evidence_paths
            if len({step.query_id for step in path.steps if step.query_id}) > 1
        )
        return {
            "malicious": assessment.malicious,
            "score": assessment.score,
            "adequacy": assessment.adequacy,
            "reasoning_mode": assessment.reasoning_mode,
            "rule_hard_refuse": assessment.hard_refuse,
            "rule_requires_llm_consensus": assessment.requires_llm_consensus,
            "reasons": list(assessment.reasons),
            "bridge_path_count": bridge_path_count,
            "latest_query_focus": bool(assessment.evidence_paths),
            "assembly_chain_score": assembly.chain_score,
            "assembly_current_advances_chain": assembly.current_query_advances_chain,
            "assembly_current_closes_chain": assembly.current_query_closes_chain,
            "assembly_current_phases": sorted(assembly.current_phases),
            "assembly_historical_phases": sorted(assembly.historical_phases),
            "assembly_current_topics": sorted(assembly.current_topics),
            "assembly_historical_topics": sorted(assembly.historical_topics),
            "assembly_shared_topics": sorted(assembly.shared_topics),
            "assembly_shared_anchors": sorted(assembly.shared_anchor_terms),
            "assembly_has_context_alignment": assembly.has_context_alignment,
            "assembly_reasons": list(assembly.reasons[:4]),
            "assembly_timeline": list(assembly.query_timeline[:5]),
            "assembly_session_queries": list(assembly.session_queries[-12:]),
        }

    def _normalize_rule_score(self, score: float) -> float:
        centered = 5.0 + (score - self.config.reasoning_risk_evidence_threshold)
        return round(min(max(centered, 0.0), 10.0), 3)

    def _merge_reasons(self, *reason_lists: Sequence[str]) -> List[str]:
        merged: List[str] = []
        for reason_list in reason_lists:
            for reason in reason_list:
                if reason:
                    merged.append(reason)
        return _dedupe(merged)[:8]

    def _build_query_signals(
        self,
        query_id: str,
        query: str,
        triples: Sequence[NormalizedTriple],
        context: ContextSubgraph,
        context_description: str,
    ) -> _QuerySignals:
        combined_text = " ".join(
            [query, context_description]
            + [triple.raw_relation for triple in triples]
            + [triple.normalized_relation for triple in triples]
            + [triple.object for triple in triples]
        ).lower()

        risk_keyword_score = 0.0
        benign_keyword_score = 0.0
        keyword_reasons: List[str] = []

        for keyword, weight in MALICIOUS_KEYWORDS.items():
            if keyword.lower() in combined_text:
                risk_keyword_score += weight
                keyword_reasons.append("matched keyword '%s'" % keyword)

        for keyword, weight in BENIGN_KEYWORDS.items():
            if keyword.lower() in combined_text:
                benign_keyword_score += weight
                keyword_reasons.append("benign signal '%s'" % keyword)

        current_relations = {triple.normalized_relation for triple in triples}
        current_entities = {
            entity
            for triple in triples
            for entity in (triple.subject, triple.object)
            if entity
        }
        historical_relations = set()
        historical_entities = set()
        historical_query_ids = set()
        node_names = {node.node_id: node.name for node in context.nodes}
        for edge in context.edges:
            if edge.relation == "mentions":
                continue
            edge_query_id = edge.attributes.get("query_id", "")
            if not edge_query_id or edge_query_id == query_id:
                continue
            historical_relations.add(edge.relation)
            historical_query_ids.add(edge_query_id)
            if edge.source in node_names:
                historical_entities.add(node_names[edge.source])
            if edge.target in node_names:
                historical_entities.add(node_names[edge.target])

        return _QuerySignals(
            risk_keyword_score=risk_keyword_score,
            benign_keyword_score=benign_keyword_score,
            keyword_reasons=keyword_reasons,
            has_multi_agent=any(marker in query.lower() for marker in MULTI_AGENT_MARKERS)
            or "coordinates_agent" in current_relations,
            wants_secret=self._contains_any(combined_text, SECRET_HINTS)
            or "exfiltrates_secret" in current_relations,
            mentions_guardrail=self._contains_any(combined_text, POLICY_HINTS)
            or "bypasses_guardrail" in current_relations,
            mentions_payload=self._contains_any(combined_text, PAYLOAD_HINTS)
            or "executes_payload" in current_relations,
            wants_analysis=self._contains_any(combined_text, ANALYSIS_HINTS)
            or bool(current_relations & set(RELATION_BENIGN)),
            current_relations=current_relations,
            current_entities=current_entities,
            historical_relations=historical_relations,
            historical_entities=historical_entities,
            historical_query_count=len(historical_query_ids),
            explicit_current_malicious=self._is_explicit_current_query_malicious(
                current_relations=current_relations,
                wants_secret=self._contains_any(combined_text, SECRET_HINTS)
                or "exfiltrates_secret" in current_relations,
                mentions_guardrail=self._contains_any(combined_text, POLICY_HINTS)
                or "bypasses_guardrail" in current_relations,
                mentions_payload=self._contains_any(combined_text, PAYLOAD_HINTS)
                or "executes_payload" in current_relations,
                wants_analysis=self._contains_any(combined_text, ANALYSIS_HINTS)
                or bool(current_relations & set(RELATION_BENIGN)),
                risk_keyword_score=risk_keyword_score,
            ),
        )

    def _build_session_assembly_summary(
        self,
        query_id: str,
        query: str,
        triples: Sequence[NormalizedTriple],
        context: ContextSubgraph,
    ) -> _SessionAssemblySummary:
        current_phases = self._infer_task_phases(query, triples)
        raw_current_topics = self._infer_dangerous_topics(query, triples)
        current_topics = set(raw_current_topics)
        current_anchor_terms = self._extract_anchor_terms(query, triples)

        historical_phases: Set[str] = set()
        historical_topics: Set[str] = set()
        historical_anchor_terms: Set[str] = set()
        timeline: List[str] = []
        session_queries: List[str] = []
        recent_topic_anchors: List[Set[str]] = []
        historical_query_nodes = [
            node
            for node in context.nodes
            if node.kind == "query"
        ]
        historical_query_nodes.sort(key=lambda node: node.attributes.get("created_at", ""))
        historical_query_nodes = [
            node for node in historical_query_nodes if node.node_id != query_id
        ][-ASSEMBLY_HISTORY_LIMIT:]
        for node in historical_query_nodes:
            node_query_id = node.node_id
            query_text = str(node.attributes.get("text", "")).strip()
            if not query_text:
                continue
            session_queries.append(query_text)
            node_triples = self._triples_for_query(node_query_id, context)
            node_phases = self._infer_task_phases(query_text, node_triples)
            node_topics = self._infer_dangerous_topics(query_text, node_triples)
            node_anchor_terms = self._extract_anchor_terms(query_text, node_triples)
            if node_phases or node_topics:
                timeline.append(
                    "%s | phases=%s | topics=%s | text=%s"
                    % (
                        node_query_id,
                        ",".join(sorted(node_phases)) or "none",
                        ",".join(sorted(node_topics)) or "none",
                        query_text,
                    )
                )
            historical_phases.update(node_phases)
            historical_topics.update(node_topics)
            historical_anchor_terms.update(node_anchor_terms)
            if node_topics:
                recent_topic_anchors.append(set(node_topics))

        inferred_current_topics: Set[str] = set()
        if (
            not current_topics
            and historical_topics
            and current_phases
            and self._query_has_topic_continuation_cue(query)
        ):
            for topic_set in reversed(recent_topic_anchors):
                if topic_set:
                    inferred_current_topics = set(topic_set)
                    break
            if inferred_current_topics:
                current_topics = set(inferred_current_topics)

        all_phases = current_phases | historical_phases
        shared_topics = current_topics & historical_topics
        shared_anchor_terms = current_anchor_terms & historical_anchor_terms
        has_context_alignment = bool(
            shared_topics or shared_anchor_terms or inferred_current_topics
        )
        phase_advances = current_phases - historical_phases
        current_query_advances_chain = bool(phase_advances) and has_context_alignment
        current_query_closes_chain = bool(
            current_query_advances_chain
            and len(all_phases) >= 3
            and (
                "execution_preparation" in all_phases
                or "objective_realization" in all_phases
                or "evasion_management" in all_phases
            )
        )

        chain_score = 0.0
        chain_score += 0.65 * len(all_phases)
        chain_score += 1.0 * len(shared_topics)
        chain_score += 0.8 * len(shared_anchor_terms)
        chain_score += 0.25 * len(current_topics)
        if inferred_current_topics:
            chain_score += 0.4
        if current_query_advances_chain:
            chain_score += 0.9
        if current_query_closes_chain:
            chain_score += 1.2
        if current_phases and not has_context_alignment and not current_topics:
            chain_score = max(0.0, chain_score - 0.8)
        chain_score = round(chain_score, 3)

        reasons: List[str] = []
        if current_topics:
            if inferred_current_topics:
                reasons.append(
                    "current query inherits dangerous topic(s) from prior context: %s"
                    % ", ".join(sorted(inferred_current_topics))
                )
            else:
                reasons.append(
                    "current query touches dangerous topic(s): %s"
                    % ", ".join(sorted(current_topics))
                )
        if shared_topics:
            reasons.append(
                "current query stays on the same risky topic as history: %s"
                % ", ".join(sorted(shared_topics))
            )
        if shared_anchor_terms:
            reasons.append(
                "current query shares content anchors with risky history: %s"
                % ", ".join(sorted(shared_anchor_terms)[:6])
            )
        elif historical_topics and current_query_advances_chain:
            reasons.append(
                "current query advances a session already anchored on dangerous topic(s): %s"
                % ", ".join(sorted(historical_topics))
            )
        if current_query_advances_chain:
            reasons.append(
                "current query adds new task phases to the session chain: %s"
                % ", ".join(sorted(phase_advances))
            )
        if current_query_closes_chain:
            reasons.append("current query helps close a multi-stage attack-planning chain")

        return _SessionAssemblySummary(
            current_phases=current_phases,
            historical_phases=historical_phases,
            all_phases=all_phases,
            current_topics=current_topics,
            historical_topics=historical_topics,
            shared_topics=shared_topics,
            current_anchor_terms=current_anchor_terms,
            historical_anchor_terms=historical_anchor_terms,
            shared_anchor_terms=shared_anchor_terms,
            inferred_current_topics=inferred_current_topics,
            has_context_alignment=has_context_alignment,
            current_query_advances_chain=current_query_advances_chain,
            current_query_closes_chain=current_query_closes_chain,
            chain_score=chain_score,
            reasons=reasons,
            query_timeline=timeline,
            session_queries=session_queries + [query],
        )

    def _triples_for_query(
        self,
        query_id: str,
        context: ContextSubgraph,
    ) -> List[NormalizedTriple]:
        triples: List[NormalizedTriple] = []
        node_names = {node.node_id: node.name for node in context.nodes}
        for edge in context.edges:
            if edge.relation == "mentions":
                continue
            if edge.attributes.get("query_id", "") != query_id:
                continue
            triples.append(
                NormalizedTriple(
                    subject=node_names.get(edge.source, ""),
                    raw_relation=str(edge.attributes.get("raw_relation", edge.relation)),
                    object=node_names.get(edge.target, ""),
                    relation_definition="",
                    normalized_relation=edge.relation,
                    confidence=float(edge.attributes.get("confidence", "0") or 0.0),
                    cluster_id=int(edge.attributes.get("cluster_id", "0") or 0),
                    candidate_relations=[],
                )
            )
        return triples

    def _infer_task_phases(
        self,
        query_text: str,
        triples: Sequence[NormalizedTriple],
    ) -> Set[str]:
        phases = {
            phase
            for triple in triples
            for relation_name, phase in RELATION_PHASE_MAP.items()
            if triple.normalized_relation == relation_name
        }
        lowered = query_text.lower()
        for phase, patterns in PHASE_TEXT_PATTERNS.items():
            if any(re.search(pattern, lowered, flags=re.IGNORECASE) for pattern in patterns):
                phases.add(phase)
        return phases

    def _infer_dangerous_topics(
        self,
        query_text: str,
        triples: Sequence[NormalizedTriple],
    ) -> Set[str]:
        combined = " ".join(
            [query_text]
            + [triple.subject for triple in triples]
            + [triple.object for triple in triples]
            + [triple.raw_relation for triple in triples]
            + [triple.normalized_relation for triple in triples]
        ).lower()
        topics = set()
        for topic, patterns in DANGEROUS_TOPIC_PATTERNS.items():
            if any(re.search(pattern, combined, flags=re.IGNORECASE) for pattern in patterns):
                topics.add(topic)
        return topics

    def _extract_anchor_terms(
        self,
        query_text: str,
        triples: Sequence[NormalizedTriple],
    ) -> Set[str]:
        fragments = [query_text]
        for triple in triples:
            fragments.append(triple.object)
        terms: Set[str] = set()
        for token in tokenize(" ".join(fragment for fragment in fragments if fragment)):
            normalized = token.strip().lower()
            if not normalized or normalized in ANCHOR_STOPWORDS:
                continue
            if normalized.isascii():
                if len(normalized) < 4:
                    continue
            elif len(normalized) < 2:
                continue
            terms.add(normalized)
        return terms

    def _query_has_topic_continuation_cue(self, query_text: str) -> bool:
        lowered = query_text.lower()
        return any(
            re.search(pattern, lowered, flags=re.IGNORECASE)
            for pattern in TOPIC_CONTINUATION_PATTERNS
        )

    def _build_search_graph(
        self,
        context: ContextSubgraph,
    ) -> Tuple[Dict[str, GraphNode], Dict[str, List[GraphEdge]]]:
        node_map = {node.node_id: node for node in context.nodes}
        adjacency: Dict[str, List[GraphEdge]] = {
            node.node_id: [] for node in context.nodes if node.kind == "entity"
        }
        for edge in context.edges:
            if edge.relation == "mentions":
                continue
            source = node_map.get(edge.source)
            target = node_map.get(edge.target)
            if not source or not target:
                continue
            if source.kind != "entity" or target.kind != "entity":
                continue
            adjacency.setdefault(edge.source, []).append(edge)
            adjacency.setdefault(edge.target, []).append(edge)
        return node_map, adjacency

    def _build_initial_paths(
        self,
        query_id: str,
        triples: Sequence[NormalizedTriple],
        context: ContextSubgraph,
        node_map: Dict[str, GraphNode],
    ) -> List[_PathState]:
        latest_relation_edges = [
            edge
            for edge in context.edges
            if edge.relation != "mentions" and edge.attributes.get("query_id", "") == query_id
        ]
        if latest_relation_edges:
            paths = []
            for edge in latest_relation_edges:
                source_node = node_map.get(edge.source)
                target_node = node_map.get(edge.target)
                if not source_node or not target_node:
                    continue
                latest_step = ReasoningStep(
                    source=source_node.name,
                    relation=edge.relation,
                    target=target_node.name,
                    direction="outgoing",
                    query_id=query_id,
                )
                relation_risk = RELATION_RISK.get(edge.relation, 0.0)
                relation_benign = RELATION_BENIGN.get(edge.relation, 0.0)
                source_risk, source_risk_reasons = self._score_entity_risk(source_node.name)
                target_risk, target_risk_reasons = self._score_entity_risk(target_node.name)
                source_benign, source_benign_reasons = self._score_entity_benign(source_node.name)
                target_benign, target_benign_reasons = self._score_entity_benign(target_node.name)
                common_reasons = _dedupe(
                    source_risk_reasons
                    + target_risk_reasons
                    + source_benign_reasons
                    + target_benign_reasons
                    + ["starts from a relation inserted by the current query"]
                )
                base_risk = relation_risk + source_risk + target_risk
                base_benign = relation_benign + source_benign + target_benign
                base_overall = base_risk - base_benign + 0.6
                for frontier_node in (source_node, target_node):
                    paths.append(
                        _PathState(
                            seed_entity=source_node.name,
                            frontier_id=frontier_node.node_id,
                            frontier_name=frontier_node.name,
                            steps=[latest_step],
                            risk_score=base_risk,
                            benign_score=base_benign,
                            overall_score=base_overall,
                            assembly_score=0.2,
                            reasons=list(common_reasons),
                            visited_entities={source_node.node_id, target_node.node_id},
                            visited_edges={
                                "%s|%s|%s|%s"
                                % (edge.source, edge.relation, edge.target, query_id)
                            },
                            latest_query_steps=1,
                            historical_steps=0,
                        )
                    )
            if paths:
                return paths

        name_to_node_id = {
            node.name: node.node_id for node in context.nodes if node.kind == "entity"
        }
        ordered_seeds: List[str] = []
        for triple in triples:
            ordered_seeds.append(triple.subject)
            ordered_seeds.append(triple.object)
        for edge in context.edges:
            if edge.relation == "mentions" and edge.source == query_id and edge.target in node_map:
                ordered_seeds.append(node_map[edge.target].name)

        paths: List[_PathState] = []
        for seed_name in _dedupe(ordered_seeds):
            node_id = name_to_node_id.get(seed_name)
            if not node_id:
                continue
            risk_score, risk_reasons = self._score_entity_risk(seed_name)
            benign_score, benign_reasons = self._score_entity_benign(seed_name)
            paths.append(
                _PathState(
                    seed_entity=seed_name,
                    frontier_id=node_id,
                    frontier_name=seed_name,
                    risk_score=risk_score,
                    benign_score=benign_score,
                    overall_score=risk_score - benign_score + 0.15,
                    assembly_score=0.0,
                    reasons=_dedupe(risk_reasons + benign_reasons),
                    visited_entities={node_id},
                    visited_edges=set(),
                    latest_query_steps=0,
                    historical_steps=0,
                )
            )
        return paths

    def _relation_search(
        self,
        active_paths: Sequence[_PathState],
        adjacency: Dict[str, List[GraphEdge]],
        node_map: Dict[str, GraphNode],
        signals: _QuerySignals,
    ) -> List[_RelationCandidate]:
        grouped: Dict[Tuple[Tuple[str, ...], str, str], _RelationCandidate] = {}

        for path in active_paths:
            for edge in adjacency.get(path.frontier_id, []):
                traversal = self._make_traversal(path.frontier_id, edge, node_map)
                if traversal.edge_key in path.visited_edges:
                    continue
                if traversal.next_entity_id in path.visited_entities and len(path.visited_entities) > 1:
                    continue
                key = (
                    self._path_signature(path.steps),
                    path.frontier_id,
                    traversal.relation,
                    traversal.direction,
                )
                candidate = grouped.get(key)
                if candidate is None:
                    candidate = _RelationCandidate(
                        base_path=path,
                        relation=traversal.relation,
                        direction=traversal.direction,
                    )
                    grouped[key] = candidate
                candidate.traversals.append(traversal)

        candidates = list(grouped.values())
        for candidate in candidates:
            candidate.score, candidate.reasons = self._score_relation_candidate(
                candidate,
                signals,
            )
        candidates.sort(key=lambda item: item.score, reverse=True)
        return candidates[: max(self.config.reasoning_beam_width * 2, 1)]

    def _entity_search(
        self,
        relation_candidates: Sequence[_RelationCandidate],
        latest_query_id: str,
        signals: _QuerySignals,
    ) -> List[_PathState]:
        expanded_paths = []
        for relation_candidate in relation_candidates:
            for traversal in relation_candidate.traversals:
                expanded_paths.append(
                    self._extend_path(
                        base_path=relation_candidate.base_path,
                        traversal=traversal,
                        latest_query_id=latest_query_id,
                        signals=signals,
                        relation_reasons=relation_candidate.reasons,
                    )
                )

        expanded_paths.sort(key=self._beam_rank, reverse=True)
        selected = []
        seen = set()
        for path in expanded_paths:
            signature = self._path_signature(path.steps)
            if signature in seen:
                continue
            seen.add(signature)
            selected.append(path)
            if len(selected) >= max(self.config.reasoning_beam_width, 1):
                break
        return selected

    def _score_relation_candidate(
        self,
        candidate: _RelationCandidate,
        signals: _QuerySignals,
    ) -> Tuple[float, List[str]]:
        score = RELATION_BRIDGE.get(candidate.relation, 0.2)
        score += 0.75 * RELATION_RISK.get(candidate.relation, 0.0)
        score += 0.65 * RELATION_BENIGN.get(candidate.relation, 0.0)

        reasons = []
        if candidate.relation in signals.current_relations:
            score += 0.8
            reasons.append("mirrors a relation from the latest query")
        if candidate.relation in RELATION_RISK:
            reasons.append("touches a high-risk relation")
        elif candidate.relation in RELATION_BENIGN:
            reasons.append("touches a benign analysis relation")

        if candidate.direction == "incoming":
            score -= 0.1

        if len(candidate.traversals) == 1:
            score += 0.15

        best_entity_risk = 0.0
        best_entity_benign = 0.0
        for traversal in candidate.traversals:
            best_entity_risk = max(
                best_entity_risk,
                self._score_entity_risk(traversal.next_entity_name)[0],
            )
            best_entity_benign = max(
                best_entity_benign,
                self._score_entity_benign(traversal.next_entity_name)[0],
            )
        score += 0.2 * max(best_entity_risk, best_entity_benign)

        if signals.has_multi_agent and candidate.relation == "coordinates_agent":
            score += 0.5
        if signals.mentions_guardrail and candidate.relation == "bypasses_guardrail":
            score += 0.6
        if signals.wants_secret and candidate.relation in {"retrieves_data", "exfiltrates_secret"}:
            score += 0.5
        if signals.mentions_payload and candidate.relation == "executes_payload":
            score += 0.5
        if signals.wants_analysis and candidate.relation in {"requests_information", "analyzes_target"}:
            score += 0.4
        if candidate.base_path.latest_query_steps and any(
            traversal.query_id and traversal.query_id != candidate.base_path.steps[-1].query_id
            for traversal in candidate.traversals
        ):
            score += 0.75
            reasons.append("can connect the current query to historical context")
        if candidate.base_path.historical_steps and any(
            traversal.query_id == candidate.base_path.steps[0].query_id
            for traversal in candidate.traversals
        ):
            score += 0.45
            reasons.append("keeps a historical chain anchored on the current query")

        return score, reasons[:3]

    def _extend_path(
        self,
        base_path: _PathState,
        traversal: _Traversal,
        latest_query_id: str,
        signals: _QuerySignals,
        relation_reasons: Sequence[str],
    ) -> _PathState:
        step = ReasoningStep(
            source=traversal.source_name,
            relation=traversal.relation,
            target=traversal.target_name,
            direction=traversal.direction,
            query_id=traversal.query_id,
        )

        risk_score = base_path.risk_score
        benign_score = base_path.benign_score
        assembly_score = base_path.assembly_score
        reasons = list(base_path.reasons) + list(relation_reasons)
        latest_query_steps = base_path.latest_query_steps
        historical_steps = base_path.historical_steps
        if traversal.query_id == latest_query_id:
            latest_query_steps += 1
        elif traversal.query_id:
            historical_steps += 1

        relation_risk = RELATION_RISK.get(traversal.relation, 0.0)
        relation_benign = RELATION_BENIGN.get(traversal.relation, 0.0)
        if relation_risk:
            risk_score += relation_risk
            reasons.append("relation '%s' adds risk evidence" % traversal.relation)
        if relation_benign:
            benign_score += relation_benign
            reasons.append("relation '%s' adds benign evidence" % traversal.relation)

        entity_risk, entity_risk_reasons = self._score_entity_risk(traversal.next_entity_name)
        entity_benign, entity_benign_reasons = self._score_entity_benign(
            traversal.next_entity_name
        )
        risk_score += entity_risk
        benign_score += entity_benign
        reasons.extend(entity_risk_reasons)
        reasons.extend(entity_benign_reasons)

        if traversal.relation in {"uses_tool", "coordinates_agent"} and (
            signals.has_multi_agent
            or signals.mentions_guardrail
            or signals.wants_secret
            or signals.mentions_payload
        ):
            risk_score += 0.4
            reasons.append("tool or agent orchestration is tied to a risky request")
        if traversal.relation == "retrieves_data" and signals.wants_secret:
            risk_score += 0.5
            reasons.append("data retrieval is close to a secret-oriented request")
        if traversal.relation == "updates_resource" and signals.wants_analysis:
            benign_score += 0.3
            reasons.append("resource updates appear in an analysis-style request")

        if latest_query_steps and historical_steps:
            assembly_score += 0.9
            reasons.append("current query bridges into historical task context")
            if traversal.relation in HIGH_RISK_RELATIONS:
                assembly_score += 0.6
                risk_score += 0.6
                reasons.append("bridge closes on a high-risk downstream action")
            if signals.historical_relations & HIGH_RISK_RELATIONS:
                assembly_score += 0.4
                risk_score += 0.3
                reasons.append("history already contains risky relations around this chain")

        if base_path.steps:
            previous_relation = base_path.steps[-1].relation
            chain_risk = CHAIN_RISK_BONUSES.get((previous_relation, traversal.relation), 0.0)
            chain_benign = CHAIN_BENIGN_BONUSES.get(
                (previous_relation, traversal.relation),
                0.0,
            )
            if chain_risk:
                risk_score += chain_risk
                reasons.append(
                    "path links '%s' to '%s' in a risky sequence"
                    % (previous_relation, traversal.relation)
                )
            if chain_benign:
                benign_score += chain_benign
                reasons.append(
                    "path links '%s' to '%s' in a benign analysis sequence"
                    % (previous_relation, traversal.relation)
                )

        relevance = 0.0
        if traversal.relation in signals.current_relations:
            relevance += 0.55
        if traversal.next_entity_name in signals.current_entities:
            relevance += 0.25
        if traversal.query_id == latest_query_id:
            relevance += 0.35
        else:
            relevance += 0.1
        if traversal.direction == "incoming":
            relevance -= 0.15
        if len(base_path.steps) >= 2:
            relevance -= 0.05 * (len(base_path.steps) - 1)

        overall_score = risk_score - benign_score + relevance + assembly_score
        return _PathState(
            seed_entity=base_path.seed_entity,
            frontier_id=traversal.next_entity_id,
            frontier_name=traversal.next_entity_name,
            steps=base_path.steps + [step],
            risk_score=risk_score,
            benign_score=benign_score,
            overall_score=overall_score,
            assembly_score=assembly_score,
            reasons=_dedupe(reasons),
            visited_entities=set(base_path.visited_entities) | {traversal.next_entity_id},
            visited_edges=set(base_path.visited_edges) | {traversal.edge_key},
            latest_query_steps=latest_query_steps,
            historical_steps=historical_steps,
        )

    def _judge_adequacy(
        self,
        paths: Sequence[_PathState],
        signals: _QuerySignals,
        assembly: _SessionAssemblySummary,
        direct_high_risk_chain: bool,
        depth: int,
        can_expand: bool,
    ) -> str:
        if not paths:
            return "uncertain"

        strongest_risk = max(path.risk_score for path in paths)
        strongest_benign = max(path.benign_score for path in paths)
        strongest_assembly = max(path.assembly_score for path in paths)
        has_high_risk_path = any(self._path_has_high_risk_chain(path) for path in paths)
        has_benign_path = any(self._path_has_benign_chain(path) for path in paths)
        has_bridge_path = any(path.latest_query_steps and path.historical_steps for path in paths)

        if direct_high_risk_chain or signals.explicit_current_malicious:
            return "sufficient_for_refuse"
        if has_high_risk_path and assembly.has_context_alignment:
            return "sufficient_for_refuse"
        if (
            assembly.has_context_alignment
            and len(assembly.all_phases) >= 3
            and bool(assembly.all_phases & ACTIONABLE_PHASES)
            and assembly.chain_score >= 3.4
            and (
                assembly.current_query_advances_chain
                or assembly.current_query_closes_chain
            )
        ):
            return "sufficient_for_refuse"
        if (
            assembly.current_query_closes_chain
            and assembly.chain_score >= 3.2
            and (
                assembly.has_context_alignment
                or signals.risk_keyword_score >= 2.5
            )
        ):
            return "sufficient_for_refuse"
        if (
            assembly.current_query_advances_chain
            and assembly.chain_score >= 4.0
            and len(assembly.all_phases) >= 3
            and assembly.has_context_alignment
        ):
            return "sufficient_for_refuse"
        if (
            has_bridge_path
            and strongest_assembly >= 0.9
            and (
                assembly.current_query_advances_chain
                or assembly.current_query_closes_chain
            )
            and (
                strongest_risk >= self.config.reasoning_risk_evidence_threshold - 1.0
                or bool(signals.historical_relations & HIGH_RISK_RELATIONS)
                or len(signals.current_relations & ATTACK_PREPARATION_RELATIONS) >= 2
                or len(signals.historical_relations & ATTACK_PREPARATION_RELATIONS) >= 2
                or signals.risk_keyword_score >= 2.5
            )
        ):
            return "sufficient_for_refuse"
        if (
            has_bridge_path
            and len(signals.current_relations & ATTACK_PREPARATION_RELATIONS) >= 1
            and len(signals.historical_relations & ATTACK_PREPARATION_RELATIONS) >= 1
            and (
                assembly.current_query_advances_chain
                or assembly.current_query_closes_chain
            )
            and strongest_risk >= self.config.reasoning_risk_evidence_threshold - 1.5
        ):
            return "sufficient_for_refuse"
        if (
            strongest_risk >= self.config.reasoning_risk_evidence_threshold
            and strongest_risk >= strongest_benign + 0.5
        ):
            return "sufficient_for_refuse"
        if (
            strongest_benign >= self.config.reasoning_benign_evidence_threshold
            and strongest_risk < self.config.reasoning_risk_evidence_threshold - 1.0
            and strongest_assembly < 0.5
            and not has_bridge_path
            and not assembly.current_query_advances_chain
            and not (assembly.current_topics or assembly.historical_topics)
            and not assembly.has_context_alignment
            and not signals.historical_relations & HIGH_RISK_RELATIONS
            and (
                signals.benign_keyword_score >= 0.5
                or has_benign_path
                or not signals.current_relations & HIGH_RISK_RELATIONS
            )
        ):
            return "sufficient_for_allow"
        if can_expand and depth < self.config.reasoning_max_depth:
            return "insufficient"
        return "uncertain"

    def _final_score(
        self,
        signals: _QuerySignals,
        assembly: _SessionAssemblySummary,
        evidence_paths: Sequence[ReasoningPath],
        counter_evidence_paths: Sequence[ReasoningPath],
        adequacy: str,
        direct_high_risk_chain: bool,
    ) -> float:
        strongest_risk = evidence_paths[0].risk_score if evidence_paths else 0.0
        strongest_benign = counter_evidence_paths[0].benign_score if counter_evidence_paths else 0.0
        score = signals.risk_keyword_score - signals.benign_keyword_score
        score += assembly.chain_score
        score += strongest_risk
        score -= 0.75 * strongest_benign
        if not assembly.has_context_alignment and not direct_high_risk_chain:
            score -= 0.9
        if adequacy == "sufficient_for_refuse":
            score += 0.75
        elif adequacy == "sufficient_for_allow":
            score -= 0.75
        if direct_high_risk_chain:
            score += 1.5
        if any(
            step.query_id and evidence_path.steps and step.query_id != evidence_path.steps[0].query_id
            for evidence_path in evidence_paths
            for step in evidence_path.steps
        ):
            score += 0.8
        if len(evidence_paths) > 1:
            score += min(1.0, 0.35 * (len(evidence_paths) - 1))
        if len(counter_evidence_paths) > 1:
            score -= min(0.5, 0.2 * (len(counter_evidence_paths) - 1))
        return round(score, 3)

    def _decide_malicious(
        self,
        adequacy: str,
        score: float,
        evidence_paths: Sequence[ReasoningPath],
        counter_evidence_paths: Sequence[ReasoningPath],
        direct_high_risk_chain: bool,
    ) -> bool:
        if adequacy == "sufficient_for_allow":
            return False
        if adequacy == "sufficient_for_refuse":
            return True

        strongest_risk = evidence_paths[0].risk_score if evidence_paths else 0.0
        strongest_benign = counter_evidence_paths[0].benign_score if counter_evidence_paths else 0.0
        return bool(
            direct_high_risk_chain
            or score >= 5.0
            or (
                strongest_risk >= self.config.reasoning_risk_evidence_threshold
                and strongest_risk > strongest_benign + 0.5
            )
        )

    def _build_reason_list(
        self,
        signals: _QuerySignals,
        assembly: _SessionAssemblySummary,
        adequacy: str,
        evidence_paths: Sequence[ReasoningPath],
        counter_evidence_paths: Sequence[ReasoningPath],
        missing_links: Sequence[str],
        malicious: bool,
    ) -> List[str]:
        reasons = list(signals.keyword_reasons)
        reasons.extend(assembly.reasons)
        if evidence_paths:
            reasons.append("risk path: %s" % self._render_path(evidence_paths[0]))
            if len({step.query_id for step in evidence_paths[0].steps if step.query_id}) > 1:
                reasons.append("current query helps assemble a cross-turn attack chain")
        if counter_evidence_paths:
            reasons.append("benign path: %s" % self._render_path(counter_evidence_paths[0]))
        if adequacy == "sufficient_for_refuse":
            reasons.append("path evidence is sufficient to support refusal")
        elif adequacy == "sufficient_for_allow":
            reasons.append("path evidence is sufficient to support allowance")
        elif missing_links:
            reasons.append("missing evidence: %s" % "; ".join(missing_links))
        if not reasons:
            reasons.append(
                "no explicit malicious signal detected"
                if not malicious
                else "risk evidence outweighs benign evidence"
            )
        return _dedupe(reasons)

    def _top_paths(
        self,
        paths: Sequence[_PathState],
        mode: str,
        limit: int,
    ) -> List[ReasoningPath]:
        ranked = []
        for path in paths:
            if mode == "risk":
                if path.risk_score < 1.0:
                    continue
                ranked.append((path.risk_score, path.overall_score, path))
            else:
                if path.benign_score < 1.0:
                    continue
                ranked.append((path.benign_score, -path.risk_score, path))
        ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)

        selected = []
        seen = set()
        for _primary, _secondary, path in ranked:
            signature = self._semantic_path_signature(path.steps)
            if signature in seen:
                continue
            seen.add(signature)
            selected.append(path.to_public())
            if len(selected) >= limit:
                break
        return selected

    def _identify_missing_links(
        self,
        signals: _QuerySignals,
        assembly: _SessionAssemblySummary,
        paths: Sequence[_PathState],
        adequacy: str,
    ) -> List[str]:
        if adequacy in {"sufficient_for_refuse", "sufficient_for_allow"}:
            return []

        seen_relations = {
            step.relation
            for path in paths
            for step in path.steps
        }
        missing = []
        if signals.has_multi_agent and "coordinates_agent" not in seen_relations:
            missing.append("no path connects multiple agents to downstream actions")
        if signals.current_relations & ATTACK_PREPARATION_RELATIONS and not seen_relations & ATTACK_PREPARATION_RELATIONS:
            missing.append("no path preserves the current query's attack-planning intent")
        if signals.mentions_guardrail and "bypasses_guardrail" not in seen_relations:
            missing.append("no path shows guardrail evasion around the target")
        if signals.wants_secret and not seen_relations & {"retrieves_data", "exfiltrates_secret"}:
            missing.append("no path connects the request to secret extraction")
        if signals.mentions_payload and "executes_payload" not in seen_relations:
            missing.append("no path shows payload execution")
        if signals.wants_analysis and not seen_relations & {"requests_information", "analyzes_target"}:
            missing.append("no path confirms an analysis-oriented workflow")
        if signals.historical_query_count and not any(
            path.latest_query_steps and path.historical_steps for path in paths
        ):
            missing.append("current query does not yet bridge into the historical session graph")
        if assembly.has_context_alignment and assembly.current_topics and len(assembly.all_phases) < 3:
            missing.append("session has not yet accumulated enough attack-planning phases around the same topic")
        if not assembly.has_context_alignment and signals.historical_query_count:
            missing.append("current query lacks topic or anchor overlap with risky history")
        if not missing:
            missing.append("evidence stays shallow around the initial entities")
        return missing

    def _score_entity_risk(self, entity_name: str) -> Tuple[float, List[str]]:
        lowered = entity_name.lower()
        score = 0.0
        reasons = []
        if self._contains_any(lowered, SECRET_HINTS):
            score += 1.3
            reasons.append("touches a secret-like asset")
        if self._contains_any(lowered, POLICY_HINTS):
            score += 1.0
            reasons.append("touches a policy or guardrail target")
        if self._contains_any(lowered, PAYLOAD_HINTS):
            score += 1.1
            reasons.append("touches a payload or command target")
        if self._contains_any(lowered, PRIVILEGE_HINTS):
            score += 1.0
            reasons.append("touches a privilege-bearing target")
        if self._contains_any(lowered, AGENT_HINTS):
            score += 0.35
            reasons.append("touches a tool or agent entity")
        return score, reasons

    def _score_entity_benign(self, entity_name: str) -> Tuple[float, List[str]]:
        lowered = entity_name.lower()
        score = 0.0
        reasons = []
        if self._contains_any(lowered, ANALYSIS_HINTS):
            score += 0.8
            reasons.append("touches an analysis-style target")
        if self._contains_any(lowered, BENIGN_ENTITY_HINTS):
            score += 0.5
            reasons.append("touches a reporting or documentation target")
        return score, reasons

    def _make_traversal(
        self,
        frontier_id: str,
        edge: GraphEdge,
        node_map: Dict[str, GraphNode],
    ) -> _Traversal:
        if edge.source == frontier_id:
            next_entity_id = edge.target
            direction = "outgoing"
        else:
            next_entity_id = edge.source
            direction = "incoming"
        source_node = node_map[edge.source]
        target_node = node_map[edge.target]
        query_id = edge.attributes.get("query_id", "")
        edge_key = "%s|%s|%s|%s" % (edge.source, edge.relation, edge.target, query_id)
        return _Traversal(
            source_id=edge.source,
            source_name=source_node.name,
            target_id=edge.target,
            target_name=target_node.name,
            relation=edge.relation,
            direction=direction,
            query_id=query_id,
            next_entity_id=next_entity_id,
            next_entity_name=node_map[next_entity_id].name,
            edge_key=edge_key,
        )

    def _beam_rank(self, path: _PathState) -> float:
        return max(path.risk_score, path.benign_score) + 0.35 * path.overall_score

    def _render_path(self, path: ReasoningPath) -> str:
        if not path.steps:
            return path.seed_entity
        parts = []
        for step in path.steps:
            if step.direction == "incoming":
                parts.append("%s <--%s-- %s" % (step.target, step.relation, step.source))
            else:
                parts.append("%s --%s--> %s" % (step.source, step.relation, step.target))
        return " ; ".join(parts)

    def _path_signature(self, steps: Sequence[ReasoningStep]) -> Tuple[str, ...]:
        if not steps:
            return ("<seed>",)
        return tuple(
            "%s|%s|%s|%s" % (step.source, step.relation, step.target, step.direction)
            for step in steps
        )

    def _semantic_path_signature(self, steps: Sequence[ReasoningStep]) -> Tuple[str, ...]:
        if not steps:
            return ("<seed>",)
        return tuple(
            "%s|%s|%s" % (step.source, step.relation, step.target)
            for step in steps
        )

    def _path_has_high_risk_chain(self, path: _PathState) -> bool:
        relations = [step.relation for step in path.steps]
        if "bypasses_guardrail" in relations and "exfiltrates_secret" in relations:
            return True
        if (
            "identifies_target" in relations
            and "discovers_weakness" in relations
            and (
                "plans_execution" in relations
                or "bypasses_guardrail" in relations
                or "exfiltrates_secret" in relations
            )
        ):
            return True
        return any(
            left == "executes_payload" and right == "escalates_privilege"
            for left, right in zip(relations, relations[1:])
        )

    def _path_has_benign_chain(self, path: _PathState) -> bool:
        relations = [step.relation for step in path.steps]
        return any(
            (left, right) in CHAIN_BENIGN_BONUSES
            for left, right in zip(relations, relations[1:])
        )

    def _has_high_risk_chain(self, triples: Sequence[NormalizedTriple]) -> bool:
        relations = {triple.normalized_relation for triple in triples}
        return bool(
            "bypasses_guardrail" in relations and "exfiltrates_secret" in relations
        )

    def _is_explicit_current_query_malicious(
        self,
        *,
        current_relations: Set[str],
        wants_secret: bool,
        mentions_guardrail: bool,
        mentions_payload: bool,
        wants_analysis: bool,
        risk_keyword_score: float,
    ) -> bool:
        current_high_risk_relations = current_relations & HIGH_RISK_RELATIONS
        if len(current_high_risk_relations) >= 2:
            return True
        if current_high_risk_relations and not wants_analysis:
            return True
        if (
            not wants_analysis
            and risk_keyword_score >= 3.0
            and (
                (wants_secret and mentions_guardrail)
                or (wants_secret and mentions_payload)
                or (mentions_guardrail and mentions_payload)
            )
        ):
            return True
        return False

    def _contains_any(self, text: str, markers: Sequence[str]) -> bool:
        lowered = text.lower()
        return any(marker.lower() in lowered for marker in markers)


def _dedupe(values: Sequence[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        cleaned = value.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
    return result
