from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Set, Tuple

from ..config import AppConfig
from ..models import (
    ContextSubgraph,
    GraphEdge,
    GraphNode,
    NormalizedTriple,
    ReasoningPath,
    ReasoningStep,
)
from ..semantic import BaseLLMAdapter


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
    reasons: List[str] = field(default_factory=list)
    visited_entities: Set[str] = field(default_factory=set)
    visited_edges: Set[str] = field(default_factory=set)

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


class Reasoner:
    def __init__(
        self,
        llm_adapter: BaseLLMAdapter,
        config: AppConfig | None = None,
    ) -> None:
        self.llm_adapter = llm_adapter
        self.config = config or AppConfig()

    def describe_context(self, context: ContextSubgraph) -> str:
        return self.llm_adapter.describe_subgraph(context)

    def assess(
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
        signals = self._build_query_signals(query, triples, context_description)
        node_map, adjacency = self._build_search_graph(context)
        active_paths = self._build_initial_paths(query_id, triples, context, node_map)
        all_selected_paths = list(active_paths)
        adequacy = "insufficient"

        direct_high_risk_chain = self._has_high_risk_chain(triples)

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
            paths=all_selected_paths,
            adequacy=adequacy,
        )
        score = self._final_score(
            signals=signals,
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
            adequacy=adequacy,
            evidence_paths=evidence_paths,
            counter_evidence_paths=counter_evidence_paths,
            missing_links=missing_links,
            malicious=malicious,
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
        )

    def _build_query_signals(
        self,
        query: str,
        triples: Sequence[NormalizedTriple],
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
                    reasons=_dedupe(risk_reasons + benign_reasons),
                    visited_entities={node_id},
                    visited_edges=set(),
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
        reasons = list(base_path.reasons) + list(relation_reasons)

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

        overall_score = risk_score - benign_score + relevance
        return _PathState(
            seed_entity=base_path.seed_entity,
            frontier_id=traversal.next_entity_id,
            frontier_name=traversal.next_entity_name,
            steps=base_path.steps + [step],
            risk_score=risk_score,
            benign_score=benign_score,
            overall_score=overall_score,
            reasons=_dedupe(reasons),
            visited_entities=set(base_path.visited_entities) | {traversal.next_entity_id},
            visited_edges=set(base_path.visited_edges) | {traversal.edge_key},
        )

    def _judge_adequacy(
        self,
        paths: Sequence[_PathState],
        signals: _QuerySignals,
        direct_high_risk_chain: bool,
        depth: int,
        can_expand: bool,
    ) -> str:
        if not paths:
            return "uncertain"

        strongest_risk = max(path.risk_score for path in paths)
        strongest_benign = max(path.benign_score for path in paths)
        has_high_risk_path = any(self._path_has_high_risk_chain(path) for path in paths)
        has_benign_path = any(self._path_has_benign_chain(path) for path in paths)

        if direct_high_risk_chain or has_high_risk_path:
            return "sufficient_for_refuse"
        if (
            strongest_risk >= self.config.reasoning_risk_evidence_threshold
            and strongest_risk >= strongest_benign + 0.5
        ):
            return "sufficient_for_refuse"
        if (
            strongest_benign >= self.config.reasoning_benign_evidence_threshold
            and strongest_risk < self.config.reasoning_risk_evidence_threshold - 1.0
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
        evidence_paths: Sequence[ReasoningPath],
        counter_evidence_paths: Sequence[ReasoningPath],
        adequacy: str,
        direct_high_risk_chain: bool,
    ) -> float:
        strongest_risk = evidence_paths[0].risk_score if evidence_paths else 0.0
        strongest_benign = counter_evidence_paths[0].benign_score if counter_evidence_paths else 0.0
        score = signals.risk_keyword_score - signals.benign_keyword_score
        score += strongest_risk
        score -= 0.75 * strongest_benign
        if adequacy == "sufficient_for_refuse":
            score += 0.75
        elif adequacy == "sufficient_for_allow":
            score -= 0.75
        if direct_high_risk_chain:
            score += 1.5
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
        adequacy: str,
        evidence_paths: Sequence[ReasoningPath],
        counter_evidence_paths: Sequence[ReasoningPath],
        missing_links: Sequence[str],
        malicious: bool,
    ) -> List[str]:
        reasons = list(signals.keyword_reasons)
        if evidence_paths:
            reasons.append("risk path: %s" % self._render_path(evidence_paths[0]))
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
        if signals.mentions_guardrail and "bypasses_guardrail" not in seen_relations:
            missing.append("no path shows guardrail evasion around the target")
        if signals.wants_secret and not seen_relations & {"retrieves_data", "exfiltrates_secret"}:
            missing.append("no path connects the request to secret extraction")
        if signals.mentions_payload and "executes_payload" not in seen_relations:
            missing.append("no path shows payload execution")
        if signals.wants_analysis and not seen_relations & {"requests_information", "analyzes_target"}:
            missing.append("no path confirms an analysis-oriented workflow")
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
