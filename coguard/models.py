from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class RawTriple:
    """Open IE style triple before relation canonicalization."""

    subject: str
    relation: str
    object: str


@dataclass
class SchemaRelation:
    """One canonical relation definition in the shared schema."""

    name: str
    definition: str
    example_text: str = ""
    example_triple: List[str] = field(default_factory=list)


@dataclass
class RelationCandidate:
    """Schema candidate surfaced during retrieval or verification."""

    name: str
    definition: str
    score: float


@dataclass
class CanonicalizationItem:
    """One relation-normalization decision prepared for batch verification."""

    triple: RawTriple
    relation_definition: str
    candidates: List[RelationCandidate] = field(default_factory=list)


@dataclass
class NormalizedTriple:
    """Triple after definition, canonicalization, and relation clustering."""

    subject: str
    raw_relation: str
    object: str
    relation_definition: str
    normalized_relation: str
    confidence: float
    cluster_id: int = 0
    candidate_relations: List[RelationCandidate] = field(default_factory=list)


@dataclass
class GraphNode:
    """Graph node used in context retrieval and reasoning."""

    node_id: str
    kind: str
    name: str
    attributes: Dict[str, str] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Graph edge plus lightweight provenance attributes."""

    source: str
    target: str
    relation: str
    attributes: Dict[str, str] = field(default_factory=dict)


@dataclass
class ContextSubgraph:
    """Bounded local evidence graph centered on the current query."""

    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)


@dataclass
class ReasoningStep:
    """One traversed hop in a reasoning path."""

    source: str
    relation: str
    target: str
    direction: str = "outgoing"
    query_id: str = ""


@dataclass
class ReasoningPath:
    """Public reasoning path returned as risk or counter-evidence."""

    seed_entity: str
    frontier_entity: str
    steps: List[ReasoningStep] = field(default_factory=list)
    risk_score: float = 0.0
    benign_score: float = 0.0
    overall_score: float = 0.0
    label: str = "mixed"
    reasons: List[str] = field(default_factory=list)


@dataclass
class LLMGraphJudgment:
    """Structured LLM review returned by the graph reasoning adapter."""

    malicious: bool
    score: float
    confidence: float
    adequacy: str
    reasons: List[str] = field(default_factory=list)


@dataclass
class QueryAnalysisResult:
    """End-to-end pipeline output for a single user query."""

    query_id: str
    query: str
    triples: List[NormalizedTriple]
    context: ContextSubgraph
    context_description: str
    malicious: bool
    decision: str
    score: float
    reasons: List[str] = field(default_factory=list)
    reasoning_mode: str = "rules"
    adequacy: str = "insufficient"
    evidence_paths: List[ReasoningPath] = field(default_factory=list)
    counter_evidence_paths: List[ReasoningPath] = field(default_factory=list)
    missing_links: List[str] = field(default_factory=list)
    graph_backend: str = "memory"
    session_id: str = ""
    context_id: str = ""
    assembly_chain_score: float = 0.0
    assembly_current_advances_chain: bool = False
    assembly_current_closes_chain: bool = False
    assembly_current_phases: List[str] = field(default_factory=list)
    assembly_historical_phases: List[str] = field(default_factory=list)
    assembly_current_topics: List[str] = field(default_factory=list)
    assembly_historical_topics: List[str] = field(default_factory=list)
    assembly_shared_topics: List[str] = field(default_factory=list)
    assembly_reasons: List[str] = field(default_factory=list)
    assembly_timeline: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
