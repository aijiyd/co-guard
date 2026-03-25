from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from ..config import AppConfig
from ..models import ContextSubgraph, GraphEdge, GraphNode, NormalizedTriple
from .entity_similarity import EntityProfile, build_entity_profile, entity_relatedness_score

try:
    from neo4j import GraphDatabase
except ImportError:  # pragma: no cover - optional dependency
    GraphDatabase = None


class BaseGraphStore:
    backend_name = "memory"

    def upsert_query(self, query: str, triples: List[NormalizedTriple]) -> str:
        raise NotImplementedError

    def get_context_subgraph(
        self, query_id: str, hops: int = 2, limit: int = 24
    ) -> ContextSubgraph:
        raise NotImplementedError


class InMemoryGraphStore(BaseGraphStore):
    backend_name = "memory"

    def __init__(self, config: Optional[AppConfig] = None) -> None:
        # The in-memory backend is the reference implementation: small,
        # deterministic, and easy to inspect during experiments.
        self.config = config or AppConfig()
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adjacency: Dict[str, Set[int]] = {}
        self._entity_profiles: Dict[str, EntityProfile] = {}
        self._query_counter = 0

    def upsert_query(self, query: str, triples: List[NormalizedTriple]) -> str:
        # Each query becomes a first-class node so context retrieval can remain
        # query-centric instead of flattening all evidence into entity links.
        self._query_counter += 1
        query_id = "query-%04d" % self._query_counter
        self._ensure_node(
            node_id=query_id,
            kind="query",
            name=query_id,
            attributes={
                "text": query,
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )

        for triple in triples:
            subject_profile = self._entity_profile(triple.subject)
            object_profile = self._entity_profile(triple.object)
            subject_id = self._entity_node_id(triple.subject)
            object_id = self._entity_node_id(triple.object)
            self._ensure_node(
                subject_id,
                "entity",
                triple.subject,
                {"entity_type": subject_profile.entity_type},
            )
            self._ensure_node(
                object_id,
                "entity",
                triple.object,
                {"entity_type": object_profile.entity_type},
            )
            self._add_edge(
                query_id,
                subject_id,
                "mentions",
                {"role": "subject"},
            )
            self._add_edge(
                query_id,
                object_id,
                "mentions",
                {"role": "object"},
            )
            self._add_edge(
                subject_id,
                object_id,
                triple.normalized_relation,
                {
                    # Provenance fields help tie graph evidence back to the parse
                    # result that created it.
                    "query_id": query_id,
                    "raw_relation": triple.raw_relation,
                    "confidence": "%.3f" % triple.confidence,
                    "cluster_id": str(triple.cluster_id),
                },
            )
        return query_id

    def get_context_subgraph(
        self, query_id: str, hops: int = 2, limit: int = 24
    ) -> ContextSubgraph:
        # Retrieval first does graph-local BFS, then optionally broadens with
        # entity-similarity expansion to recover aliases and close variants.
        if query_id not in self._nodes:
            return ContextSubgraph()

        visited_nodes = {query_id}
        frontier = {query_id}
        visited_edges = set()
        node_order = [query_id]

        for _ in range(hops):
            next_frontier = set()
            for node_id in frontier:
                for edge_index in self._adjacency.get(node_id, set()):
                    visited_edges.add(edge_index)
                    edge = self._edges[edge_index]
                    neighbor = edge.target if edge.source == node_id else edge.source
                    if neighbor not in visited_nodes and len(node_order) < limit:
                        visited_nodes.add(neighbor)
                        node_order.append(neighbor)
                        next_frontier.add(neighbor)
            frontier = next_frontier
            if not frontier or len(node_order) >= limit:
                break

        self._expand_with_related_entities(visited_nodes, visited_edges, node_order, limit)

        nodes = [self._nodes[node_id] for node_id in node_order]
        edges = [
            self._edges[index]
            for index in sorted(visited_edges)
            if self._edges[index].source in visited_nodes
            and self._edges[index].target in visited_nodes
        ]
        return ContextSubgraph(nodes=nodes, edges=edges)

    def _ensure_node(
        self,
        node_id: str,
        kind: str,
        name: str,
        attributes: Optional[Dict[str, str]] = None,
    ) -> None:
        if node_id in self._nodes:
            return
        self._nodes[node_id] = GraphNode(
            node_id=node_id,
            kind=kind,
            name=name,
            attributes=attributes or {},
        )
        self._adjacency.setdefault(node_id, set())

    def _add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        attributes: Optional[Dict[str, str]] = None,
    ) -> None:
        edge = GraphEdge(source=source, target=target, relation=relation, attributes=attributes or {})
        self._edges.append(edge)
        edge_index = len(self._edges) - 1
        self._adjacency.setdefault(source, set()).add(edge_index)
        self._adjacency.setdefault(target, set()).add(edge_index)

    def _expand_with_related_entities(
        self,
        visited_nodes: Set[str],
        visited_edges: Set[int],
        node_order: List[str],
        limit: int,
    ) -> None:
        # Expansion only pulls in one hop around related entities so recall
        # improves without flooding the subgraph with distant noise.
        entity_nodes = [
            self._nodes[node_id]
            for node_id in list(visited_nodes)
            if self._nodes[node_id].kind == "entity"
        ]
        candidate_scores: Dict[str, float] = {}
        for seed_node in entity_nodes:
            seed_profile = self._entity_profile(seed_node.name)
            for candidate_id, candidate_node in self._nodes.items():
                if candidate_id in visited_nodes or candidate_node.kind != "entity":
                    continue
                score = entity_relatedness_score(
                    seed_profile,
                    self._entity_profile(candidate_node.name),
                )
                if score < self.config.entity_relatedness_threshold:
                    continue
                current_score = candidate_scores.get(candidate_id, 0.0)
                if score > current_score:
                    candidate_scores[candidate_id] = score

        for candidate_id, _score in sorted(
            candidate_scores.items(),
            key=lambda item: (-item[1], self._nodes[item[0]].name),
        ):
            if len(node_order) >= limit:
                return
            visited_nodes.add(candidate_id)
            node_order.append(candidate_id)
            for edge_index in self._adjacency.get(candidate_id, set()):
                visited_edges.add(edge_index)
                edge = self._edges[edge_index]
                neighbor = edge.target if edge.source == candidate_id else edge.source
                if neighbor not in visited_nodes and len(node_order) < limit:
                    visited_nodes.add(neighbor)
                    node_order.append(neighbor)

    def _entity_node_id(self, name: str) -> str:
        digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:12]
        return "entity-%s" % digest

    def _entity_profile(self, name: str) -> EntityProfile:
        if name not in self._entity_profiles:
            self._entity_profiles[name] = build_entity_profile(name)
        return self._entity_profiles[name]


class Neo4jGraphStore(BaseGraphStore):  # pragma: no cover - optional backend
    backend_name = "neo4j"

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        database: str = "neo4j",
    ) -> None:
        if GraphDatabase is None:
            raise RuntimeError("neo4j package is not installed.")
        self._driver = GraphDatabase.driver(uri, auth=(username, password))
        self._database = database

    @classmethod
    def from_config(cls, config: AppConfig) -> "Neo4jGraphStore":
        if not config.neo4j_uri or not config.neo4j_username or not config.neo4j_password:
            raise RuntimeError("Neo4j credentials are incomplete.")
        return cls(
            uri=config.neo4j_uri,
            username=config.neo4j_username,
            password=config.neo4j_password,
            database=config.neo4j_database,
        )

    def close(self) -> None:
        self._driver.close()

    def upsert_query(self, query: str, triples: List[NormalizedTriple]) -> str:
        query_id = "query-%s" % hashlib.sha1(
            ("%s|%s" % (query, datetime.now(timezone.utc).isoformat())).encode("utf-8")
        ).hexdigest()[:12]
        triple_rows = [
            {
                "subject": triple.subject,
                "subject_id": self._entity_node_id(triple.subject),
                "subject_type": build_entity_profile(triple.subject).entity_type,
                "object": triple.object,
                "object_id": self._entity_node_id(triple.object),
                "object_type": build_entity_profile(triple.object).entity_type,
                "normalized_relation": triple.normalized_relation,
                "raw_relation": triple.raw_relation,
                "confidence": float("%.3f" % triple.confidence),
                "cluster_id": triple.cluster_id,
            }
            for triple in triples
        ]
        with self._driver.session(database=self._database) as session:
            session.execute_write(self._write_query, query_id, query, triple_rows)
        return query_id

    def get_context_subgraph(
        self, query_id: str, hops: int = 2, limit: int = 24
    ) -> ContextSubgraph:
        # Neo4j retrieval mirrors the in-memory contract and converts database
        # rows back into shared dataclasses for the reasoner.
        safe_hops = max(1, int(hops))
        cypher = (
            """
        MATCH (q:Query {id: $query_id})
        OPTIONAL MATCH p=(q)-[*1..%d]-(n)
        WITH collect(DISTINCT q) + collect(DISTINCT n) AS raw_nodes
        WITH [node IN raw_nodes WHERE node IS NOT NULL][..$limit] AS nodes
        UNWIND nodes AS node
        OPTIONAL MATCH (node)-[r]-(neighbor)
        WHERE neighbor IN nodes
        RETURN
          collect(DISTINCT {
            node_id: node.id,
            kind: CASE WHEN 'Query' IN labels(node) THEN 'query' ELSE 'entity' END,
            name: coalesce(node.name, node.text, node.id),
            attributes: properties(node)
          }) AS node_rows,
          collect(DISTINCT {
            source: startNode(r).id,
            target: endNode(r).id,
            relation: coalesce(r.normalized_relation, type(r)),
            attributes: properties(r)
          }) AS edge_rows
        """
            % safe_hops
        )
        with self._driver.session(database=self._database) as session:
            row = session.run(cypher, query_id=query_id, limit=limit).single()
        if not row:
            return ContextSubgraph()
        nodes = [
            GraphNode(
                node_id=node_row["node_id"],
                kind=node_row["kind"],
                name=node_row["name"],
                attributes=dict(node_row["attributes"] or {}),
            )
            for node_row in row["node_rows"]
            if node_row["node_id"]
        ]
        edges = [
            GraphEdge(
                source=edge_row["source"],
                target=edge_row["target"],
                relation=edge_row["relation"],
                attributes=dict(edge_row["attributes"] or {}),
            )
            for edge_row in row["edge_rows"]
            if edge_row["source"] and edge_row["target"]
        ]
        return ContextSubgraph(nodes=nodes, edges=edges)

    @staticmethod
    def _write_query(
        tx,
        query_id: str,
        query_text: str,
        triples: List[Dict[str, object]],
    ) -> None:
        # Query and entity nodes are MERGE'd so historical context can
        # accumulate across runs without extra schema management.
        tx.run(
            """
            MERGE (q:Query {id: $query_id})
            SET q.text = $query_text,
                q.name = $query_id,
                q.created_at = $created_at
            """,
            query_id=query_id,
            query_text=query_text,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        for triple in triples:
            tx.run(
                """
                MATCH (q:Query {id: $query_id})
                MERGE (s:Entity {id: $subject_id})
                SET s.name = $subject,
                    s.entity_type = $subject_type
                MERGE (o:Entity {id: $object_id})
                SET o.name = $object,
                    o.entity_type = $object_type
                MERGE (q)-[:MENTIONS {role: 'subject'}]->(s)
                MERGE (q)-[:MENTIONS {role: 'object'}]->(o)
                MERGE (s)-[r:RELATION {
                  query_id: $query_id,
                  raw_relation: $raw_relation,
                  normalized_relation: $normalized_relation,
                  object_id: $object_id
                }]->(o)
                SET r.confidence = $confidence,
                    r.cluster_id = $cluster_id
                """,
                query_id=query_id,
                subject=triple["subject"],
                subject_id=triple["subject_id"],
                subject_type=triple["subject_type"],
                object=triple["object"],
                object_id=triple["object_id"],
                object_type=triple["object_type"],
                raw_relation=triple["raw_relation"],
                normalized_relation=triple["normalized_relation"],
                confidence=triple["confidence"],
                cluster_id=triple["cluster_id"],
            )

    @staticmethod
    def _entity_node_id(name: str) -> str:
        digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:12]
        return "entity-%s" % digest
