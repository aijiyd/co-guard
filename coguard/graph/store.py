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

    def upsert_query(
        self,
        query: str,
        triples: List[NormalizedTriple],
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> str:
        raise NotImplementedError

    def get_context_subgraph(
        self,
        query_id: str,
        hops: int = 2,
        limit: int = 24,
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> ContextSubgraph:
        raise NotImplementedError

    def clear_session(self, session_id: str) -> None:
        raise NotImplementedError

    def clear_context(self, context_id: str) -> None:
        raise NotImplementedError

    def export_state(self) -> Dict[str, object]:
        raise NotImplementedError

    def import_state(self, state: Dict[str, object]) -> None:
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

    def upsert_query(
        self,
        query: str,
        triples: List[NormalizedTriple],
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> str:
        # Each query becomes a first-class node so context retrieval can remain
        # query-centric instead of flattening all evidence into entity links.
        self._query_counter += 1
        explicit_context = bool(context_id)
        effective_context_id = context_id or session_id or ""
        query_id = self._query_node_id(
            self._query_counter,
            session_id=session_id,
            context_id=effective_context_id,
        )
        self._ensure_node(
            node_id=query_id,
            kind="query",
            name=query_id,
            attributes={
                "text": query,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id or "",
                "context_id": effective_context_id,
            },
        )

        for triple in triples:
            subject_profile = self._entity_profile(triple.subject)
            object_profile = self._entity_profile(triple.object)
            subject_id = self._entity_node_id(
                triple.subject,
                session_id=session_id,
                context_id=effective_context_id,
            )
            object_id = self._entity_node_id(
                triple.object,
                session_id=session_id,
                context_id=effective_context_id,
            )
            self._ensure_node(
                subject_id,
                "entity",
                triple.subject,
                {
                    "entity_type": subject_profile.entity_type,
                    "session_id": "" if explicit_context else session_id or "",
                    "context_id": effective_context_id,
                },
            )
            self._ensure_node(
                object_id,
                "entity",
                triple.object,
                {
                    "entity_type": object_profile.entity_type,
                    "session_id": "" if explicit_context else session_id or "",
                    "context_id": effective_context_id,
                },
            )
            self._add_edge(
                query_id,
                subject_id,
                "mentions",
                {
                    "role": "subject",
                    "session_id": session_id or "",
                    "context_id": effective_context_id,
                },
            )
            self._add_edge(
                query_id,
                object_id,
                "mentions",
                {
                    "role": "object",
                    "session_id": session_id or "",
                    "context_id": effective_context_id,
                },
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
                    "session_id": session_id or "",
                    "context_id": effective_context_id,
                },
            )
        return query_id

    def get_context_subgraph(
        self,
        query_id: str,
        hops: int = 2,
        limit: int = 24,
        session_id: str | None = None,
        context_id: str | None = None,
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
                    edge = self._edges[edge_index]
                    if not self._matches_session_attributes(
                        edge.attributes,
                        session_id=session_id,
                        context_id=context_id,
                    ):
                        continue
                    neighbor = edge.target if edge.source == node_id else edge.source
                    if not self._matches_session_attributes(
                        self._nodes[neighbor].attributes,
                        session_id=session_id,
                        context_id=context_id,
                    ):
                        continue
                    visited_edges.add(edge_index)
                    if neighbor not in visited_nodes and len(node_order) < limit:
                        visited_nodes.add(neighbor)
                        node_order.append(neighbor)
                        next_frontier.add(neighbor)
            frontier = next_frontier
            if not frontier or len(node_order) >= limit:
                break

        self._expand_with_related_entities(
            visited_nodes,
            visited_edges,
            node_order,
            limit,
            session_id=session_id,
            context_id=context_id,
        )

        nodes = [self._nodes[node_id] for node_id in node_order]
        edges = [
            self._edges[index]
            for index in sorted(visited_edges)
            if self._edges[index].source in visited_nodes
            and self._edges[index].target in visited_nodes
            and self._matches_session_attributes(
                self._edges[index].attributes,
                session_id=session_id,
                context_id=context_id,
            )
        ]
        return ContextSubgraph(nodes=nodes, edges=edges)

    def clear_session(self, session_id: str) -> None:
        # Rebuild the in-memory graph without the selected session.
        kept_nodes = {
            node_id: node
            for node_id, node in self._nodes.items()
            if not self._matches_session_attributes(node.attributes, session_id=session_id)
        }
        kept_edges = [
            edge
            for edge in self._edges
            if not self._matches_session_attributes(edge.attributes, session_id=session_id)
        ]
        self._rebuild_graph(kept_nodes, kept_edges)

    def clear_context(self, context_id: str) -> None:
        kept_nodes = {
            node_id: node
            for node_id, node in self._nodes.items()
            if not self._matches_session_attributes(node.attributes, context_id=context_id)
        }
        kept_edges = [
            edge
            for edge in self._edges
            if not self._matches_session_attributes(edge.attributes, context_id=context_id)
        ]
        self._rebuild_graph(kept_nodes, kept_edges)

    def export_state(self) -> Dict[str, object]:
        return {
            "query_counter": self._query_counter,
            "nodes": [
                {
                    "node_id": node.node_id,
                    "kind": node.kind,
                    "name": node.name,
                    "attributes": dict(node.attributes),
                }
                for node in self._nodes.values()
            ],
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "relation": edge.relation,
                    "attributes": dict(edge.attributes),
                }
                for edge in self._edges
            ],
        }

    def import_state(self, state: Dict[str, object]) -> None:
        self._query_counter = int(state.get("query_counter", 0))
        nodes = {
            str(item["node_id"]): GraphNode(
                node_id=str(item["node_id"]),
                kind=str(item["kind"]),
                name=str(item["name"]),
                attributes={str(k): str(v) for k, v in dict(item.get("attributes", {})).items()},
            )
            for item in list(state.get("nodes", []))
            if isinstance(item, dict) and "node_id" in item
        }
        edges = [
            GraphEdge(
                source=str(item["source"]),
                target=str(item["target"]),
                relation=str(item["relation"]),
                attributes={str(k): str(v) for k, v in dict(item.get("attributes", {})).items()},
            )
            for item in list(state.get("edges", []))
            if isinstance(item, dict) and "source" in item and "target" in item and "relation" in item
        ]
        self._entity_profiles = {}
        self._rebuild_graph(nodes, edges)

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
        session_id: str | None = None,
        context_id: str | None = None,
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
                if not self._matches_session_attributes(
                    candidate_node.attributes,
                    session_id=session_id,
                    context_id=context_id,
                ):
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
                edge = self._edges[edge_index]
                if not self._matches_session_attributes(
                    edge.attributes,
                    session_id=session_id,
                    context_id=context_id,
                ):
                    continue
                neighbor = edge.target if edge.source == candidate_id else edge.source
                if not self._matches_session_attributes(
                    self._nodes[neighbor].attributes,
                    session_id=session_id,
                    context_id=context_id,
                ):
                    continue
                visited_edges.add(edge_index)
                if neighbor not in visited_nodes and len(node_order) < limit:
                    visited_nodes.add(neighbor)
                    node_order.append(neighbor)

    def _entity_node_id(
        self,
        name: str,
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> str:
        digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:12]
        scope_id = context_id or session_id
        if scope_id:
            return "entity-%s-%s" % (scope_id, digest)
        return "entity-%s" % digest

    def _query_node_id(
        self,
        query_index: int,
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> str:
        query_id = "query-%04d" % query_index
        scope_id = session_id or context_id
        if scope_id:
            return "%s::%s" % (scope_id, query_id)
        return query_id

    def _matches_session_attributes(
        self,
        attributes: Dict[str, str],
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> bool:
        if context_id:
            return attributes.get("context_id", "") == context_id
        if not session_id:
            return True
        return attributes.get("session_id", "") == session_id

    def _rebuild_graph(
        self,
        kept_nodes: Dict[str, GraphNode],
        kept_edges: List[GraphEdge],
    ) -> None:
        referenced_node_ids = set()
        for edge in kept_edges:
            referenced_node_ids.add(edge.source)
            referenced_node_ids.add(edge.target)
        self._nodes = {
            node_id: node
            for node_id, node in kept_nodes.items()
            if node.kind == "query" or node_id in referenced_node_ids
        }
        self._edges = kept_edges
        self._adjacency = {node_id: set() for node_id in self._nodes}
        for edge_index, edge in enumerate(self._edges):
            if edge.source in self._adjacency:
                self._adjacency[edge.source].add(edge_index)
            if edge.target in self._adjacency:
                self._adjacency[edge.target].add(edge_index)

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

    def upsert_query(
        self,
        query: str,
        triples: List[NormalizedTriple],
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> str:
        explicit_context = bool(context_id)
        effective_context_id = context_id or session_id or ""
        query_id = self._query_node_id(
            query,
            session_id=session_id,
            context_id=effective_context_id,
        )
        triple_rows = [
            {
                "subject": triple.subject,
                "subject_id": self._entity_node_id(
                    triple.subject,
                    session_id=session_id,
                    context_id=effective_context_id,
                ),
                "subject_type": build_entity_profile(triple.subject).entity_type,
                "object": triple.object,
                "object_id": self._entity_node_id(
                    triple.object,
                    session_id=session_id,
                    context_id=effective_context_id,
                ),
                "object_type": build_entity_profile(triple.object).entity_type,
                "normalized_relation": triple.normalized_relation,
                "raw_relation": triple.raw_relation,
                "confidence": float("%.3f" % triple.confidence),
                "cluster_id": triple.cluster_id,
                "session_id": session_id or "",
                "context_id": effective_context_id,
                "explicit_context": explicit_context,
            }
            for triple in triples
        ]
        with self._driver.session(database=self._database) as session:
            session.execute_write(
                self._write_query,
                query_id,
                query,
                triple_rows,
                session_id or "",
                effective_context_id,
            )
        return query_id

    def get_context_subgraph(
        self,
        query_id: str,
        hops: int = 2,
        limit: int = 24,
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> ContextSubgraph:
        # Neo4j retrieval mirrors the in-memory contract and converts database
        # rows back into shared dataclasses for the reasoner.
        safe_hops = max(1, int(hops))
        scope_field = "context_id" if context_id else "session_id"
        scope_value = context_id or session_id or ""
        cypher = (
            """
        MATCH (q:Query {id: $query_id, %s: $scope_value})
        OPTIONAL MATCH p=(q)-[*1..%d]-(n)
        WHERE all(node IN nodes(p) WHERE coalesce(node.%s, '') = $scope_value)
        WITH collect(DISTINCT q) + collect(DISTINCT n) AS raw_nodes
        WITH [node IN raw_nodes WHERE node IS NOT NULL][..$limit] AS nodes
        UNWIND nodes AS node
        OPTIONAL MATCH (node)-[r]-(neighbor)
        WHERE neighbor IN nodes
          AND coalesce(node.%s, '') = $scope_value
          AND coalesce(neighbor.%s, '') = $scope_value
          AND coalesce(r.%s, '') = $scope_value
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
            % (
                scope_field,
                safe_hops,
                scope_field,
                scope_field,
                scope_field,
                scope_field,
            )
        )
        with self._driver.session(database=self._database) as session:
            row = session.run(
                cypher,
                query_id=query_id,
                scope_value=scope_value,
                limit=limit,
            ).single()
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

    def clear_session(self, session_id: str) -> None:
        with self._driver.session(database=self._database) as session:
            session.execute_write(self._delete_session, session_id)

    def clear_context(self, context_id: str) -> None:
        with self._driver.session(database=self._database) as session:
            session.execute_write(self._delete_context, context_id)

    def export_state(self) -> Dict[str, object]:
        raise RuntimeError("Neo4j graph store does not support in-process checkpoint export.")

    def import_state(self, state: Dict[str, object]) -> None:
        del state
        raise RuntimeError("Neo4j graph store does not support in-process checkpoint import.")

    @staticmethod
    def _write_query(
        tx,
        query_id: str,
        query_text: str,
        triples: List[Dict[str, object]],
        session_id: str,
        context_id: str,
    ) -> None:
        # Query and entity nodes are MERGE'd so historical context can
        # accumulate across runs without extra schema management.
        tx.run(
            """
            MERGE (q:Query {id: $query_id})
            SET q.text = $query_text,
                q.name = $query_id,
                q.created_at = $created_at,
                q.session_id = $session_id,
                q.context_id = $context_id
            """,
            query_id=query_id,
            query_text=query_text,
            created_at=datetime.now(timezone.utc).isoformat(),
            session_id=session_id,
            context_id=context_id,
        )
        for triple in triples:
            tx.run(
                """
                MATCH (q:Query {id: $query_id})
                MERGE (s:Entity {id: $subject_id, context_id: $context_id})
                SET s.name = $subject,
                    s.entity_type = $subject_type,
                    s.session_id = $entity_session_id
                MERGE (o:Entity {id: $object_id, context_id: $context_id})
                SET o.name = $object,
                    o.entity_type = $object_type,
                    o.session_id = $entity_session_id
                MERGE (q)-[:MENTIONS {role: 'subject', session_id: $session_id, context_id: $context_id}]->(s)
                MERGE (q)-[:MENTIONS {role: 'object', session_id: $session_id, context_id: $context_id}]->(o)
                MERGE (s)-[r:RELATION {
                  query_id: $query_id,
                  session_id: $session_id,
                  context_id: $context_id,
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
                session_id=triple["session_id"],
                context_id=triple["context_id"],
                entity_session_id="" if triple["explicit_context"] else triple["session_id"],
            )

    @staticmethod
    def _entity_node_id(
        name: str,
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> str:
        digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:12]
        scope_id = context_id or session_id
        if scope_id:
            return "entity-%s-%s" % (scope_id, digest)
        return "entity-%s" % digest

    @staticmethod
    def _query_node_id(
        query: str,
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> str:
        digest = hashlib.sha1(
            ("%s|%s" % (query, datetime.now(timezone.utc).isoformat())).encode("utf-8")
        ).hexdigest()[:12]
        query_id = "query-%s" % digest
        scope_id = session_id or context_id
        if scope_id:
            return "%s::%s" % (scope_id, query_id)
        return query_id

    @staticmethod
    def _delete_session(tx, session_id: str) -> None:
        tx.run(
            """
            MATCH ()-[r {session_id: $session_id}]-()
            DELETE r
            """,
            session_id=session_id,
        )
        tx.run(
            """
            MATCH (n:Query {session_id: $session_id})
            DETACH DELETE n
            """,
            session_id=session_id,
        )
        tx.run(
            """
            MATCH (e:Entity)
            WHERE NOT (e)--()
            DELETE e
            """,
        )

    @staticmethod
    def _delete_context(tx, context_id: str) -> None:
        tx.run(
            """
            MATCH (n {context_id: $context_id})
            DETACH DELETE n
            """,
            context_id=context_id,
        )
