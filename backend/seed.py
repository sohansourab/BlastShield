"""Phase 1 — BlastShield FalkorDB connection & seeding.

Stands up the SecOps cloud topology inside FalkorDB under the graph key
``secops_graph``. Safe to re-run: the target graph is cleared first, so the
seed is deterministic and idempotent.

Canonical graph:
    (Alert:ALT-9021) -[:TARGETS]-> (Workload:pod-payment-gateway)
    (Workload) -[:USES_SG]-> (SecurityGroup:sg-payment-cluster)
    (Workload) -[:ASSUMES_ROLE]-> (IAMRole:PaymentProcessorRole)
    (IAMRole) -[:CAN_ACCESS]-> (DataStore:s3-customer-pii-vault [RESTRICTED_PII])
    (IAMRole) -[:CAN_ACCESS]-> (DataStore:rds-billing-logs [INTERNAL])
    (Commit:4f9a2b) -[:DEPLOYED_TO]-> (Workload)
    (User:Alex Engineer) -[:AUTHORED]-> (Commit)

Usage:
    python backend/seed.py
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

try:  # optional: load backend/.env regardless of the current working directory
    from dotenv import load_dotenv

    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except Exception:  # pragma: no cover - dotenv is optional at runtime
    pass

from falkordb import FalkorDB

GRAPH_NAME: str = os.getenv("FALKORDB_GRAPH", "secops_graph")
FALKORDB_HOST: str = os.getenv("FALKORDB_HOST", "localhost")
FALKORDB_PORT: int = int(os.getenv("FALKORDB_PORT", "6379"))

# --------------------------------------------------------------------------- #
# Topology definition
# --------------------------------------------------------------------------- #
# Every node carries an explicit ``type`` property (in addition to its Cypher
# label) so the API/frontend can reason about it without parsing labels.

NODES: List[Tuple[str, Dict[str, Any]]] = [
    (
        "Alert",
        {
            "id": "ALT-9021",
            "type": "Alert",
            "name": "ALT-9021",
            "title": "Anomalous egress from payment workload to restricted datastore",
            "severity": "CRITICAL",
            "status": "OPEN",
            "source": "GuardDuty EKS Runtime Monitoring",
            "detected_at": "2026-10-17T02:14:07Z",
        },
    ),
    (
        "Workload",
        {
            "id": "pod-payment-gateway",
            "type": "Workload",
            "name": "pod-payment-gateway",
            "namespace": "payments",
            "kind": "Deployment",
            "status": "RUNNING",
            "replicas": 6,
            "image": "registry.internal/payment-gateway:2.7.1",
            "node_pool": "prod-general",
            "region": "us-east-1",
        },
    ),
    (
        "SecurityGroup",
        {
            "id": "sg-payment-cluster",
            "type": "SecurityGroup",
            "name": "sg-payment-cluster",
            "inbound_rule": "0.0.0.0/0:443",
            "vpc": "vpc-prod-9f12",
            "region": "us-east-1",
        },
    ),
    (
        "IAMRole",
        {
            "id": "PaymentProcessorRole",
            "type": "IAMRole",
            "name": "PaymentProcessorRole",
            "arn": "arn:aws:iam::111122223333:role/PaymentProcessorRole",
            "status": "ACTIVE",
            "max_session_duration": 3600,
        },
    ),
    (
        "DataStore",
        {
            "id": "s3-customer-pii-vault",
            "type": "DataStore",
            "name": "s3-customer-pii-vault",
            "service": "s3",
            "classification": "RESTRICTED_PII",
            "record_count": 4213550,
            "encrypted": True,
            "region": "us-east-1",
        },
    ),
    (
        "DataStore",
        {
            "id": "rds-billing-logs",
            "type": "DataStore",
            "name": "rds-billing-logs",
            "service": "rds",
            "classification": "INTERNAL",
            "record_count": 812400,
            "encrypted": True,
            "region": "us-east-1",
        },
    ),
    (
        "Commit",
        {
            "id": "commit-4f9a2b",
            "type": "Commit",
            "name": "4f9a2b",
            "sha": "4f9a2b",
            "message": "hotfix: widen payment SG + grant s3 vault read to processor role",
            "authored_by": "Alex Engineer",
            "committed_at": "2026-10-16T23:41:12Z",
            "branch": "release/2.7.1",
        },
    ),
    (
        "User",
        {
            "id": "user-alex",
            "type": "User",
            "name": "Alex Engineer",
            "email": "alex.engineer@example.com",
            "team": "Payments Platform",
            "mfa_enabled": True,
        },
    ),
]

# (relationship type, source id, target id)
EDGES: List[Tuple[str, str, str]] = [
    ("TARGETS", "ALT-9021", "pod-payment-gateway"),
    ("USES_SG", "pod-payment-gateway", "sg-payment-cluster"),
    ("ASSUMES_ROLE", "pod-payment-gateway", "PaymentProcessorRole"),
    ("CAN_ACCESS", "PaymentProcessorRole", "s3-customer-pii-vault"),
    ("CAN_ACCESS", "PaymentProcessorRole", "rds-billing-logs"),
    ("DEPLOYED_TO", "commit-4f9a2b", "pod-payment-gateway"),
    ("AUTHORED", "user-alex", "commit-4f9a2b"),
]


# --------------------------------------------------------------------------- #
# FalkorDB helpers
# --------------------------------------------------------------------------- #
def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_db() -> FalkorDB:
    """Open a connection to FalkorDB (bounded timeouts).

    Fully environment-driven, so the same code targets either deployment:

    * Local Docker    -> FALKORDB_HOST / FALKORDB_PORT (defaults localhost:6379)
    * FalkorDB Cloud  -> FALKORDB_URL=rediss://user:pass@host:port (TLS implied)
      or FALKORDB_HOST / FALKORDB_PORT + FALKORDB_USERNAME / FALKORDB_PASSWORD
      with FALKORDB_TLS=true.
    """
    kwargs: Dict[str, Any] = {
        "socket_connect_timeout": float(os.getenv("FALKORDB_CONNECT_TIMEOUT", "5")),
        "socket_timeout": float(os.getenv("FALKORDB_SOCKET_TIMEOUT", "15")),
    }
    cert_reqs = os.getenv("FALKORDB_SSL_CERT_REQS")

    url = os.getenv("FALKORDB_URL")
    if url:
        # `redis://` / `rediss://` (and falkor:// / falkors://) are all accepted.
        if cert_reqs:
            kwargs["ssl_cert_reqs"] = cert_reqs
        return FalkorDB.from_url(url, **kwargs)

    kwargs["host"] = FALKORDB_HOST
    kwargs["port"] = FALKORDB_PORT
    username = os.getenv("FALKORDB_USERNAME")
    password = os.getenv("FALKORDB_PASSWORD")
    if username:
        kwargs["username"] = username
    if password:
        kwargs["password"] = password
    if _env_bool("FALKORDB_TLS"):
        kwargs["ssl"] = True
        if cert_reqs:
            kwargs["ssl_cert_reqs"] = cert_reqs
    return FalkorDB(**kwargs)


def select_graph(db: FalkorDB | None = None):
    """Return the ``secops_graph`` graph handle."""
    db = db or get_db()
    return db.select_graph(GRAPH_NAME)


def clear_graph(graph) -> None:
    """Remove every node and relationship from the graph."""
    graph.query("MATCH (n) DETACH DELETE n")


def upsert_node(graph, label: str, props: Dict[str, Any]) -> None:
    """Merge a node by its ``id`` and set the given properties."""
    assign = [k for k in props if k != "id"]
    set_clause = ""
    if assign:
        set_clause = " SET " + ", ".join(f"n.{k} = ${k}" for k in assign)
    cypher = f"MERGE (n:{label} {{id: $id}}){set_clause}"
    graph.query(cypher, params=props)


def upsert_edge(graph, rel_type: str, src_id: str, dst_id: str,
                props: Dict[str, Any] | None = None) -> None:
    """Merge a typed relationship between two nodes matched by ``id``."""
    props = props or {}
    params: Dict[str, Any] = {"src": src_id, "dst": dst_id, **props}
    set_clause = ""
    if props:
        set_clause = " SET " + ", ".join(f"r.{k} = ${k}" for k in props)
    cypher = (
        f"MATCH (a {{id: $src}}), (b {{id: $dst}}) "
        f"MERGE (a)-[r:{rel_type}]->(b){set_clause}"
    )
    graph.query(cypher, params=params)


def graph_stats(graph) -> Dict[str, int]:
    """Return node/relationship counts for the graph."""
    nodes = graph.query("MATCH (n) RETURN count(n)").result_set[0][0]
    edges = graph.query("MATCH ()-[r]->() RETURN count(r)").result_set[0][0]
    return {"nodes": int(nodes), "edges": int(edges)}


def seed(graph=None) -> Dict[str, Any]:
    """Clear and repopulate ``secops_graph``. Returns counts + timestamp."""
    graph = graph or select_graph()
    clear_graph(graph)
    for label, props in NODES:
        upsert_node(graph, label, props)
    for rel_type, src_id, dst_id in EDGES:
        upsert_edge(graph, rel_type, src_id, dst_id)
    stats = graph_stats(graph)
    return {
        "graph": GRAPH_NAME,
        "nodes": stats["nodes"],
        "edges": stats["edges"],
        "seeded_at": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":  # pragma: no cover
    try:
        result = seed()
    except Exception as exc:  # noqa: BLE001
        print(f"[seed] FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
    print(
        f"[seed] '{result['graph']}' seeded -> "
        f"{result['nodes']} nodes, {result['edges']} relationships "
        f"@ {result['seeded_at']}"
    )
