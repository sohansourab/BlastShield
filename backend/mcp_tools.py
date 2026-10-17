"""Phase 2 — MCP tool layer & graph engine for BlastShield.

Exposes four tools over FalkorDB and adapts them to both:

  * Model Context Protocol (MCP) conventions — ``name`` / ``description`` /
    ``inputSchema`` (exposed via :func:`mcp_manifest`), and
  * OpenAI-compatible function calling — via :func:`openai_tools`.

Reads are funnelled through ``query_falkordb`` (guarded to stay read-only).
Writes are only possible through the two dedicated containment tools, so the
agent can never mutate graph state without an explicit, auditable call.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List

try:  # package import (uvicorn backend.main:app)
    from .seed import select_graph
except ImportError:  # direct script import
    from seed import select_graph  # type: ignore

# --------------------------------------------------------------------------- #
# Cypher safety guard for query_falkordb
# --------------------------------------------------------------------------- #
# query_falkordb is intentionally read-only. Mutating keywords are rejected so
# the model cannot bypass the dedicated containment tools.
_DENY = (
    "delete", "detach", "drop", "create", "merge", "set", "remove",
    "load csv", "foreach", "copy", "call apoc", "call db.",
)
_ALLOWED_PREFIXES = ("match", "optional match", "with", "unwind", "return", "call")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rows(result) -> List[List[Any]]:
    return [list(row) for row in result.result_set]


def _header(result) -> List[str]:
    header = getattr(result, "header", None)
    return list(header) if header else []


def _authorize_read_query(cypher: str) -> None:
    if not cypher or not cypher.strip():
        raise ValueError("cypher must be a non-empty string")
    normalized = " ".join(cypher.lower().split())
    for keyword in _DENY:
        if keyword in normalized:
            raise ValueError(
                f"query_falkordb is read-only; '{keyword}' is not permitted. "
                "Use quarantine_workload / revoke_iam_role for state changes."
            )
    if not normalized.startswith(_ALLOWED_PREFIXES):
        raise ValueError(
            "query_falkordb only accepts read queries beginning with "
            "MATCH / OPTIONAL MATCH / WITH / UNWIND / RETURN / CALL."
        )


# --------------------------------------------------------------------------- #
# Tool 1 — query_falkordb
# --------------------------------------------------------------------------- #
def query_falkordb(cypher: str) -> Dict[str, Any]:
    """Execute a read-only Cypher query and return a JSON-safe result set."""
    _authorize_read_query(cypher)
    graph = select_graph()
    result = graph.ro_query(cypher)
    rows = _rows(result)
    return {
        "cypher": cypher,
        "columns": _header(result),
        "row_count": len(rows),
        "rows": rows,
    }


# --------------------------------------------------------------------------- #
# Tool 2 — calculate_blast_radius
# --------------------------------------------------------------------------- #
def calculate_blast_radius(workload_id: str) -> Dict[str, Any]:
    """1–3 hop forward traversal from a workload to RESTRICTED_PII data stores."""
    cypher = """
    MATCH (w:Workload {id: $workload_id})
    MATCH path = (w)-[*1..3]->(d:DataStore)
    WHERE d.classification = 'RESTRICTED_PII'
      AND all(rel IN relationships(path)
              WHERE type(rel) IN ['USES_SG', 'ASSUMES_ROLE', 'CAN_ACCESS'])
    RETURN d.id            AS id,
           d.name          AS name,
           d.classification AS classification,
           d.record_count  AS record_count,
           length(path)    AS hops,
           [n IN nodes(path) | coalesce(n.name, n.id)] AS path
    ORDER BY hops ASC, record_count DESC
    """
    graph = select_graph()
    result = graph.ro_query(cypher, params={"workload_id": workload_id})
    rows = _rows(result)

    reachable = [
        {
            "id": row[0],
            "name": row[1],
            "classification": row[2],
            "record_count": row[3],
            "hops": row[4],
            "path": row[5],
        }
        for row in rows
    ]
    total_records = sum(int(item["record_count"] or 0) for item in reachable)

    if total_records >= 1_000_000:
        risk = "CRITICAL"
    elif total_records > 0:
        risk = "HIGH"
    else:
        risk = "LOW"

    return {
        "workload_id": workload_id,
        "reachable_restricted_datastores": reachable,
        "datastore_count": len(reachable),
        "total_records_exposed": total_records,
        "risk_level": risk,
    }


# --------------------------------------------------------------------------- #
# Tool 3 — quarantine_workload
# --------------------------------------------------------------------------- #
def quarantine_workload(workload_id: str, reason: str | None = None) -> Dict[str, Any]:
    """Contain a workload by mutating its status to QUARANTINED."""
    cypher = """
    MATCH (w:Workload {id: $workload_id})
    SET w.status          = 'QUARANTINED',
        w.quarantined_at  = $ts,
        w.quarantine_reason = $reason
    RETURN w.id AS id, w.name AS name, w.status AS status
    """
    graph = select_graph()
    result = graph.query(
        cypher,
        params={
            "workload_id": workload_id,
            "ts": _utcnow(),
            "reason": reason or "BlastShield autonomous containment",
        },
    )
    if not result.result_set:
        raise ValueError(f"workload not found: {workload_id}")
    row = result.result_set[0]
    return {
        "action": "QUARANTINE_WORKLOAD",
        "ok": True,
        "id": row[0],
        "name": row[1],
        "status": row[2],
        "at": _utcnow(),
    }


# --------------------------------------------------------------------------- #
# Tool 4 — revoke_iam_role
# --------------------------------------------------------------------------- #
def revoke_iam_role(role_name: str, reason: str | None = None) -> Dict[str, Any]:
    """Contain lateral movement by mutating a role's status to REVOKED."""
    cypher = """
    MATCH (r:IAMRole)
    WHERE r.name = $role_name OR r.id = $role_name
    SET r.status         = 'REVOKED',
        r.revoked_at     = $ts,
        r.revoke_reason  = $reason
    RETURN r.id AS id, r.name AS name, r.status AS status
    """
    graph = select_graph()
    result = graph.query(
        cypher,
        params={
            "role_name": role_name,
            "ts": _utcnow(),
            "reason": reason or "BlastShield autonomous containment",
        },
    )
    if not result.result_set:
        raise ValueError(f"IAM role not found: {role_name}")
    row = result.result_set[0]
    return {
        "action": "REVOKE_IAM_ROLE",
        "ok": True,
        "id": row[0],
        "name": row[1],
        "status": row[2],
        "at": _utcnow(),
    }


# --------------------------------------------------------------------------- #
# MCP registry / adapters
# --------------------------------------------------------------------------- #
TOOL_SPECS: List[Dict[str, Any]] = [
    {
        "name": "query_falkordb",
        "description": (
            "Execute a READ-ONLY Cypher query against the secops_graph in FalkorDB "
            "and return the result rows. Use this to inspect alerts, workloads, "
            "commits, users, security groups, IAM roles and data stores. Mutating "
            "keywords (CREATE/MERGE/SET/DELETE/DROP) are rejected."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cypher": {
                    "type": "string",
                    "description": (
                        "A read-only Cypher query, e.g. "
                        "\"MATCH (a:Alert {id:'ALT-9021'})-[:TARGETS]->(w:Workload) "
                        "RETURN w.id, w.name\"."
                    ),
                }
            },
            "required": ["cypher"],
            "additionalProperties": False,
        },
    },
    {
        "name": "calculate_blast_radius",
        "description": (
            "Traverse 1 to 3 forward hops from a workload to every DataStore "
            "classified RESTRICTED_PII, and return the exposed stores, the minimum "
            "hop count, total exposed record count and a computed risk level."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "workload_id": {
                    "type": "string",
                    "description": "Workload id, e.g. 'pod-payment-gateway'.",
                }
            },
            "required": ["workload_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "quarantine_workload",
        "description": (
            "CONTAINMENT ACTION: set a workload's status to QUARANTINED in the "
            "graph. Use only when the blast-radius assessment shows high risk."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "workload_id": {"type": "string"},
                "reason": {
                    "type": "string",
                    "description": "Short justification recorded on the node.",
                },
            },
            "required": ["workload_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "revoke_iam_role",
        "description": (
            "CONTAINMENT ACTION: set an IAM role's status to REVOKED in the graph, "
            "cutting off lateral movement to reachable data stores. Use only when "
            "the blast-radius assessment shows high risk."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "role_name": {
                    "type": "string",
                    "description": "Role name or id, e.g. 'PaymentProcessorRole'.",
                },
                "reason": {"type": "string"},
            },
            "required": ["role_name"],
            "additionalProperties": False,
        },
    },
]

_HANDLERS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "query_falkordb": query_falkordb,
    "calculate_blast_radius": calculate_blast_radius,
    "quarantine_workload": quarantine_workload,
    "revoke_iam_role": revoke_iam_role,
}


def mcp_manifest() -> List[Dict[str, Any]]:
    """Return the tool catalogue using MCP field names."""
    return [
        {
            "name": spec["name"],
            "description": spec["description"],
            "inputSchema": spec["inputSchema"],
        }
        for spec in TOOL_SPECS
    ]


def openai_tools() -> List[Dict[str, Any]]:
    """Return the tool catalogue in OpenAI function-calling format."""
    return [
        {
            "type": "function",
            "function": {
                "name": spec["name"],
                "description": spec["description"],
                "parameters": spec["inputSchema"],
            },
        }
        for spec in TOOL_SPECS
    ]


def execute(name: str, arguments: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Dispatch a tool call by name and never raise across the boundary."""
    arguments = arguments or {}
    handler = _HANDLERS.get(name)
    if handler is None:
        return {"ok": False, "tool": name, "error": f"unknown tool: {name}"}
    try:
        return {"ok": True, "tool": name, "result": handler(**arguments)}
    except Exception as exc:  # noqa: BLE001 - surfaced to the agent as an observation
        return {"ok": False, "tool": name, "error": f"{type(exc).__name__}: {exc}"}
