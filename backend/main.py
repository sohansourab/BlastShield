"""Phase 3b — BlastShield FastAPI server.

Endpoints:
    POST /api/seed         clear + reseed the FalkorDB graph
    GET  /api/graph        nodes + edges with deterministic (x, y) positions
    GET  /api/tools        MCP-style tool catalogue (for the UI)
    POST /api/investigate  run the autonomous agent, return trace + graph

Run:
    docker compose up -d
    python backend/seed.py
    uvicorn backend.main:app --reload --port 8000
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

try:  # optional .env for local dev (loaded from the backend dir, not cwd)
    from dotenv import load_dotenv

    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except Exception:  # pragma: no cover
    pass

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

try:  # package import
    from . import agent, mcp_tools, seed as seed_module
except ImportError:  # direct script import
    import agent  # type: ignore
    import mcp_tools  # type: ignore
    import seed as seed_module  # type: ignore


app = FastAPI(
    title="BlastShield API",
    description="Autonomous incident triage & containment over FalkorDB.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# Deterministic layout for React Flow
# --------------------------------------------------------------------------- #
# Hand-placed coordinates keep the topology stable between re-seeds: the
# frontend never has to run a physics simulation.
POSITIONS: Dict[str, Dict[str, float]] = {
    "ALT-9021": {"x": 40, "y": 240},
    "pod-payment-gateway": {"x": 560, "y": 500},
    "sg-payment-cluster": {"x": 880, "y": 240},
    "PaymentProcessorRole": {"x": 880, "y": 560},
    "s3-customer-pii-vault": {"x": 1200, "y": 400},
    "rds-billing-logs": {"x": 1200, "y": 700},
    "commit-4f9a2b": {"x": 300, "y": 760},
    "user-alex": {"x": 40, "y": 760},
}


def _position_for(node_id: str) -> Dict[str, float]:
    if node_id in POSITIONS:
        return POSITIONS[node_id]
    # Deterministic fallback grid for any node not explicitly laid out.
    ordered = sorted(POSITIONS.keys())
    index = ordered.index(node_id) if node_id in ordered else len(node_id)
    col, row = index % 4, index // 4
    return {"x": 60 + col * 320, "y": 120 + row * 220}


# --------------------------------------------------------------------------- #
# Graph serialization
# --------------------------------------------------------------------------- #
def serialize_graph() -> Dict[str, Any]:
    """Read the whole graph and shape it for React Flow."""
    graph = seed_module.select_graph()
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    node_result = graph.ro_query("MATCH (n) RETURN n.id, labels(n), properties(n)")
    for row in node_result.result_set:
        node_id = row[0]
        labels = row[1] or []
        props = dict(row[2] or {})
        kind = props.get("type") or (labels[0] if labels else "Unknown")
        nodes.append(
            {
                "id": node_id,
                "type": kind,
                "label": props.get("name", node_id),
                "position": _position_for(node_id),
                "data": {**props, "type": kind, "kind": kind, "labels": list(labels)},
            }
        )

    edge_result = graph.ro_query(
        "MATCH (a)-[r]->(b) RETURN a.id, type(r), b.id, properties(r)"
    )
    for index, row in enumerate(edge_result.result_set):
        src, rel_type, dst, props = row[0], row[1], row[2], dict(row[3] or {})
        edges.append(
            {
                "id": f"e{index}:{src}:{rel_type}:{dst}",
                "source": src,
                "target": dst,
                "type": rel_type,
                "label": rel_type,
                "data": props,
            }
        )

    return {"nodes": nodes, "edges": edges}


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #
class InvestigateRequest(BaseModel):
    max_steps: int = Field(default=12, ge=1, le=25)
    incident: Optional[str] = Field(default=None, description="Optional incident override.")


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "name": "BlastShield API",
        "status": "online",
        "graph": seed_module.GRAPH_NAME,
        "model": agent.configured_model(),
        "endpoints": ["/api/seed", "/api/graph", "/api/tools", "/api/investigate"],
    }


@app.get("/api/health")
def health() -> Dict[str, Any]:
    try:
        seed_module.select_graph().query("RETURN 1")
        return {"ok": True, "falkordb": "reachable", "model": agent.configured_model()}
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            status_code=503,
            content={"ok": False, "falkordb": "unreachable", "error": str(exc)},
        )


@app.post("/api/seed")
def seed_endpoint() -> Dict[str, Any]:
    try:
        result = seed_module.seed()
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=503, content={"ok": False, "error": str(exc)})
    return {"ok": True, **result, "graph_state": serialize_graph()}


@app.get("/api/graph")
def graph_endpoint() -> Dict[str, Any]:
    try:
        return serialize_graph()
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=503, content={"ok": False, "error": str(exc)})


@app.get("/api/tools")
def tools_endpoint() -> Dict[str, Any]:
    return {"tools": mcp_tools.mcp_manifest()}


@app.post("/api/investigate")
def investigate_endpoint(payload: Optional[InvestigateRequest] = None) -> Dict[str, Any]:
    request = payload or InvestigateRequest()
    try:
        run = agent.run_incident_triage(max_steps=request.max_steps)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            status_code=502,
            content={"ok": False, "error": f"{type(exc).__name__}: {exc}"},
        )
    return {
        "ok": True,
        "incident": "ALT-9021",
        "model": run["model"],
        "steps": run["steps"],
        "summary": run["summary"],
        "trace": run["trace"],
        "graph": serialize_graph(),
    }
