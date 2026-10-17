#!/usr/bin/env python3
"""BlastShield MCP server (stdio transport).

Exposes the four FalkorDB SecOps tools over the Model Context Protocol so any
MCP client — including OpenCode driving it with *its* configured models — can
run the autonomous incident triage. No external API and no extra dependency:
this speaks newline-delimited JSON-RPC 2.0 on stdin/stdout, which is the MCP
stdio transport.

Tool names advertised to the client:
    query_falkordb
    calculate_blast_radius
    quarantine_workload
    revoke_iam_role

OpenCode namespaces them as ``blastshield_<tool>`` (or, under Code Mode,
``tools.blastshield.<tool>(...)``).

Run directly:
    python backend/mcp_server.py
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Optional

# Make ``mcp_tools`` / ``seed`` importable no matter what cwd the client uses.
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

try:  # optional local .env (FALKORDB_HOST / PORT / GRAPH)
    from dotenv import load_dotenv

    load_dotenv(os.path.join(_BACKEND_DIR, ".env"))
except Exception:  # pragma: no cover
    pass

try:  # package import
    from . import mcp_tools
except ImportError:  # direct execution
    import mcp_tools  # type: ignore

SERVER_NAME = "blastshield"
SERVER_VERSION = "1.0.0"
DEFAULT_PROTOCOL = "2025-11-25"

INSTRUCTIONS = (
    "BlastShield exposes the FalkorDB SecOps graph 'secops_graph'. Use "
    "query_falkordb for read-only Cypher, calculate_blast_radius to quantify "
    "RESTRICTED_PII exposure from a workload, and the containment actions "
    "quarantine_workload / revoke_iam_role to mutate graph state. Inspect alert "
    "ALT-9021 first, attribute the deploying commit, assess the blast radius, "
    "then contain autonomously if restricted PII is reachable."
)

# stdout is reserved for protocol frames; diagnostics go to stderr.
try:  # be explicit about UTF-8 on Windows
    sys.stdin.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    pass


def _log(*parts: Any) -> None:
    print("[blastshield-mcp]", *parts, file=sys.stderr, flush=True)


def _ok(msg_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


# --------------------------------------------------------------------------- #
# Request dispatch
# --------------------------------------------------------------------------- #
def handle(request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Handle one JSON-RPC request. Return a response, or None for notifications."""
    method = request.get("method")
    params: Dict[str, Any] = request.get("params") or {}
    msg_id = request.get("id")

    if method == "initialize":
        protocol = params.get("protocolVersion") or DEFAULT_PROTOCOL
        return _ok(
            msg_id,
            {
                "protocolVersion": protocol,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {},
                    "prompts": {},
                },
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "instructions": INSTRUCTIONS,
            },
        )

    if method == "ping":
        return _ok(msg_id, {})

    if method == "tools/list":
        return _ok(msg_id, {"tools": mcp_tools.mcp_manifest()})

    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        outcome = mcp_tools.execute(name, arguments)
        text = json.dumps(outcome, ensure_ascii=False, default=str)
        return _ok(
            msg_id,
            {
                "content": [{"type": "text", "text": text}],
                "isError": not bool(outcome.get("ok", False)),
            },
        )

    if method == "resources/list":
        return _ok(msg_id, {"resources": []})
    if method == "resources/templates/list":
        return _ok(msg_id, {"resourceTemplates": []})
    if method == "prompts/list":
        return _ok(msg_id, {"prompts": []})

    # Notifications (no id) — acknowledge by ignoring.
    if msg_id is None:
        return None

    return _err(msg_id, -32601, f"Method not found: {method}")


def main() -> None:
    _log(f"stdio server ready (graph={os.getenv('FALKORDB_GRAPH', 'secops_graph')})")
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            _log("ignoring malformed JSON line")
            continue
        if not isinstance(request, dict):
            continue
        try:
            response = handle(request)
        except Exception as exc:  # noqa: BLE001
            response = _err(request.get("id"), -32603, f"Internal error: {exc}")
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
