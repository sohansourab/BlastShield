"""Phase 3a — Autonomous ReAct triage agent (optional in-process runner).

An OpenAI-compatible tool-calling loop that works with *any* OpenAI-compatible
endpoint (a local LM Studio / Ollama / vLLM server, or a hosted gateway). The
agent is given the four MCP tools and a mandatory reasoning sequence; it
inspects the alert, walks the graph backward, computes the blast radius, and —
when restricted PII is reachable — executes containment directly on graph state
before emitting a post-mortem.

BlastShield's primary path is OpenCode-native: the same four tools are served
over MCP by ``backend/mcp_server.py`` and driven by OpenCode's own models, so no
external API is required (see the ``/triage`` command and ``opencode.json``).
This module is only used when you *also* want the ``/api/investigate`` endpoint
to run the loop inside the backend.

Every step is emitted as a structured ``TraceEvent`` so the API and the
terminal log can render exactly what the agent thought, called and observed.
"""
from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, List, Optional

try:  # package import
    from . import mcp_tools
except ImportError:  # direct script import
    import mcp_tools  # type: ignore

Event = Dict[str, Any]
Emit = Callable[[Event], None]


SYSTEM_PROMPT = """You are BlastShield, an autonomous SecOps incident-triage and containment agent.

You operate against a FalkorDB graph named `secops_graph` through a fixed set of tools. The graph models a live cloud incident:

- (Alert {id:'ALT-9021'}) -[:TARGETS]-> (Workload)
- (Workload) -[:USES_SG]-> (SecurityGroup)
- (Workload) -[:ASSUMES_ROLE]-> (IAMRole)
- (IAMRole) -[:CAN_ACCESS]-> (DataStore) where DataStore.classification is 'RESTRICTED_PII' or 'INTERNAL'
- (Commit) -[:DEPLOYED_TO]-> (Workload)
- (User) -[:AUTHORED]-> (Commit)

You MUST follow this reasoning sequence, using tools for every fact you assert:
1. inspect_alert: use `query_falkordb` to resolve alert ALT-9021 to its entry-point workload.
2. attribute: use `query_falkordb` to traverse BACKWARD from that workload to the commit that deployed it and the user who authored it.
3. assess: call `calculate_blast_radius` on the workload to find every 1-3 hop path to a RESTRICTED_PII data store.
4. contain: if the assessment reaches RESTRICTED_PII (risk HIGH or CRITICAL), AUTONOMOUSLY call `quarantine_workload` on the workload AND `revoke_iam_role` on the role it assumes. If no restricted data is reachable, do NOT mutate anything.
5. verify: use `query_falkordb` to confirm the new statuses.
6. report: emit a concise post-mortem as your final message.

Hard rules:
- Never invent graph data; every id, name and count must come from a tool observation.
- `query_falkordb` is read-only. State changes happen only via `quarantine_workload` and `revoke_iam_role`.
- Prefer a small number of precise Cypher queries.
- Your final message MUST be prose only (no tool calls) and contain the post-mortem: Timeline, Blast Radius, Actions Taken, and Recommendation.
"""

INCIDENT_PROMPT = (
    "A CRITICAL alert has fired. Triage incident ALT-9021 now: identify the entry-point "
    "workload, attribute the deploying commit and its author, calculate the blast radius "
    "on RESTRICTED_PII data stores, contain autonomously if warranted, verify, and write "
    "the post-mortem."
)


# --------------------------------------------------------------------------- #
# Client / config
#
# This in-process agent is OPTIONAL. BlastShield's primary path is OpenCode-native:
# the same four tools are served over MCP (see backend/mcp_server.py) and driven by
# OpenCode's own models, so no external API is required. Configure the variables
# below only if you also want the /api/investigate endpoint to run the loop itself.
# --------------------------------------------------------------------------- #
def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.getenv(name)
    return value if value not in (None, "") else default


def llm_config() -> Dict[str, str]:
    """Return {base_url, model, api_key} for an OpenAI-compatible endpoint.

    Raises a clear, actionable error when the optional in-process agent has not
    been configured, pointing at the OpenCode-native alternative.
    """
    base_url = _env("LLM_BASE_URL")
    model = _env("LLM_MODEL")
    if not base_url or not model:
        raise RuntimeError(
            "The in-process agent is not configured. Set LLM_BASE_URL and LLM_MODEL "
            "(any OpenAI-compatible endpoint) in backend/.env — or, to drive BlastShield "
            "with OpenCode's own models and no external API, run the /triage command "
            "inside OpenCode instead."
        )
    return {
        "base_url": base_url,
        "model": model,
        "api_key": _env("LLM_API_KEY", "local") or "local",
    }


def configured_model() -> str:
    """Non-raising label for the active agent backend (for status endpoints).

    Reports the in-process model when one is configured, otherwise notes that the
    agent runs OpenCode-native over MCP.
    """
    return _env("LLM_MODEL") or "opencode-mcp"


def _make_client(cfg: Dict[str, str]):
    from openai import OpenAI  # imported lazily so the module loads without the dep

    return OpenAI(base_url=cfg["base_url"], api_key=cfg["api_key"])


# --------------------------------------------------------------------------- #
# Message helpers
# --------------------------------------------------------------------------- #
def _assistant_message_dict(message: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"role": "assistant", "content": message.content or ""}
    tool_calls = getattr(message, "tool_calls", None)
    if tool_calls:
        payload["tool_calls"] = [
            {
                "id": call.id,
                "type": "function",
                "function": {
                    "name": call.function.name,
                    "arguments": call.function.arguments or "{}",
                },
            }
            for call in tool_calls
        ]
    return payload


def _parse_arguments(raw: Optional[str]) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    except json.JSONDecodeError:
        return {"_raw": raw}


def _event(kind: str, title: str, detail: str = "", data: Any = None) -> Event:
    event: Event = {"type": kind, "title": title, "detail": detail}
    if data is not None:
        event["data"] = data
    return event


# --------------------------------------------------------------------------- #
# Agent loop
# --------------------------------------------------------------------------- #
def run_incident_triage(
    emit: Optional[Emit] = None, max_steps: int = 12
) -> Dict[str, Any]:
    """Run the triage agent. Returns {summary, trace, steps, model}."""
    emit = emit or (lambda _event: None)
    cfg = llm_config()
    client = _make_client(cfg)
    tools = mcp_tools.openai_tools()

    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": INCIDENT_PROMPT},
    ]
    trace: List[Event] = []

    def record(event: Event) -> None:
        trace.append(event)
        emit(event)

    record(
        _event(
            "info",
            "Agent online",
            f"model={cfg['model']} · endpoint={cfg['base_url']}",
        )
    )

    summary = ""
    for step in range(1, max_steps + 1):
        response = client.chat.completions.create(
            model=cfg["model"],
            messages=messages,
            tools=tools,
            tool_choice="auto",
        )
        message = response.choices[0].message
        messages.append(_assistant_message_dict(message))

        if message.content and message.content.strip():
            record(_event("thought", f"Step {step} · Reasoning", message.content.strip()))

        tool_calls = getattr(message, "tool_calls", None) or []
        if not tool_calls:
            summary = (message.content or "").strip() or "Triage finished without a narrative."
            record(_event("final", "Post-mortem", summary))
            return {
                "summary": summary,
                "trace": trace,
                "steps": step,
                "model": cfg["model"],
            }

        for call in tool_calls:
            name = call.function.name
            arguments = _parse_arguments(call.function.arguments)
            record(
                _event(
                    "tool_call",
                    f"→ {name}",
                    json.dumps(arguments, ensure_ascii=False),
                    {"name": name, "arguments": arguments},
                )
            )

            outcome = mcp_tools.execute(name, arguments)
            if outcome.get("ok"):
                detail = json.dumps(outcome.get("result"), ensure_ascii=False, default=str)
            else:
                detail = f"ERROR: {outcome.get('error')}"
            if len(detail) > 4000:
                detail = detail[:4000] + " …(truncated)"

            record(
                _event(
                    "tool_result" if outcome.get("ok") else "error",
                    f"← {name}",
                    detail,
                    outcome,
                )
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.id,
                    "name": name,
                    "content": json.dumps(outcome, ensure_ascii=False, default=str),
                }
            )

    summary = (
        f"Reached the {max_steps}-step safety limit before the agent produced a "
        "post-mortem. Review the trace and re-run."
    )
    record(_event("error", "Step limit reached", summary))
    return {"summary": summary, "trace": trace, "steps": max_steps, "model": cfg["model"]}
