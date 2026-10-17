# 🛡️ BlastShield

**Autonomous incident triage & containment over connected cloud data.**

> **Hackathon:** Graph Hacks: Context for AI Agents — WeMakeDevs × FalkorDB, Oct 15–18 2026
> **Track entered:** **01 — Agents That Act on Connected Data**

BlastShield models a live cloud attack path in **FalkorDB**, exposes the graph as
tools over **Model Context Protocol (MCP)**, and runs an autonomous agent that
reasons across multiple hops and then *acts directly on graph state* to contain
the incident — all visualized in a React Flow dashboard.

**No external API is required.** The agent runs on **OpenCode's own models**: the
four graph tools are served over MCP and driven from OpenCode with the built-in
[`/triage`](.opencode/command/triage.md) command.

---

## Architecture

```
     OpenCode  (your chosen model)
         │
         │  MCP stdio  (initialize → tools/list → tools/call)
         ▼
 ┌───────────────────────────┐          read-only view            ┌────────────────────┐
 │ backend/mcp_server.py     │◀──────────────────────────────┐    │ React Flow (Vite)  │
 │   4 MCP tools             │                               │    │ + Tailwind         │
 └────────────┬──────────────┘                               │    └────────────────────┘
              │ Cypher                                       │  /api/graph · /api/seed
              ▼                                              │
       ┌────────────────┐                        ┌───────────┴──────────┐
       │   FalkorDB     │                        │  FastAPI (main.py)   │
       │  secops_graph  │                        └──────────────────────┘
       └────────────────┘
```

Two ways to run the agent:

| Path | Needs an external API? | How |
| --- | --- | --- |
| **OpenCode-native (primary)** | **No** | OpenCode connects to the `blastshield` MCP server and runs `/triage` with your configured model |
| In-process (optional) | any OpenAI-compatible endpoint | `POST /api/investigate` runs `agent.py` when `LLM_BASE_URL` / `LLM_MODEL` are set |

**FalkorDB does real work here.** Remove it and there is no product: the agent's
every decision (which workload the alert targets, who deployed it, what PII is
reachable, and which state to mutate) is a graph traversal, and containment is a
graph write. The React Flow view is only a read-only projection of that graph.

---

## Graph data model

One graph, key **`secops_graph`** — 8 nodes, 7 relationships. Every node carries an
explicit `type` property (mirroring its label) so the API/frontend can reason
about it without parsing labels.

**Node labels & key properties**

| Label | Example `id` | Notable properties |
| --- | --- | --- |
| `Alert` | `ALT-9021` | `severity=CRITICAL`, `status=OPEN`, `source`, `detected_at` |
| `Workload` | `pod-payment-gateway` | `namespace`, `kind`, `status=RUNNING`, `replicas`, `image`, `region` |
| `SecurityGroup` | `sg-payment-cluster` | `inbound_rule=0.0.0.0/0:443`, `vpc`, `region` |
| `IAMRole` | `PaymentProcessorRole` | `arn`, `status=ACTIVE`, `max_session_duration` |
| `DataStore` | `s3-customer-pii-vault` | `classification=RESTRICTED_PII`, `record_count=4213550`, `encrypted` |
| `DataStore` | `rds-billing-logs` | `classification=INTERNAL`, `record_count=812400` |
| `Commit` | `commit-4f9a2b` | `sha`, `message`, `authored_by`, `committed_at`, `branch` |
| `User` | `user-alex` | `name=Alex Engineer`, `email`, `team`, `mfa_enabled` |

**Relationships**

```
(Alert)      -[:TARGETS]->      (Workload)
(Workload)   -[:USES_SG]->      (SecurityGroup)
(Workload)   -[:ASSUMES_ROLE]-> (IAMRole)
(IAMRole)    -[:CAN_ACCESS]->   (DataStore)
(Commit)     -[:DEPLOYED_TO]->  (Workload)
(User)       -[:AUTHORED]->     (Commit)
```

**The attack path the agent must reconstruct**

```
ALT-9021 ─TARGETS→ pod-payment-gateway ─ASSUMES_ROLE→ PaymentProcessorRole ─CAN_ACCESS→ s3-customer-pii-vault 🔴
                                             │                                                   (RESTRICTED_PII)
                                             └─CAN_ACCESS→ rds-billing-logs (INTERNAL)

user-alex ─AUTHORED→ commit-4f9a2b ─DEPLOYED_TO→ pod-payment-gateway
```

The agent must traverse **backward** (workload → commit → author) *and*
**forward** (workload → role → PII store) to explain *and* contain the breach.

---

## Cypher queries & graph algorithms the product depends on

Everything the product does routes through these queries (all in
`backend/seed.py` and `backend/mcp_tools.py`).

**1 · Seed — idempotent node upsert** (`seed.py`)
```cypher
MERGE (n:Workload {id: $id})
SET n.name = $name, n.status = $status, n.region = $region, …
```

**2 · Seed — typed relationship upsert** (`seed.py`)
```cypher
MATCH (a {id: $src}), (b {id: $dst})
MERGE (a)-[r:ASSUMES_ROLE]->(b)
```

**3 · `calculate_blast_radius` — bounded variable-length traversal** (`mcp_tools.py`)

The core multi-hop "graph algorithm as a tool": a 1–3 hop forward walk from a
workload to restricted data, restricted to the attack-relevant relationship
types, returning the shortest path to each store.
```cypher
MATCH (w:Workload {id: $workload_id})
MATCH path = (w)-[*1..3]->(d:DataStore)
WHERE d.classification = 'RESTRICTED_PII'
  AND all(rel IN relationships(path)
          WHERE type(rel) IN ['USES_SG', 'ASSUMES_ROLE', 'CAN_ACCESS'])
RETURN d.id AS id, d.name AS name, d.classification AS classification,
       d.record_count AS record_count,
       length(path) AS hops,
       [n IN nodes(path) | coalesce(n.name, n.id)] AS path
ORDER BY hops ASC, record_count DESC
```
The tool then aggregates `total_records_exposed` and derives a `risk_level`
(`≥1,000,000 → CRITICAL`, `>0 → HIGH`, else `LOW`).

**4 · Containment — quarantine a workload** (`mcp_tools.py`, state write)
```cypher
MATCH (w:Workload {id: $workload_id})
SET w.status = 'QUARANTINED',
    w.quarantined_at = $ts,
    w.quarantine_reason = $reason
RETURN w.id AS id, w.name AS name, w.status AS status
```

**5 · Containment — revoke an IAM role** (`mcp_tools.py`, state write)
```cypher
MATCH (r:IAMRole)
WHERE r.name = $role_name OR r.id = $role_name
SET r.status = 'REVOKED',
    r.revoked_at = $ts,
    r.revoke_reason = $reason
RETURN r.id AS id, r.name AS name, r.status AS status
```

**6 · Dashboard projection — full graph read** (`main.py`)
```cypher
MATCH (n) RETURN n.id, labels(n), properties(n)
MATCH (a)-[r]->(b) RETURN a.id, type(r), b.id, properties(r)
```
Node coordinates are computed deterministically in Python, so the layout is
stable and no client-side physics is needed.

**7 · Agent-generated read queries** via `query_falkordb`, e.g.
```cypher
MATCH (a:Alert {id:'ALT-9021'})-[:TARGETS]->(w:Workload) RETURN w.id, w.name

MATCH (c:Commit)-[:DEPLOYED_TO]->(w:Workload {id:'pod-payment-gateway'}),
      (u:User)-[:AUTHORED]->(c)
RETURN u.name, c.sha, c.message, c.committed_at
```

**Read-only guarantee.** `query_falkordb` rejects `CREATE/MERGE/SET/DELETE/DETACH/
DROP/REMOVE/…` and only accepts statements beginning with `MATCH / OPTIONAL MATCH /
WITH / UNWIND / RETURN / CALL`. State changes are therefore *only* possible through
the two audited containment tools.

> No server-side GDS procedures are required — the multi-hop reasoning is a
> bounded variable-length path traversal, which is exactly the track's focus on
> "graph queries and algorithms as agent tools".

---

## Tools (MCP)

Server name `blastshield`. OpenCode exposes the tools as `blastshield_<tool>`
(under the default Code Mode: `tools.blastshield.<tool>(...)`).

| Tool | Mutates? | Purpose |
| --- | --- | --- |
| `query_falkordb` | no | Read-only Cypher (mutating keywords rejected) |
| `calculate_blast_radius` | no | 1–3 hop traversal to `RESTRICTED_PII` stores |
| `quarantine_workload` | **yes** | `SET w.status = 'QUARANTINED'` |
| `revoke_iam_role` | **yes** | `SET r.status = 'REVOKED'` |

---

## Run it

### 0. Prerequisites
- Python 3.11+, Node 18+, and [OpenCode](https://opencode.ai)
- **FalkorDB** — either Docker **or** FalkorDB Cloud (both accepted by the rules)
- **No LLM API key required** for the primary path.

### 1. FalkorDB

**Option A — Docker (local):**
```bash
docker compose up -d
docker compose logs -f falkordb   # wait for "Ready to accept connections"
```

**Option B — FalkorDB Cloud (no local setup):** create a free instance at
<https://app.falkordb.cloud>, then in `backend/.env`:
```ini
# single URL form ('rediss://' implies TLS)
FALKORDB_URL=rediss://default:<password>@<host>:<port>
```
*(or use the discrete `FALKORDB_HOST` / `FALKORDB_PORT` / `FALKORDB_USERNAME` /
`FALKORDB_PASSWORD` / `FALKORDB_TLS=true` fields).*

### 2. Backend (graph API + dashboard feed)
```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env      # set FalkorDB Cloud creds here if you chose Option B
python seed.py            # seed secops_graph
python -m uvicorn main:app --reload --port 8000
```
On Windows (from the project root) the venv interpreter paths are
`.venv\Scripts\python.exe`.

### 3. Frontend (dashboard)
```bash
cd frontend
npm install
npm run dev
```
Open <http://localhost:5173>. The topology auto-refreshes every 3s, so it tracks
any change the agent makes.

### 4. Agent (OpenCode-native — already wired)
The project [`opencode.json`](opencode.json) registers the `blastshield` MCP server
(a local stdio process: your `.venv` Python running `backend/mcp_server.py`).

```bash
# from the project root
opencode
```
Inside OpenCode:
1. Run `/mcps` and confirm `blastshield  connected`.
2. Run the **`/triage`** command. OpenCode's own model calls the MCP tools:
   it resolves `ALT-9021`, attributes the deploying commit, computes the blast
   radius, contains the workload + IAM role, verifies, and prints the post-mortem.
3. Watch the dashboard — quarantined/revoked nodes turn red and slashed.

> `opencode.json` launches the server through `scripts/mcp_launcher.mjs`, which
> finds your Python automatically (`.venv/Scripts/python.exe`, then
> `.venv/bin/python`, then `python3`/`python`). To force a specific interpreter,
> set `BLASTSHIELD_PYTHON`.

#### Optional: in-process agent
Set an OpenAI-compatible endpoint in `backend/.env` to also enable the
**🚨 Trigger Triage** button (`POST /api/investigate`):
```ini
LLM_BASE_URL=http://localhost:11434/v1   # a local Ollama / LM Studio / vLLM server
LLM_MODEL=qwen3-coder
LLM_API_KEY=local
```

---

## API

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/seed` | Clear + reseed `secops_graph` |
| `GET`  | `/api/graph` | Nodes/edges with deterministic `(x, y)` for React Flow |
| `GET`  | `/api/tools` | MCP tool catalogue |
| `POST` | `/api/investigate` | Run the in-process agent → `{ trace, summary, graph }` |

```bash
curl -X POST http://localhost:8000/api/investigate \
  -H "Content-Type: application/json" -d '{"max_steps": 12}'
```

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `FALKORDB_HOST` | `localhost` | local Docker |
| `FALKORDB_PORT` | `6379` | local Docker |
| `FALKORDB_GRAPH` | `secops_graph` | graph key |
| `FALKORDB_URL` | — | FalkorDB Cloud, e.g. `rediss://user:pass@host:port` |
| `FALKORDB_USERNAME` / `FALKORDB_PASSWORD` | — | Cloud auth (discrete form) |
| `FALKORDB_TLS` | `false` | enable TLS for Cloud |
| `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` | — | *optional*, in-process agent only |

Secrets are read from the environment only and are **never** written into source.

## Visual explainability

- **65% left:** React Flow topology. Alerts pulse; quarantined/revoked nodes
  render slashed and dimmed with a red border; `RESTRICTED_PII` stores are
  crimson with a lock icon and record count.
- **35% right:** cyberpunk control console. The terminal streams the in-process
  agent's reasoning, tool calls, observations and post-mortem; an OpenCode
  `/triage` run shows its narrative inside OpenCode and its effects on the
  topology here.

## Project layout

```
opencode.json                 # OpenCode project config: registers the blastshield MCP server
scripts/mcp_launcher.mjs      # cross-platform launcher: finds Python, runs backend/mcp_server.py
.opencode/command/triage.md   # /triage command: the autonomous incident-response prompt
backend/mcp_server.py         # MCP stdio server exposing the 4 tools (no extra deps)
backend/mcp_tools.py          # tool implementations + read-only guard
backend/seed.py               # FalkorDB schema, connection (Docker/Cloud) + seed data
backend/agent.py              # optional in-process ReAct loop (OpenAI-compatible)
backend/main.py               # FastAPI: /api/seed, /api/graph, /api/tools, /api/investigate
frontend/src/App.tsx          # React Flow dashboard + console
docker-compose.yml            # FalkorDB
```

---

## AI-assistant disclosure

Rule 11 compliance: an AI coding assistant (**OpenCode**) was used to help write
and refactor parts of this project. All code was reviewed, run and verified by
the author, who can explain the graph model, the Cypher queries, the MCP tool
layer and the overall architecture.

## Submission checklist (rule 10)

- [x] **Public source-code repository** — this repo
- [x] **README with setup instructions** — "Run it" above
- [x] **README with the graph data model** — "Graph data model" above
- [x] **The Cypher queries / graph algorithms** — "Cypher queries & graph algorithms" above
- [ ] **Demo video** — record a run of `/triage` + the dashboard updating
- [x] **Live deployment *or* complete local setup instructions** — "Run it" (Docker or Cloud)
- [x] **Track you are entering** — Track 01, Agents That Act on Connected Data
