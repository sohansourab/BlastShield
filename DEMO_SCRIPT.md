# BlastShield — demo video script (~2:45)

**Format:** 1080p screen capture, no face cam required. Suggested layout: OpenCode
on the left, the dashboard on the right, or cut between full-screen scenes.
Aim for **under 3 minutes** — judges watch a lot of these.

---

## Pre-flight (do this before you hit record)

- [ ] FalkorDB running — `docker compose up -d` **or** a FalkorDB Cloud URL in `backend/.env`
- [ ] Seed the graph:
  `.\\.venv\\Scripts\\python.exe backend\\seed.py` → prints `8 nodes, 7 relationships`
- [ ] Backend up: `.\\.venv\\Scripts\\python.exe -m uvicorn backend.main:app --port 8000`
- [ ] Dashboard up: `cd frontend && npm run dev` → <http://localhost:5173>
- [ ] Press **Reset Graph** so every run starts from `RUNNING` / `ACTIVE`
- [ ] OpenCode open in the project; `/mcps` shows `blastshield  connected`
- [ ] Fresh OpenCode session (a clean transcript reads better on camera)
- [ ] Hide bookmarks/notifications; 1080p; legible terminal font

---

## Timeline & narration (verbatim)

### 0:00–0:12 · Hook
**On screen:** dashboard, the red `ALT-9021` node pulsing.
> "This is a live production cloud — a payment workload, an over-permissive IAM
> role, and three and a half million customer records behind it. A critical alert
> just fired. BlastShield triages and contains it autonomously — and it reasons
> over a **graph**, not a table."

### 0:12–0:40 · The graph is the product
**On screen:** show the data-model section of the README (or FalkorDB Browser).
> "Everything lives in FalkorDB. The alert *targets* a workload, which *assumes*
> a role, which *can access* the PII vault — and separately, a commit *deployed to*
> that workload and a user *authored* that commit. The attack path only exists in
> how these things connect. Take FalkorDB out and there is no product."

**Optional:** run one Cypher query live to prove it
```cypher
MATCH (a:Alert {id:'ALT-9021'})-[:TARGETS]->(w:Workload) RETURN w.id, w.name
```

### 0:40–1:00 · The agent's toolbox (MCP)
**On screen:** run `/mcps` in OpenCode; highlight the four tools.
> "The graph is exposed to the agent over **MCP** as four tools: a read-only Cypher
> query, a blast-radius traversal, and two containment actions. Crucially, the
> agent can look anywhere — but it can only *change* the graph through those two
> audited actions. Every step is traceable."

### 1:00–2:15 · Live triage (the centrepiece)
**On screen:** type `/triage` and let it run. Don't talk over the tool calls — let
a few land, then narrate.

Capture these moments:
- `query_falkordb` resolving `ALT-9021 → pod-payment-gateway`
- the backward traversal: commit `4f9a2b` + author *Alex Engineer*
- `calculate_blast_radius` returning **4,213,550 records → CRITICAL**
- the two containment calls firing
- the verification query

> "Watch the hops. It resolves the alert, walks *backward* to the commit and the
> engineer who shipped it, then forward to the blast radius — four and a quarter
> million restricted records, one hop away. That crosses the threshold, so it acts
> on its own: quarantine the workload, revoke the role."

### 2:15–2:40 · Containment + explainability
**On screen:** the dashboard — `pod-payment-gateway` and `PaymentProcessorRole`
turn red and slashed; the post-mortem text.
> "No human clicked anything. The dashboard updates live because it's a projection
> of the same graph — the workload is quarantined, the role is revoked. And the
> agent finishes with a post-mortem you can trace back to every query it ran."

### 2:40–2:55 · Close
**On screen:** end card — repo URL, track.
> "BlastShield. Autonomous containment over connected data — built on FalkorDB,
> driven by MCP. Track 01: *Agents That Act on Connected Data*."

---

## Run sheet (commands to have ready)

```powershell
# graph (choose one)
docker compose up -d                                    # local
# or set FALKORDB_URL=rediss://default:<pw>@<host>:<port> in backend/.env  # cloud

.\.venv\Scripts\python.exe backend\seed.py
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --port 8000

cd frontend; npm run dev        # http://localhost:5173
opencode                        # then:  /mcps   and   /triage
```

---

## If something fails on camera

- **FalkorDB not reachable** → the agent's tool result will say `ConnectionError
  10061`. Cut, get the DB up, re-seed, re-record that beat. Don't fake it.
- **`/triage` stalls** → press `Esc`, re-run `/triage`. It is idempotent: re-seeding
  restores `RUNNING` / `ACTIVE` so you can retake cleanly.
- **Dashboard not updating** → it polls every 3 s; wait one beat, or hit **Reset
  Graph** then re-run.

## Shot list / b-roll (optional cutaways)

1. The four-tool table from `backend/mcp_tools.py`.
2. FalkorDB Browser showing the 8 nodes and 7 edges.
3. The Cypher for the blast-radius traversal (README).
4. A close-up of the two `SET` containment queries.
