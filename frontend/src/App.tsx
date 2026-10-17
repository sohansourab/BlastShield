import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  useEdgesState,
  useNodesState,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from "@xyflow/react";
import {
  Activity,
  AlertTriangle,
  Ban,
  CheckCircle2,
  Database,
  GitCommitHorizontal,
  KeyRound,
  Loader2,
  Lock,
  Network,
  Play,
  Radio,
  RotateCcw,
  Server,
  ShieldAlert,
  Terminal as TerminalIcon,
  UserRound,
} from "lucide-react";
import type {
  GraphNodeData,
  GraphResponse,
  InvestigateResponse,
  NodeKind,
  SeedResponse,
  TraceEventType,
} from "./types";

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

const API_BASE = import.meta.env.VITE_API_BASE ?? "";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  const text = await res.text();
  const body = text ? (JSON.parse(text) as unknown) : ({} as unknown);
  if (!res.ok) {
    const message =
      (body as { error?: string }).error ?? `${res.status} ${res.statusText}`;
    throw new Error(message);
  }
  return body as T;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const numberFmt = new Intl.NumberFormat("en-US");

/* ------------------------------------------------------------------ */
/* Visual language                                                     */
/* ------------------------------------------------------------------ */

interface KindTheme {
  icon: typeof Server;
  color: string;
  ring: string;
}

const THEME: Record<string, KindTheme> = {
  Alert: { icon: AlertTriangle, color: "#ef4444", ring: "rgba(239,68,68,0.35)" },
  Workload: { icon: Server, color: "#38bdf8", ring: "rgba(56,189,248,0.35)" },
  SecurityGroup: { icon: Network, color: "#f59e0b", ring: "rgba(245,158,11,0.35)" },
  IAMRole: { icon: KeyRound, color: "#a78bfa", ring: "rgba(167,139,250,0.35)" },
  DataStore: { icon: Database, color: "#10b981", ring: "rgba(16,185,129,0.35)" },
  Commit: { icon: GitCommitHorizontal, color: "#94a3b8", ring: "rgba(148,163,184,0.35)" },
  User: { icon: UserRound, color: "#2dd4bf", ring: "rgba(45,212,191,0.35)" },
  Unknown: { icon: Activity, color: "#94a3b8", ring: "rgba(148,163,184,0.35)" },
};

function themeFor(kind: string | undefined): KindTheme {
  return THEME[kind ?? "Unknown"] ?? THEME.Unknown;
}

/* ------------------------------------------------------------------ */
/* Custom React Flow node                                              */
/* ------------------------------------------------------------------ */

function SystemNode({ data }: NodeProps) {
  const d = data as unknown as GraphNodeData & { label?: string };
  const kind = (d.kind ?? d.type ?? "Unknown") as NodeKind;
  const theme = themeFor(kind);
  const Icon = theme.icon;

  const quarantined = d.status === "QUARANTINED";
  const revoked = d.status === "REVOKED";
  const contained = quarantined || revoked;
  const isAlert = kind === "Alert" && d.status !== "RESOLVED";
  const isPii = kind === "DataStore" && d.classification === "RESTRICTED_PII";
  const isInternal = kind === "DataStore" && d.classification === "INTERNAL";

  const borderColor = isPii
    ? "#e11d48"
    : contained
      ? "#dc2626"
      : theme.color;

  return (
    <div
      className={[
        "relative w-[220px] rounded-xl border-2 bg-[#0b1220] px-3 py-2 text-left shadow-lg transition-all",
        contained ? "opacity-60" : "opacity-100",
        isAlert ? "blast-alert-pulse" : "",
      ].join(" ")}
      style={{ borderColor, boxShadow: `0 0 18px ${contained ? "rgba(220,38,38,0.25)" : theme.ring}` }}
    >
      <Handle type="target" position={Position.Left} style={{ background: theme.color }} />
      <Handle type="source" position={Position.Right} style={{ background: theme.color }} />

      {quarantined && (
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 overflow-hidden rounded-xl"
        >
          <div className="absolute left-[-10%] top-1/2 h-[2px] w-[120%] -rotate-[24deg] bg-red-500/70" />
        </div>
      )}

      <div className="flex items-start gap-2">
        <span
          className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md"
          style={{ background: `${theme.color}22`, color: theme.color }}
        >
          <Icon size={15} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1">
            <p
              className={[
                "truncate text-[13px] font-semibold tracking-tight text-slate-100",
                contained ? "line-through decoration-red-500/80" : "",
              ].join(" ")}
              title={d.label ?? d.name ?? String(d.id)}
            >
              {d.label ?? d.name ?? String(d.id)}
            </p>
            {isPii && <Lock size={12} className="shrink-0 text-rose-400" />}
          </div>
          <p className="truncate text-[10px] uppercase tracking-[0.14em] text-slate-500">
            {kind}
          </p>
        </div>
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        {d.status && (
          <span
            className="rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider"
            style={{
              background: contained ? "rgba(220,38,38,0.18)" : `${theme.color}22`,
              color: contained ? "#f87171" : theme.color,
            }}
          >
            {contained ? <Ban size={9} className="mr-1 inline" /> : null}
            {d.status}
          </span>
        )}
        {isPii && (
          <span className="rounded bg-rose-600/20 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-rose-300">
            PII · {numberFmt.format(Number(d.record_count ?? 0))} recs
          </span>
        )}
        {isInternal && (
          <span className="rounded bg-emerald-600/20 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-emerald-300">
            {numberFmt.format(Number(d.record_count ?? 0))} recs
          </span>
        )}
        {isAlert && (
          <span className="rounded bg-red-600/20 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-red-300">
            {d.severity ?? "ALERT"}
          </span>
        )}
        {kind === "SecurityGroup" && d.inbound_rule && (
          <span className="rounded bg-amber-600/20 px-1.5 py-0.5 font-mono text-[9px] text-amber-300">
            {d.inbound_rule}
          </span>
        )}
      </div>
    </div>
  );
}

const nodeTypes: NodeTypes = { system: SystemNode };

/* ------------------------------------------------------------------ */
/* Conversion helpers                                                  */
/* ------------------------------------------------------------------ */

function toFlowNodes(graph: GraphResponse): Node[] {
  return graph.nodes.map((n) => ({
    id: n.id,
    type: "system",
    position: n.position,
    data: { ...n.data, kind: n.type, label: n.label },
  }));
}

function toFlowEdges(graph: GraphResponse): Edge[] {
  return graph.edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    type: "smoothstep",
    animated: true,
    label: e.label,
    markerEnd: { type: MarkerType.ArrowClosed, color: "#475569" },
    style: { stroke: "#334155", strokeWidth: 1.5 },
    labelStyle: { fill: "#94a3b8", fontSize: 10, fontWeight: 700 },
    labelBgStyle: { fill: "#05070d", fillOpacity: 0.85 },
    labelBgPadding: [4, 2] as [number, number],
    labelBgBorderRadius: 4,
  }));
}

/* ------------------------------------------------------------------ */
/* Terminal log                                                        */
/* ------------------------------------------------------------------ */

interface LogLine {
  id: number;
  type: TraceEventType;
  title: string;
  detail?: string;
}

const LOG_META: Record<TraceEventType, { tag: string; tagClass: string; textClass: string }> = {
  info: { tag: "SYS", tagClass: "text-slate-400", textClass: "text-slate-300" },
  thought: { tag: "REASON", tagClass: "text-sky-400", textClass: "text-sky-100" },
  tool_call: { tag: "CALL", tagClass: "text-amber-400", textClass: "text-amber-100" },
  tool_result: { tag: "OBS", tagClass: "text-emerald-400", textClass: "text-emerald-100" },
  final: { tag: "REPORT", tagClass: "text-fuchsia-400", textClass: "text-fuchsia-100" },
  error: { tag: "ERR", tagClass: "text-red-400", textClass: "text-red-200" },
};

/* ------------------------------------------------------------------ */
/* App                                                                 */
/* ------------------------------------------------------------------ */

export default function App() {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [summary, setSummary] = useState("");
  const [model, setModel] = useState("");
  const [investigating, setInvestigating] = useState(false);
  const [seeding, setSeeding] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState({ nodes: 0, edges: 0 });
  const [booted, setBooted] = useState(false);

  const logIdRef = useRef(0);
  const terminalRef = useRef<HTMLDivElement>(null);

  const pushLog = useCallback((line: Omit<LogLine, "id">) => {
    logIdRef.current += 1;
    setLogs((prev) => [...prev, { id: logIdRef.current, ...line }]);
  }, []);

  const applyGraph = useCallback(
    (graph: GraphResponse) => {
      setNodes(toFlowNodes(graph));
      setEdges(toFlowEdges(graph));
      setStats({ nodes: graph.nodes.length, edges: graph.edges.length });
    },
    [setNodes, setEdges]
  );

  /* -- boot ------------------------------------------------------- */
  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        const graph = await api<GraphResponse>("/api/graph");
        if (cancelled) return;
        applyGraph(graph);
        setBooted(true);
        pushLog({
          type: "info",
          title: "Graph loaded",
          detail: `${graph.nodes.length} nodes · ${graph.edges.length} relationships`,
        });
      } catch (err) {
        if (cancelled) return;
        setBooted(true);
        setError(
          `Could not reach the backend: ${(err as Error).message}. Is FastAPI running on :8000?`
        );
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [applyGraph, pushLog]);

  /* -- live topology poll ---------------------------------------- */
  /* Surfaces graph mutations performed outside the browser (e.g. the
     OpenCode-native /triage run over the blastshield MCP server). Node
     positions are preserved so operator drags are not clobbered. */
  useEffect(() => {
    if (!booted) return;
    const timer = window.setInterval(async () => {
      if (investigating || seeding) return;
      try {
        const graph = await api<GraphResponse>("/api/graph");
        setNodes((prev) =>
          toFlowNodes(graph).map((node) => {
            const existing = prev.find((p) => p.id === node.id);
            return existing ? { ...node, position: existing.position } : node;
          })
        );
        setEdges(toFlowEdges(graph));
        setStats({ nodes: graph.nodes.length, edges: graph.edges.length });
      } catch {
        /* transient poll failure — keep the last good graph */
      }
    }, 3000);
    return () => window.clearInterval(timer);
  }, [booted, investigating, seeding, setNodes, setEdges]);

  /* -- terminal autoscroll --------------------------------------- */
  useEffect(() => {
    const el = terminalRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [logs, investigating]);

  /* -- actions ---------------------------------------------------- */
  const resetGraph = useCallback(async () => {
    setSeeding(true);
    setError(null);
    setSummary("");
    setLogs([]);
    try {
      const res = await api<SeedResponse>("/api/seed", { method: "POST" });
      applyGraph(res.graph_state);
      pushLog({
        type: "info",
        title: "Graph reset",
        detail: `Reseeded '${res.graph}' → ${res.nodes} nodes / ${res.edges} relationships`,
      });
    } catch (err) {
      const message = (err as Error).message;
      setError(message);
      pushLog({ type: "error", title: "Reset failed", detail: message });
    } finally {
      setSeeding(false);
    }
  }, [applyGraph, pushLog]);

  const investigate = useCallback(async () => {
    setInvestigating(true);
    setError(null);
    setSummary("");
    setLogs([]);
    pushLog({
      type: "info",
      title: "Incident triage started",
      detail: "ALT-9021 · dispatching autonomous BlastShield agent…",
    });

    try {
      const res = await api<InvestigateResponse>("/api/investigate", {
        method: "POST",
        body: JSON.stringify({ max_steps: 12 }),
      });
      if (!res.ok) throw new Error(res.error ?? "Investigation failed");

      setModel(res.model ?? "");
      applyGraph(res.graph);

      for (const event of res.trace) {
        pushLog({ type: event.type, title: event.title, detail: event.detail });
        if (event.type !== "final") await sleep(360);
      }

      setSummary(res.summary ?? "");
      pushLog({
        type: "info",
        title: "Containment workflow complete",
        detail: `model=${res.model ?? "?"} · steps=${res.steps ?? "?"}`,
      });
    } catch (err) {
      const message = (err as Error).message;
      setError(message);
      pushLog({ type: "error", title: "Investigation failed", detail: message });
    } finally {
      setInvestigating(false);
    }
  }, [applyGraph, pushLog]);

  const busy = investigating || seeding;

  /* -- derived minimap ------------------------------------------- */
  const minimapColor = useMemo(
    () => (node: Node) => {
      const kind = (node.data as { kind?: string }).kind ?? "Unknown";
      const status = (node.data as { status?: string }).status;
      if (status === "QUARANTINED" || status === "REVOKED") return "#dc2626";
      return themeFor(kind).color;
    },
    []
  );

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#05070d] text-slate-200">
      {/* ---------------- GRAPH (65%) ---------------- */}
      <section className="relative h-full w-[65%] border-r border-slate-800">
        <div className="pointer-events-none absolute left-4 top-4 z-10">
          <div className="pointer-events-auto flex items-center gap-3 rounded-xl border border-slate-800 bg-[#0b1220]/90 px-4 py-3 backdrop-blur">
            <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-rose-600/15 text-rose-400">
              <ShieldAlert size={20} />
            </span>
            <div>
              <h1 className="text-sm font-bold tracking-tight text-slate-100">
                BlastShield
              </h1>
              <p className="text-[11px] text-slate-400">
                FalkorDB cloud topology · {stats.nodes} nodes / {stats.edges} edges
              </p>
            </div>
          </div>
        </div>

        <div className="pointer-events-none absolute bottom-4 left-4 z-10 flex flex-wrap gap-2">
          {(
            [
              ["Alert", "#ef4444"],
              ["Workload", "#38bdf8"],
              ["SecurityGroup", "#f59e0b"],
              ["IAMRole", "#a78bfa"],
              ["DataStore", "#10b981"],
              ["PII", "#e11d48"],
              ["Contained", "#dc2626"],
            ] as const
          ).map(([label, color]) => (
            <span
              key={label}
              className="flex items-center gap-1.5 rounded-full border border-slate-800 bg-[#0b1220]/90 px-2.5 py-1 text-[10px] font-medium text-slate-400 backdrop-blur"
            >
              <span
                className="h-2 w-2 rounded-full"
                style={{ background: color, boxShadow: `0 0 8px ${color}` }}
              />
              {label}
            </span>
          ))}
        </div>

        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          fitView
          minZoom={0.25}
          maxZoom={1.75}
          proOptions={{ hideAttribution: true }}
          defaultEdgeOptions={{ type: "smoothstep" }}
        >
          <Background
            variant={BackgroundVariant.Dots}
            gap={26}
            size={1}
            color="#1e293b"
          />
          <Controls showInteractive={false} />
          <MiniMap
            pannable
            zoomable
            nodeColor={minimapColor}
            maskColor="rgba(5,7,13,0.75)"
            style={{ background: "#0b1220", border: "1px solid #1e293b" }}
          />
        </ReactFlow>
      </section>

      {/* ---------------- CONSOLE (35%) ---------------- */}
      <aside className="console-grid flex h-full w-[35%] flex-col bg-[#070b14]">
        <header className="border-b border-slate-800 px-5 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <TerminalIcon size={16} className="text-cyan-400" />
              <h2 className="text-xs font-bold uppercase tracking-[0.22em] text-cyan-300">
                SecOps Control Console
              </h2>
            </div>
            <span className="flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-emerald-400">
              <Radio size={10} className="animate-pulse" />
              live
            </span>
          </div>
          <p className="mt-1 font-mono text-[11px] text-slate-500">
            target: secops_graph · incident: ALT-9021
            {model ? ` · model: ${model}` : ""}
          </p>
        </header>

        {/* Controls */}
        <div className="grid grid-cols-2 gap-3 border-b border-slate-800 px-5 py-4">
          <button
            type="button"
            onClick={investigate}
            disabled={busy}
            className="group flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-rose-600 to-red-500 px-3 py-3 text-sm font-bold text-white shadow-lg shadow-rose-900/30 transition hover:from-rose-500 hover:to-red-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {investigating ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              <Play size={16} />
            )}
            {investigating ? "Triaging…" : "🚨 Trigger Triage"}
          </button>

          <button
            type="button"
            onClick={resetGraph}
            disabled={busy}
            className="flex items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-3 text-sm font-bold text-slate-200 transition hover:bg-slate-700/60 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {seeding ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              <RotateCcw size={16} />
            )}
            {seeding ? "Reseeding…" : "Reset Graph"}
          </button>
        </div>

        {error && (
          <div className="flex items-start gap-2 border-b border-red-900/50 bg-red-950/40 px-5 py-3 text-[11px] text-red-300">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Terminal */}
        <div
          ref={terminalRef}
          className="flex-1 overflow-y-auto px-5 py-4 font-mono text-[11px] leading-relaxed"
        >
          {logs.length === 0 && !investigating && (
            <p className="text-slate-600">
              Awaiting operator input… run{" "}
              <span className="text-cyan-400">/triage</span> inside OpenCode to drive
              the agent over MCP, or press{" "}
              <span className="text-rose-400">Trigger Triage</span> for the in-process
              agent. The topology auto-refreshes every 3s.
            </p>
          )}

          <div className="space-y-3">
            {logs.map((line) => {
              const meta = LOG_META[line.type] ?? LOG_META.info;
              return (
                <div key={line.id} className="flex flex-col gap-0.5">
                  <div className="flex items-baseline gap-2">
                    <span className={`shrink-0 font-bold ${meta.tagClass}`}>
                      [{meta.tag}]
                    </span>
                    <span className={`font-semibold ${meta.textClass}`}>
                      {line.title}
                    </span>
                  </div>
                  {line.detail && (
                    <pre className="ml-[52px] whitespace-pre-wrap break-words text-[10.5px] text-slate-400">
                      {line.detail}
                    </pre>
                  )}
                </div>
              );
            })}
          </div>

          {investigating && (
            <div className="mt-3 flex items-center gap-2 text-slate-500">
              <Loader2 size={12} className="animate-spin" />
              <span className="caret-blink">▋</span>
              agent reasoning…
            </div>
          )}
        </div>

        {/* Post-mortem */}
        {summary && (
          <div className="max-h-[38%] shrink-0 overflow-y-auto border-t border-fuchsia-900/40 bg-fuchsia-950/10 px-5 py-4">
            <div className="mb-2 flex items-center gap-2 text-fuchsia-300">
              <CheckCircle2 size={14} />
              <h3 className="text-[11px] font-bold uppercase tracking-[0.2em]">
                Post-Mortem
              </h3>
            </div>
            <p className="whitespace-pre-wrap text-[11.5px] leading-relaxed text-slate-300">
              {summary}
            </p>
          </div>
        )}

        <footer className="border-t border-slate-800 px-5 py-2 text-[10px] text-slate-600">
          {booted ? "connected" : "connecting…"} · graph queries via FalkorDB ·
          agent via blastshield MCP server
        </footer>
      </aside>
    </div>
  );
}
