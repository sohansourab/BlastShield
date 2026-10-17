// Shared API contracts between the BlastShield FastAPI backend and the UI.

export type NodeKind =
  | "Alert"
  | "Workload"
  | "SecurityGroup"
  | "IAMRole"
  | "DataStore"
  | "Commit"
  | "User"
  | "Unknown";

export type DataClassification = "RESTRICTED_PII" | "INTERNAL" | "PUBLIC" | string;

export interface GraphNodeData {
  // Identity & type
  id: string;
  type: NodeKind;
  kind: NodeKind;
  name?: string;
  labels?: string[];

  // Common lifecycle
  status?: string;

  // Alert
  title?: string;
  severity?: string;
  source?: string;
  detected_at?: string;

  // Workload
  namespace?: string;
  replicas?: number;
  image?: string;
  region?: string;
  quarantined_at?: string;
  quarantine_reason?: string;

  // SecurityGroup
  inbound_rule?: string;
  vpc?: string;

  // IAMRole
  arn?: string;
  revoked_at?: string;
  revoke_reason?: string;

  // DataStore
  service?: string;
  classification?: DataClassification;
  record_count?: number;
  encrypted?: boolean;

  // Commit / User
  sha?: string;
  message?: string;
  authored_by?: string;
  committed_at?: string;
  branch?: string;
  email?: string;
  team?: string;

  // Allow any additional server-side property without breaking the UI.
  [key: string]: unknown;
}

export interface GraphNode {
  id: string;
  type: NodeKind;
  label: string;
  position: { x: number; y: number };
  data: GraphNodeData;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
  data?: Record<string, unknown>;
}

export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export type TraceEventType =
  | "info"
  | "thought"
  | "tool_call"
  | "tool_result"
  | "final"
  | "error";

export interface TraceEvent {
  type: TraceEventType;
  title: string;
  detail?: string;
  data?: unknown;
}

export interface InvestigateResponse {
  ok: boolean;
  incident?: string;
  model?: string;
  steps?: number;
  summary?: string;
  trace: TraceEvent[];
  graph: GraphResponse;
  error?: string;
}

export interface SeedResponse {
  ok: boolean;
  graph: string;
  nodes: number;
  edges: number;
  seeded_at: string;
  graph_state: GraphResponse;
}

export interface ToolManifestEntry {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface ToolsResponse {
  tools: ToolManifestEntry[];
}
