import type {
  AiConfigSummary,
  AiProvider,
  AiValidationResult,
  AnalyzeThreatsRequest,
  CodeGraph,
  CodeSymbol,
  DeleteAiConfigRequest,
  DescribeNodeRequest,
  GraphNode,
  NodeDescriptionReport,
  NodeThreatReport,
  SaveAiConfigRequest,
  ValidateAiKeyRequest,
} from "@adam/core";

export interface NodeResponse {
  node: GraphNode;
  content: string;
  masked: boolean;
  redactions: number;
}

export interface SymbolResponse {
  symbol: CodeSymbol;
  content: string;
  masked: boolean;
  redactions: number;
}

/**
 * Everything the UI needs from wherever it runs. The VS Code webview talks to the extension
 * over postMessage; the internal browser dev/test harness talks to the local Adam service
 * over HTTP. AI key management and provider calls are available only in the extension.
 */
export interface Host {
  readonly kind: "vscode" | "browser";
  getGraph(): Promise<CodeGraph>;
  getNode(id: string): Promise<NodeResponse>;
  getSymbol(nodeId: string, symbolId: string): Promise<SymbolResponse>;
  reindex(): Promise<void>;
  onGraphChanged(listener: () => void): void;
  /** Opens the file in a real editor for manual editing. Absent when there is no editor. */
  openFile?(path: string, line?: number): void;

  // --- AI Provider & Key Management ---
  getAiConfig(): Promise<AiConfigSummary>;
  saveAiConfig(req: SaveAiConfigRequest): Promise<AiConfigSummary>;
  deleteAiConfig(provider: AiProvider): Promise<AiConfigSummary>;
  setActiveAiProvider(provider: AiProvider): Promise<AiConfigSummary>;
  validateAiKey(req: ValidateAiKeyRequest): Promise<AiValidationResult>;
  listAiModels(provider: AiProvider, apiKey?: string): Promise<string[]>;
  describeNode(req: DescribeNodeRequest): Promise<NodeDescriptionReport>;
  analyzeNodeThreats(req: AnalyzeThreatsRequest): Promise<NodeThreatReport>;
}

/** Messages exchanged between the webview and the extension. */
export type WebviewRequest =
  | { type: "request"; id: number; method: "graph" }
  | { type: "request"; id: number; method: "node"; params: { id: string } }
  | { type: "request"; id: number; method: "symbol"; params: { node: string; id: string } }
  | { type: "request"; id: number; method: "reindex" }
  | { type: "openFile"; path: string; line?: number }
  // --- AI Config Methods ---
  | { type: "request"; id: number; method: "ai:getConfig" }
  | { type: "request"; id: number; method: "ai:saveConfig"; params: SaveAiConfigRequest }
  | { type: "request"; id: number; method: "ai:deleteConfig"; params: DeleteAiConfigRequest }
  | { type: "request"; id: number; method: "ai:setActive"; params: { provider: AiProvider } }
  | { type: "request"; id: number; method: "ai:validateKey"; params: ValidateAiKeyRequest }
  | { type: "request"; id: number; method: "ai:listModels"; params: { provider: AiProvider; apiKey?: string } }
  | { type: "request"; id: number; method: "ai:describeNode"; params: DescribeNodeRequest }
  | { type: "request"; id: number; method: "ai:analyzeThreats"; params: AnalyzeThreatsRequest };

export type ExtensionMessage =
  | { type: "response"; id: number; ok: true; result: unknown }
  | { type: "response"; id: number; ok: false; error: string }
  | { type: "event"; event: "graph" };

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
type RequestBody = DistributiveOmit<Extract<WebviewRequest, { type: "request" }>, "id">;

export interface VsCodeApi {
  postMessage(message: WebviewRequest): void;
}

declare function acquireVsCodeApi(): VsCodeApi;

export function createVsCodeHost(api: VsCodeApi): Host {
  let nextId = 1;
  const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  const listeners: Array<() => void> = [];

  window.addEventListener("message", (e: MessageEvent<ExtensionMessage>) => {
    const msg = e.data;
    if (msg.type === "event") listeners.forEach((l) => l());
    if (msg.type !== "response") return;
    const p = pending.get(msg.id);
    if (!p) return;
    pending.delete(msg.id);
    if (msg.ok) p.resolve(msg.result);
    else p.reject(new Error(msg.error));
  });

  const request = <T>(req: RequestBody): Promise<T> =>
    new Promise<T>((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      api.postMessage({ ...req, id } as WebviewRequest);
    });

  return {
    kind: "vscode",
    getGraph: () => request({ type: "request", method: "graph" }),
    getNode: (id) => request({ type: "request", method: "node", params: { id } }),
    getSymbol: (node, id) => request({ type: "request", method: "symbol", params: { node, id } }),
    reindex: () => request({ type: "request", method: "reindex" }),
    onGraphChanged: (l) => listeners.push(l),
    openFile: (path, line) => api.postMessage({ type: "openFile", path, line }),
    getAiConfig: () => request({ type: "request", method: "ai:getConfig" }),
    saveAiConfig: (req) => request({ type: "request", method: "ai:saveConfig", params: req }),
    deleteAiConfig: (provider) => request({ type: "request", method: "ai:deleteConfig", params: { provider } }),
    setActiveAiProvider: (provider) => request({ type: "request", method: "ai:setActive", params: { provider } }),
    validateAiKey: (req) => request({ type: "request", method: "ai:validateKey", params: req }),
    listAiModels: (provider, apiKey) => request({ type: "request", method: "ai:listModels", params: { provider, apiKey } }),
    describeNode: (req) => request({ type: "request", method: "ai:describeNode", params: req }),
    analyzeNodeThreats: (req) => request({ type: "request", method: "ai:analyzeThreats", params: req }),
  };
}

export function createBrowserHost(): Host {
  // The token rides in the URL fragment, which browsers never send to a server or a referrer.
  const token = new URLSearchParams(location.hash.slice(1)).get("token") ?? "";
  const call = async <T>(path: string, init: RequestInit = {}): Promise<T> => {
    const res = await fetch(path, { ...init, headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) throw new Error(((await res.json().catch(() => ({}))) as { error?: string }).error ?? res.statusText);
    return (await res.json()) as T;
  };
  return {
    kind: "browser",
    getGraph: () => call("/api/graph"),
    getNode: (id) => call(`/api/node?id=${encodeURIComponent(id)}`),
    getSymbol: (node, id) => call(`/api/symbol?node=${encodeURIComponent(node)}&id=${encodeURIComponent(id)}`),
    reindex: async () => void (await call("/api/reindex", { method: "POST" })),
    onGraphChanged: (listener) => {
      const events = new EventSource(`/api/events?token=${encodeURIComponent(token)}`);
      events.addEventListener("graph", () => listener());
    },
    getAiConfig: () => Promise.reject(new Error("AI features are available in the VS Code extension only.")),
    saveAiConfig: () => Promise.reject(new Error("AI features are available in the VS Code extension only.")),
    deleteAiConfig: () => Promise.reject(new Error("AI features are available in the VS Code extension only.")),
    setActiveAiProvider: () => Promise.reject(new Error("AI features are available in the VS Code extension only.")),
    validateAiKey: () => Promise.reject(new Error("AI features are available in the VS Code extension only.")),
    listAiModels: () => Promise.reject(new Error("AI features are available in the VS Code extension only.")),
    describeNode: () => Promise.reject(new Error("AI features are available in the VS Code extension only.")),
    analyzeNodeThreats: () => Promise.reject(new Error("AI features are available in the VS Code extension only.")),
  };
}

export function createHost(): Host {
  return typeof acquireVsCodeApi === "function" ? createVsCodeHost(acquireVsCodeApi()) : createBrowserHost();
}
