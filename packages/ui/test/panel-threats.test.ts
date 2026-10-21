import { describe, expect, it, vi, beforeEach } from "vitest";
import type { GraphNode, NodeDescriptionReport, NodeThreatReport } from "@adam/core";
import {
  descriptionCache,
  patchedThreats,
  renderNodePanel,
  threatCache,
  type PanelContext,
} from "../src/panel";
import type { Host } from "../src/host";

// --- Minimal In-Memory DOM Shim for testing UI in Node environment ---

class MockNode {
  nodeType = 1;
  _textContent: string = "";
  children: MockNode[] = [];
  parentElement: MockNode | null = null;
  attributes: Record<string, string> = {};
  eventListeners: Record<string, Array<(e: any) => void>> = {};

  get textContent(): string {
    if (this.nodeType === 3) return this._textContent;
    return this.children.map((c) => c.textContent).join("");
  }

  set textContent(value: string) {
    if (this.nodeType === 3) {
      this._textContent = value;
    } else {
      this.children = [];
      if (value) {
        const textNode = new MockNode();
        textNode.nodeType = 3;
        textNode._textContent = value;
        textNode.parentElement = this;
        this.children.push(textNode);
      }
    }
  }

  append(...nodes: (MockNode | string | null | undefined | false)[]) {
    for (const n of nodes) {
      if (!n && n !== "") continue;
      if (typeof n === "string") {
        const textNode = new MockNode();
        textNode.nodeType = 3;
        textNode._textContent = n;
        this.children.push(textNode);
        textNode.parentElement = this;
      } else {
        this.children.push(n);
        n.parentElement = this;
      }
    }
  }

  replaceChildren(...nodes: (MockNode | string)[]) {
    this.children = [];
    this.append(...nodes);
  }

  remove() {
    if (this.parentElement) {
      this.parentElement.children = this.parentElement.children.filter((c) => c !== this);
      this.parentElement = null;
    }
  }

  addEventListener(type: string, listener: (e: any) => void) {
    this.eventListeners[type] = this.eventListeners[type] ?? [];
    this.eventListeners[type].push(listener);
  }

  removeEventListener(type: string, listener: (e: any) => void) {
    if (this.eventListeners[type]) {
      this.eventListeners[type] = this.eventListeners[type].filter((l) => l !== listener);
    }
  }

  dispatchEvent(event: { type: string; [k: string]: any }): boolean {
    const listeners = this.eventListeners[event.type] ?? [];
    for (const l of listeners) {
      l({
        ...event,
        currentTarget: this,
        target: event.target ?? this,
        stopPropagation: () => {},
      });
    }
    return true;
  }

  click() {
    this.dispatchEvent({ type: "click" });
  }

  setAttribute(name: string, value: string) {
    this.attributes[name] = String(value);
  }

  getAttribute(name: string) {
    return this.attributes[name] ?? null;
  }

  removeAttribute(name: string) {
    delete this.attributes[name];
  }

  querySelector(selector: string): MockElement | null {
    const all = this.querySelectorAll(selector);
    return all[0] ?? null;
  }

  querySelectorAll(selector: string): MockElement[] {
    const results: MockElement[] = [];
    const check = (node: MockNode) => {
      if (node instanceof MockElement) {
        if (selector.startsWith(".")) {
          const classes = selector.split(".").filter(Boolean);
          const elClasses = node.className.split(/\s+/).filter(Boolean);
          if (classes.every((c) => elClasses.includes(c))) {
            results.push(node);
          }
        } else if (selector.startsWith("#") && node.id === selector.slice(1)) {
          results.push(node);
        } else if (node.tagName.toLowerCase() === selector.toLowerCase()) {
          results.push(node);
        }
      }
      for (const child of node.children) {
        check(child);
      }
    };
    for (const child of this.children) {
      check(child);
    }
    return results;
  }
}

class MockElement extends MockNode {
  tagName: string;
  className: string = "";
  id: string = "";
  value: string = "";
  type: string = "text";
  disabled: boolean = false;
  selected: boolean = false;
  hidden: boolean = false;
  title: string = "";
  style: Record<string, string> = {};

  constructor(tagName: string) {
    super();
    this.tagName = tagName.toUpperCase();
  }

  get classList() {
    const el = this;
    return {
      contains: (cls: string) => el.className.split(/\s+/).includes(cls),
      add: (cls: string) => {
        const set = new Set(el.className.split(/\s+/).filter(Boolean));
        set.add(cls);
        el.className = Array.from(set).join(" ");
      },
      remove: (cls: string) => {
        const set = new Set(el.className.split(/\s+/).filter(Boolean));
        set.delete(cls);
        el.className = Array.from(set).join(" ");
      },
      toggle: (cls: string) => {
        const set = new Set(el.className.split(/\s+/).filter(Boolean));
        if (set.has(cls)) set.delete(cls);
        else set.add(cls);
        el.className = Array.from(set).join(" ");
      },
    };
  }

  override setAttribute(name: string, value: string) {
    super.setAttribute(name, value);
    if (name === "type") this.type = value;
    if (name === "value") this.value = value;
    if (name === "id") this.id = value;
    if (name === "class") this.className = value;
    if (name === "title") this.title = value;
    if (name === "disabled") this.disabled = true;
  }

  focus() {}
}

function setupMockDom() {
  const body = new MockElement("body");
  const winListeners: Record<string, Array<(e: any) => void>> = {};

  const doc = {
    body,
    activeElement: null as any,
    createElement: (tag: string) => new MockElement(tag),
    createTextNode: (text: string) => {
      const node = new MockNode();
      node.nodeType = 3;
      node.textContent = text;
      return node;
    },
  };

  const win = {
    addEventListener: (type: string, listener: (e: any) => void) => {
      winListeners[type] = winListeners[type] ?? [];
      winListeners[type].push(listener);
    },
    removeEventListener: (type: string, listener: (e: any) => void) => {
      if (winListeners[type]) {
        winListeners[type] = winListeners[type].filter((l) => l !== listener);
      }
    },
    dispatchEvent: (event: any) => {
      const listeners = winListeners[event.type] ?? [];
      for (const l of listeners) l(event);
    },
  };

  (globalThis as any).document = doc;
  (globalThis as any).window = win;

  return { doc, win };
}

function makeNode(overrides: Partial<GraphNode> = {}): GraphNode {
  return {
    id: "src/auth.ts",
    name: "auth.ts",
    folder: "src",
    ext: ".ts",
    hash: "abc123hash",
    size: 2048,
    lines: 120,
    language: "typescript",
    binary: false,
    sensitive: false,
    secretHints: 0,
    parsed: true,
    symbols: [],
    packages: [],
    envReads: [],
    envDeclares: [],
    unresolved: [],
    ...overrides,
  };
}

function makeHost(overrides: Partial<Host> = {}): Host {
  return {
    kind: "browser",
    getGraph: vi.fn(),
    getNode: vi.fn(),
    getSymbol: vi.fn(),
    reindex: vi.fn(),
    onGraphChanged: vi.fn(),
    openFile: vi.fn(),
    getAiConfig: vi.fn().mockResolvedValue({
      activeProvider: "chatgpt",
      providers: {
        chatgpt: { provider: "chatgpt", configured: true, selectedModel: "gpt-4o" },
        claude: { provider: "claude", configured: false },
        grok: { provider: "grok", configured: false },
        gemini: { provider: "gemini", configured: false },
      },
    }),
    saveAiConfig: vi.fn(),
    deleteAiConfig: vi.fn(),
    setActiveAiProvider: vi.fn(),
    validateAiKey: vi.fn(),
    listAiModels: vi.fn().mockResolvedValue([]),
    describeNode: vi.fn(),
    analyzeNodeThreats: vi.fn(),
    ...overrides,
  };
}

const sampleReport: NodeThreatReport = {
  nodeId: "src/auth.ts",
  provider: "chatgpt",
  model: "gpt-4o",
  analyzedAt: "2026-10-20T10:00:00Z",
  summary: "Found SQL injection and hardcoded credential risks in authentication flow.",
  overallRisk: "high",
  masked: false,
  redactions: 0,
  threats: [
    {
      id: "THREAT-1",
      title: "SQL Injection in login query",
      category: "injection",
      severity: "critical",
      description: "Direct string concatenation into SQL query allows authentication bypass.",
      location: { line: 42, symbolName: "login" },
      recommendation: "Use parameterized queries or ORM placeholders instead of string templates.",
    },
    {
      id: "THREAT-2",
      title: "Weak hashing algorithm",
      category: "crypto",
      severity: "medium",
      description: "MD5 is used for password hashing which is susceptible to collision attacks.",
      location: { line: 88, symbolName: "hashPassword" },
      recommendation: "Migrate to argon2id or bcrypt with work factor >= 12.",
    },
  ],
};

const sampleDescription: NodeDescriptionReport = {
  nodeId: "src/auth.ts",
  nodeHash: "abc123hash",
  provider: "chatgpt",
  model: "gpt-4o",
  analyzedAt: "2026-10-20T10:00:00Z",
  summary: "Defines the authentication workflow for the application.",
  purpose: "Validate credentials and establish authenticated sessions.",
  responsibilities: ["Validate login input", "Create signed session tokens"],
  keySymbols: [
    {
      name: "login",
      kind: "function",
      description: "Validates credentials and returns a session token.",
      line: 42,
    },
  ],
  dependencies: ["jsonwebtoken signs session tokens"],
  dataFlow: ["Credentials enter through login", "A signed token is returned"],
  notableDetails: ["Reads AUTH_SECRET from configuration"],
  confidence: "high",
  masked: false,
  redactions: 1,
};

describe("Node Security Threats Panel", () => {
  beforeEach(() => {
    setupMockDom();
    descriptionCache.clear();
    threatCache.clear();
    patchedThreats.clear();
  });

  it("renders a safe description for the selected file", () => {
    const container = new MockElement("div") as any;
    const node = makeNode({
      symbols: [
        { id: "Auth", name: "Auth", kind: "class", exported: true, signature: "class Auth", start: { line: 1, column: 0 }, end: { line: 8, column: 1 } },
        { id: "Auth.login", name: "login", kind: "method", exported: false, parent: "Auth", signature: "login()", start: { line: 2, column: 2 }, end: { line: 6, column: 3 } },
      ],
      packages: ["zod"],
      envReads: ["AUTH_SECRET"],
    });
    const ctx: PanelContext = {
      host: makeHost(),
      incoming: [{ id: "src/app.ts->src/auth.ts:imports", source: "src/app.ts", target: node.id, kind: "imports", specifier: "./auth", typeOnly: false }],
      outgoing: [
        { id: "src/auth.ts->src/db.ts:imports", source: node.id, target: "src/db.ts", kind: "imports", specifier: "./db", typeOnly: false },
        { id: "src/auth.ts->src/types.ts:imports", source: node.id, target: "src/types.ts", kind: "imports", specifier: "./types", typeOnly: true },
      ],
      onSelect: vi.fn(),
    };

    renderNodePanel(container, node, ctx);

    const description = container.querySelector(".panel-description");
    expect(description).toBeTruthy();
    expect(description.textContent).toContain("TypeScript source");
    expect(description.textContent).toContain("defines 1 class, 1 method");
    expect(description.textContent).toContain("imports 2 local files");
    expect(description.textContent).toContain("is imported by 1 file");
    expect(description.textContent).toContain("uses zod");
    expect(description.textContent).toContain("reads 1 environment or configuration value");
  });

  it("describes protected and binary files without exposing contents", () => {
    const container = new MockElement("div") as any;
    const ctx: PanelContext = { host: makeHost(), incoming: [], outgoing: [], onSelect: vi.fn() };

    renderNodePanel(container, makeNode({ language: "dotenv", sensitive: true, envDeclares: ["API_KEY"] }), ctx);
    expect(container.querySelector(".panel-description")?.textContent).toContain("values remain hidden");
    expect(container.querySelector(".panel-description")?.textContent).toContain("declared key");

    renderNodePanel(container, makeNode({ language: "png", binary: true }), ctx);
    expect(container.querySelector(".panel-description")?.textContent).toContain("binary png file");
    expect(container.querySelector(".panel-description")?.textContent).toContain("not parsed");
  });

  it("checks and describes a selected non-sensitive file with the active provider", async () => {
    const container = new MockElement("div") as any;
    const node = makeNode();
    const host = makeHost({
      kind: "vscode",
      describeNode: vi.fn().mockResolvedValue(sampleDescription),
    });
    const ctx: PanelContext = { host, incoming: [], outgoing: [], onSelect: vi.fn() };

    renderNodePanel(container, node, ctx);
    const describeBtn = container.querySelector(".node-describe-btn");
    expect(describeBtn).toBeTruthy();
    expect(describeBtn.textContent).toContain("Check & Describe");

    describeBtn.click();
    expect(host.describeNode).toHaveBeenCalledWith({ nodeId: node.id, forceRefresh: false });

    await vi.waitFor(() => {
      expect(container.querySelector(".node-description-report")).toBeTruthy();
    });

    expect(descriptionCache.get(node.id)).toEqual(sampleDescription);
    expect(container.textContent).toContain("Defines the authentication workflow");
    expect(container.textContent).toContain("Validate login input");
    expect(container.textContent).toContain("1 secret-looking value was excluded before analysis");

    container.querySelector(".node-description-symbols")?.querySelector(".link")?.click();
    expect(host.openFile).toHaveBeenCalledWith(node.id, 42);
  });

  it("does not offer AI description for sensitive files", () => {
    const container = new MockElement("div") as any;
    const host = makeHost({ kind: "vscode", describeNode: vi.fn() });
    const node = makeNode({ sensitive: true, sensitiveReason: "Contains credentials" });

    renderNodePanel(container, node, { host, incoming: [], outgoing: [], onSelect: vi.fn() });

    expect(container.querySelector(".node-describe-btn")).toBeNull();
    expect(container.querySelector(".node-description-sensitive-notice")?.textContent).toContain(
      "will not be sent to an external model",
    );
    expect(host.describeNode).not.toHaveBeenCalled();
  });

  it("discards a cached description when the node hash changes", () => {
    const container = new MockElement("div") as any;
    const host = makeHost({ kind: "vscode" });
    descriptionCache.set("src/auth.ts", sampleDescription);

    renderNodePanel(
      container,
      makeNode({ hash: "changed-hash" }),
      { host, incoming: [], outgoing: [], onSelect: vi.fn() },
    );

    expect(descriptionCache.has("src/auth.ts")).toBe(false);
    expect(container.querySelector(".node-describe-btn")).toBeTruthy();
    expect(container.querySelector(".node-description-report")).toBeNull();
  });

  it("renders unscanned state with prominent trace button and subtitle", () => {
    const container = new MockElement("div") as any;
    const node = makeNode();
    const host = makeHost();
    const ctx: PanelContext = {
      host,
      incoming: [],
      outgoing: [],
      onSelect: vi.fn(),
    };

    renderNodePanel(container, node, ctx);

    const scanBtn = container.querySelector(".threat-scan-btn");
    expect(scanBtn).toBeTruthy();
    expect(scanBtn.textContent).toContain("Trace Potential Threats");
    expect(scanBtn.title).toContain("Audit this file for vulnerabilities, loopholes, and attack vectors");

    const subtitle = container.querySelector(".threat-scan-subtitle");
    expect(subtitle).toBeTruthy();
    expect(subtitle.textContent).toContain("Audit this file for vulnerabilities, loopholes, and attack vectors");
  });

  it("clicking scan button triggers host.analyzeNodeThreats and displays scanned report", async () => {
    const container = new MockElement("div") as any;
    const node = makeNode();
    const host = makeHost({
      analyzeNodeThreats: vi.fn().mockResolvedValue(sampleReport),
    });
    const ctx: PanelContext = {
      host,
      incoming: [],
      outgoing: [],
      onSelect: vi.fn(),
    };

    renderNodePanel(container, node, ctx);

    const scanBtn = container.querySelector(".threat-scan-btn");
    expect(scanBtn).toBeTruthy();

    scanBtn.click();

    expect(host.analyzeNodeThreats).toHaveBeenCalledWith({
      nodeId: "src/auth.ts",
      forceRefresh: false,
    });

    await vi.waitFor(() => {
      expect(container.querySelector(".threat-cards-list")).toBeTruthy();
    });

    expect(threatCache.get(node.id)).toEqual(sampleReport);
    expect(container.textContent).toContain("Security Threats (2)");
  });

  it("renders threat cards with severity badges, category chips, line links, and remediation", () => {
    const container = new MockElement("div") as any;
    const node = makeNode();
    const host = makeHost();
    const ctx: PanelContext = {
      host,
      incoming: [],
      outgoing: [],
      onSelect: vi.fn(),
    };

    threatCache.set(node.id, sampleReport);
    renderNodePanel(container, node, ctx);

    const cards = container.querySelectorAll(".threat-card");
    expect(cards).toHaveLength(2);

    // First card: Critical SQL Injection
    const card1 = cards[0];
    expect(card1.textContent).toContain("SQL Injection in login query");
    expect(card1.textContent).toContain("Direct string concatenation");

    const badge1 = card1.querySelector(".threat-severity-badge");
    expect(badge1).toBeTruthy();
    expect(badge1.textContent).toContain("CRITICAL");
    expect(badge1.className).toContain("severity-critical");

    const catChip1 = card1.querySelector(".threat-category-chip");
    expect(catChip1).toBeTruthy();
    expect(catChip1.textContent).toContain("Injection");

    const lineLink1 = card1.querySelector(".threat-location-link");
    expect(lineLink1).toBeTruthy();
    expect(lineLink1.textContent).toContain("Line 42");

    lineLink1.click();
    expect(host.openFile).toHaveBeenCalledWith("src/auth.ts", 42);

    const remBox1 = card1.querySelector(".threat-remediation-box");
    expect(remBox1).toBeTruthy();
    expect(remBox1.textContent).toContain("💡 Remediation: Use parameterized queries");

    // Second card: Medium Weak hashing
    const card2 = cards[1];
    expect(card2.textContent).toContain("Weak hashing algorithm");
    const badge2 = card2.querySelector(".threat-severity-badge");
    expect(badge2.textContent).toContain("MEDIUM");
    expect(badge2.className).toContain("severity-medium");
  });

  it("toggles mark-as-patched on individual threat cards", () => {
    const container = new MockElement("div") as any;
    const node = makeNode();
    const host = makeHost();
    const ctx: PanelContext = {
      host,
      incoming: [],
      outgoing: [],
      onSelect: vi.fn(),
    };

    threatCache.set(node.id, sampleReport);
    renderNodePanel(container, node, ctx);

    const cards = container.querySelectorAll(".threat-card");
    const card1 = cards[0];

    expect(card1.classList.contains("patched")).toBe(false);
    expect(card1.querySelector(".threat-patched-badge")).toBeNull();

    const patchBtn = card1.querySelector(".threat-patch-btn");
    expect(patchBtn).toBeTruthy();
    expect(patchBtn.textContent).toContain("Mark as Patched");

    // Click to mark as patched
    patchBtn.click();

    const updatedCard1 = container.querySelectorAll(".threat-card")[0];
    expect(updatedCard1.classList.contains("patched")).toBe(true);

    const patchedBadge = updatedCard1.querySelector(".threat-patched-badge");
    expect(patchedBadge).toBeTruthy();
    expect(patchedBadge.textContent).toContain("✓ Patched");

    // Click again to unmark (toggle)
    const updatedPatchBtn = updatedCard1.querySelector(".threat-patch-btn");
    updatedPatchBtn.click();

    const toggledCard1 = container.querySelectorAll(".threat-card")[0];
    expect(toggledCard1.classList.contains("patched")).toBe(false);
    expect(toggledCard1.querySelector(".threat-patched-badge")).toBeNull();
  });

  it("clear threats button removes findings from cache and returns to unscanned state", () => {
    const container = new MockElement("div") as any;
    const node = makeNode();
    const host = makeHost();
    const ctx: PanelContext = {
      host,
      incoming: [],
      outgoing: [],
      onSelect: vi.fn(),
    };

    threatCache.set(node.id, sampleReport);
    patchedThreats.add(`${node.id}:THREAT-1`);
    renderNodePanel(container, node, ctx);

    expect(container.querySelector(".threat-cards-list")).toBeTruthy();

    const clearBtn = container.querySelector(".threat-clear-btn");
    expect(clearBtn).toBeTruthy();
    expect(clearBtn.textContent).toContain("Clear Threats");

    clearBtn.click();

    expect(threatCache.has(node.id)).toBe(false);
    expect(patchedThreats.has(`${node.id}:THREAT-1`)).toBe(false);

    expect(container.querySelector(".threat-cards-list")).toBeNull();
    const scanBtn = container.querySelector(".threat-scan-btn");
    expect(scanBtn).toBeTruthy();
    expect(scanBtn.textContent).toContain("Trace Potential Threats");
  });

  it("re-scan button triggers host.analyzeNodeThreats with forceRefresh: true", async () => {
    const container = new MockElement("div") as any;
    const node = makeNode();
    const host = makeHost({
      analyzeNodeThreats: vi.fn().mockResolvedValue(sampleReport),
    });
    const ctx: PanelContext = {
      host,
      incoming: [],
      outgoing: [],
      onSelect: vi.fn(),
    };

    threatCache.set(node.id, sampleReport);
    renderNodePanel(container, node, ctx);

    const rescanBtn = container.querySelector(".threat-rescan-btn");
    expect(rescanBtn).toBeTruthy();
    expect(rescanBtn.textContent).toContain("Re-scan");

    rescanBtn.click();

    expect(host.analyzeNodeThreats).toHaveBeenCalledWith({
      nodeId: "src/auth.ts",
      forceRefresh: true,
    });
  });

  it("shows green callout when 0 threats detected in node", () => {
    const container = new MockElement("div") as any;
    const node = makeNode();
    const host = makeHost();
    const ctx: PanelContext = {
      host,
      incoming: [],
      outgoing: [],
      onSelect: vi.fn(),
    };

    const cleanReport: NodeThreatReport = {
      nodeId: "src/auth.ts",
      provider: "chatgpt",
      model: "gpt-4o",
      analyzedAt: "2026-10-20T10:00:00Z",
      summary: "No threats detected.",
      overallRisk: "info",
      masked: false,
      redactions: 0,
      threats: [],
    };

    threatCache.set(node.id, cleanReport);
    renderNodePanel(container, node, ctx);

    expect(container.textContent).toContain("Security Threats (0)");
    const callout = container.querySelector(".threat-summary-callout.success");
    expect(callout).toBeTruthy();
    expect(callout.textContent).toContain("✓ No security vulnerabilities or loopholes detected in this node.");
  });

  it("sensitive file protection banner prevents scanning and protects data", () => {
    const container = new MockElement("div") as any;
    const node = makeNode({
      sensitive: true,
      sensitiveReason: "Contains production secrets and tokens",
    });
    const host = makeHost();
    const ctx: PanelContext = {
      host,
      incoming: [],
      outgoing: [],
      onSelect: vi.fn(),
    };

    renderNodePanel(container, node, ctx);

    expect(container.querySelector(".threat-scan-btn")).toBeNull();
    const notice = container.querySelector(".threat-sensitive-notice");
    expect(notice).toBeTruthy();
    expect(notice.textContent).toContain(
      "🔒 Security Analysis unavailable: Sensitive files are protected and never sent to external AI models.",
    );
  });

  it("preserves cached threats when switching between nodes", () => {
    const container = new MockElement("div") as any;
    const host = makeHost();
    const ctx: PanelContext = {
      host,
      incoming: [],
      outgoing: [],
      onSelect: vi.fn(),
    };

    const nodeA = makeNode({ id: "src/a.ts", name: "a.ts" });
    const nodeB = makeNode({ id: "src/b.ts", name: "b.ts" });

    threatCache.set("src/a.ts", {
      ...sampleReport,
      nodeId: "src/a.ts",
    });

    // Render node A: has scanned threats
    renderNodePanel(container, nodeA, ctx);
    expect(container.textContent).toContain("Security Threats (2)");

    // Switch to node B: unscanned
    renderNodePanel(container, nodeB, ctx);
    expect(container.querySelector(".threat-scan-btn")?.textContent).toContain("Trace Potential Threats");

    // Return to node A: preserved from cache!
    renderNodePanel(container, nodeA, ctx);
    expect(container.textContent).toContain("Security Threats (2)");
  });

  it("handles unconfigured AI provider error with configure button", async () => {
    const container = new MockElement("div") as any;
    const node = makeNode();
    const host = makeHost({
      analyzeNodeThreats: vi.fn().mockRejectedValue(new Error("No active AI provider configured")),
    });
    const ctx: PanelContext = {
      host,
      incoming: [],
      outgoing: [],
      onSelect: vi.fn(),
    };

    renderNodePanel(container, node, ctx);

    const scanBtn = container.querySelector(".threat-scan-btn");
    scanBtn.click();

    await vi.waitFor(() => {
      expect(container.querySelector(".threat-error-banner")).toBeTruthy();
    });

    const errorBanner = container.querySelector(".threat-error-banner");
    expect(errorBanner.textContent).toContain("No active AI provider configured");

    const configBtn = container.querySelector(".threat-config-btn");
    expect(configBtn).toBeTruthy();
    expect(configBtn.textContent).toContain("✨ Configure AI Provider");
  });
});
