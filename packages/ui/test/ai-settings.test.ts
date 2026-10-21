import { describe, expect, it, vi, beforeEach } from "vitest";
import type {
  AiConfigSummary,
  AiProvider,
  AiValidationResult,
  SaveAiConfigRequest,
  ValidateAiKeyRequest,
} from "@adam/core";
import {
  closeAiSettingsDialog,
  getAiButtonInfo,
  getProviderDisplayName,
  getProviderShortName,
  openAiSettingsDialog,
} from "../src/ai-settings";
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

  append(...nodes: (MockNode | string)[]) {
    for (const n of nodes) {
      if (typeof n === "string") {
        const textNode = new MockNode();
        textNode.nodeType = 3;
        textNode._textContent = n;
        this.children.push(textNode);
        textNode.parentElement = this;
      } else if (n) {
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
      l({ ...event, currentTarget: this, target: event.target ?? this });
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
        if (selector.startsWith(".") && node.className.split(" ").includes(selector.slice(1))) {
          results.push(node);
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

  constructor(tagName: string) {
    super();
    this.tagName = tagName.toUpperCase();
  }

  override setAttribute(name: string, value: string) {
    super.setAttribute(name, value);
    if (name === "type") this.type = value;
    if (name === "value") this.value = value;
    if (name === "id") this.id = value;
    if (name === "class") this.className = value;
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

// --- Tests ---

describe("AI Settings Helpers", () => {
  it("getProviderDisplayName returns appropriate names", () => {
    expect(getProviderDisplayName("gemini")).toBe("Google Gemini / Antigravity");
    expect(getProviderDisplayName("chatgpt")).toBe("OpenAI ChatGPT");
    expect(getProviderDisplayName("claude")).toBe("Anthropic Claude");
    expect(getProviderDisplayName("grok")).toBe("xAI Grok");
  });

  it("getProviderShortName returns concise names for buttons/badges", () => {
    expect(getProviderShortName("chatgpt")).toBe("ChatGPT");
    expect(getProviderShortName("claude")).toBe("Claude");
    expect(getProviderShortName("grok")).toBe("Grok");
    expect(getProviderShortName("gemini")).toBe("Gemini");
  });

  it("getAiButtonInfo handles unconfigured states", () => {
    expect(getAiButtonInfo(undefined)).toEqual({
      label: "✨ Configure AI",
      isActive: false,
    });

    const emptySummary: AiConfigSummary = {
      activeProvider: undefined,
      providers: {
        chatgpt: { provider: "chatgpt", configured: false },
        claude: { provider: "claude", configured: false },
        grok: { provider: "grok", configured: false },
        gemini: { provider: "gemini", configured: false },
      },
    };
    expect(getAiButtonInfo(emptySummary)).toEqual({
      label: "✨ Configure AI",
      isActive: false,
    });
  });

  it("getAiButtonInfo handles active configured provider", () => {
    const summary: AiConfigSummary = {
      activeProvider: "claude",
      providers: {
        chatgpt: { provider: "chatgpt", configured: false },
        claude: { provider: "claude", configured: true, maskedKey: "sk-ant-...1234" },
        grok: { provider: "grok", configured: false },
        gemini: { provider: "gemini", configured: false },
      },
    };

    expect(getAiButtonInfo(summary)).toEqual({
      label: "✨ Claude (Active)",
      isActive: true,
      provider: "claude",
    });
  });

  it("getAiButtonInfo handles configured provider when activeProvider is not set", () => {
    const summary: AiConfigSummary = {
      activeProvider: undefined,
      providers: {
        chatgpt: { provider: "chatgpt", configured: false },
        claude: { provider: "claude", configured: true, maskedKey: "sk-ant-...1234" },
        grok: { provider: "grok", configured: false },
        gemini: { provider: "gemini", configured: false },
      },
    };

    expect(getAiButtonInfo(summary)).toEqual({
      label: "✨ Claude",
      isActive: false,
      provider: "claude",
    });
  });
});

describe("AI Settings Dialog Component", () => {
  let mockHost: Host;
  let currentSummary: AiConfigSummary;
  let dom: ReturnType<typeof setupMockDom>;

  beforeEach(() => {
    dom = setupMockDom();

    currentSummary = {
      activeProvider: "claude",
      providers: {
        chatgpt: { provider: "chatgpt", configured: false },
        claude: {
          provider: "claude",
          configured: true,
          maskedKey: "sk-ant-...5678",
          selectedModel: "claude-3-7-sonnet-20250219",
        },
        grok: { provider: "grok", configured: false },
        gemini: { provider: "gemini", configured: false },
      },
    };

    mockHost = {
      kind: "browser",
      getGraph: vi.fn(),
      getNode: vi.fn(),
      getSymbol: vi.fn(),
      reindex: vi.fn(),
      onGraphChanged: vi.fn(),
      getAiConfig: vi.fn().mockImplementation(async () => currentSummary),
      saveAiConfig: vi.fn().mockImplementation(async (req: SaveAiConfigRequest) => {
        currentSummary = {
          ...currentSummary,
          providers: {
            ...currentSummary.providers,
            [req.provider]: {
              provider: req.provider,
              configured: true,
              maskedKey: req.apiKey ? "sk-ant-...new" : currentSummary.providers[req.provider].maskedKey,
              selectedModel: req.selectedModel,
            },
          },
        };
        if (req.setActive) currentSummary.activeProvider = req.provider;
        return currentSummary;
      }),
      deleteAiConfig: vi.fn().mockImplementation(async (provider: AiProvider) => {
        currentSummary = {
          ...currentSummary,
          providers: {
            ...currentSummary.providers,
            [provider]: { provider, configured: false },
          },
        };
        if (currentSummary.activeProvider === provider) {
          currentSummary.activeProvider = undefined;
        }
        return currentSummary;
      }),
      setActiveAiProvider: vi.fn().mockImplementation(async (provider: AiProvider) => {
        currentSummary = { ...currentSummary, activeProvider: provider };
        return currentSummary;
      }),
      validateAiKey: vi.fn().mockImplementation(async (req: ValidateAiKeyRequest): Promise<AiValidationResult> => {
        return {
          provider: req.provider,
          ok: true,
          message: "Authentication successful",
          latencyMs: 120,
        };
      }),
      listAiModels: vi.fn().mockResolvedValue([]),
      describeNode: vi.fn(),
      analyzeNodeThreats: vi.fn(),
    };
  });

  it("opens modal and displays security banner, provider cards, and stored key", async () => {
    const onConfigChange = vi.fn();
    const modal = await openAiSettingsDialog(mockHost, onConfigChange);

    expect(dom.doc.body.children).toContain(modal);

    // Security banner
    const securityBanner = modal.querySelector(".ai-security-banner");
    expect(securityBanner).not.toBeNull();
    expect(securityBanner?.textContent).toContain("Stored locally and safely");

    // Provider cards
    const cards = modal.querySelectorAll(".ai-provider-card");
    expect(cards.length).toBe(4);

    // Check saved masked key for Claude
    const maskedKey = modal.querySelector(".ai-masked-key");
    expect(maskedKey).not.toBeNull();
    expect(maskedKey?.textContent).toBe("sk-ant-...5678");

    // Close button
    const closeBtn = modal.querySelector(".ai-modal-close") as unknown as MockElement;
    expect(closeBtn).not.toBeNull();
    closeBtn.click();
    expect(dom.doc.body.children).not.toContain(modal);
  });

  it("toggles password visibility on eye button click", async () => {
    const modal = await openAiSettingsDialog(mockHost);
    const keyInput = modal.querySelector(".ai-key-input") as unknown as MockElement;
    const toggleBtn = modal.querySelector(".ai-toggle-btn") as unknown as MockElement;

    expect(keyInput).not.toBeNull();
    expect(keyInput.type).toBe("password");

    toggleBtn.click();
    expect(keyInput.type).toBe("text");
    expect(toggleBtn.textContent).toBe("🙈");

    toggleBtn.click();
    expect(keyInput.type).toBe("password");
    expect(toggleBtn.textContent).toBe("👁️");
  });

  it("tests connection via host.validateAiKey", async () => {
    const modal = await openAiSettingsDialog(mockHost);
    const testBtn = modal.querySelector(".ai-test-btn") as unknown as MockElement;

    expect(testBtn).not.toBeNull();
    testBtn.click();

    // Allow async tick
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(mockHost.validateAiKey).toHaveBeenCalledWith({
      provider: "claude",
      apiKey: undefined, // Validating stored key
    });

    const callout = modal.querySelector(".ai-test-callout");
    expect(callout).not.toBeNull();
    expect(callout?.className).toContain("success");
  });

  it("saves new model and triggers onConfigChange", async () => {
    const onConfigChange = vi.fn();
    const modal = await openAiSettingsDialog(mockHost, onConfigChange);

    const modelSelect = modal.querySelector(".ai-model-select") as unknown as MockElement;
    modelSelect.value = "claude-3-5-sonnet-20241022";

    const saveBtn = modal.querySelector(".ai-save-btn") as unknown as MockElement;
    saveBtn.click();

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(mockHost.saveAiConfig).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: "claude",
        selectedModel: "claude-3-5-sonnet-20241022",
      }),
    );
    expect(onConfigChange).toHaveBeenCalled();
  });

  it("saves custom model ID when __custom__ is selected", async () => {
    const onConfigChange = vi.fn();
    const modal = await openAiSettingsDialog(mockHost, onConfigChange);

    const modelSelect = modal.querySelector(".ai-model-select") as unknown as MockElement;
    const customModelInput = modal.querySelector(".ai-custom-model-input") as unknown as MockElement;

    modelSelect.value = "__custom__";
    modelSelect.dispatchEvent({ type: "change" });
    customModelInput.value = "gemini-3.8-flash";

    const saveBtn = modal.querySelector(".ai-save-btn") as unknown as MockElement;
    saveBtn.click();

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(mockHost.saveAiConfig).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: "claude",
        selectedModel: "gemini-3.8-flash",
      }),
    );
    expect(onConfigChange).toHaveBeenCalled();
  });

  it("handles remove key confirmation and deletion", async () => {
    const onConfigChange = vi.fn();
    const modal = await openAiSettingsDialog(mockHost, onConfigChange);

    const removeBtn = modal.querySelector(".ai-remove-btn") as unknown as MockElement;
    removeBtn.click();

    // Confirm box should appear
    const confirmBox = modal.querySelector(".ai-confirm-box");
    expect(confirmBox).not.toBeNull();

    // Click confirm delete
    const confirmActions = confirmBox?.querySelector(".ai-confirm-actions");
    const confirmDeleteBtn = confirmActions?.children[0] as unknown as MockElement;
    confirmDeleteBtn.click();

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(mockHost.deleteAiConfig).toHaveBeenCalledWith("claude");
    expect(onConfigChange).toHaveBeenCalled();
  });

  it("closes modal on Escape key press", async () => {
    const modal = await openAiSettingsDialog(mockHost);
    expect(dom.doc.body.children).toContain(modal);

    dom.win.dispatchEvent({
      type: "keydown",
      key: "Escape",
      stopPropagation: () => {},
    });

    expect(dom.doc.body.children).not.toContain(modal);
  });

  it("closes modal via closeAiSettingsDialog", async () => {
    const modal = await openAiSettingsDialog(mockHost);
    expect(dom.doc.body.children).toContain(modal);

    closeAiSettingsDialog();
    expect(dom.doc.body.children).not.toContain(modal);
  });
});
