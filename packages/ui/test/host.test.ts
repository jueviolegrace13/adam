import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { NodeDescriptionReport, NodeThreatReport } from "@adam/core";
import { createBrowserHost, createVsCodeHost, type VsCodeApi } from "../src/host";

describe("Host threat analysis wiring", () => {
  const originalFetch = globalThis.fetch;
  const originalWindow = (globalThis as any).window;
  const originalLocation = (globalThis as any).location;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    (globalThis as any).window = originalWindow;
    (globalThis as any).location = originalLocation;
  });

  it("wires analyzeNodeThreats in createVsCodeHost", async () => {
    const listeners: Array<(e: any) => void> = [];
    (globalThis as any).window = {
      addEventListener: (type: string, listener: (e: any) => void) => {
        if (type === "message") listeners.push(listener);
      },
    };

    let sentMessage: any;
    const api: VsCodeApi = {
      postMessage: (msg) => {
        sentMessage = msg;
        if (msg.type !== "request") return;
        const msgId = msg.id;
        // Simulate extension reply
        setTimeout(() => {
          listeners.forEach((l) =>
            l({
              data: {
                type: "response",
                id: msgId,
                ok: true,
                result: {
                  nodeId: "src/index.ts",
                  provider: "chatgpt",
                  model: "gpt-4o",
                  analyzedAt: new Date().toISOString(),
                  summary: "No threats",
                  threats: [],
                  overallRisk: "info",
                  masked: false,
                  redactions: 0,
                } as NodeThreatReport,
              },
            }),
          );
        }, 0);
      },
    };

    const host = createVsCodeHost(api);
    expect(host.kind).toBe("vscode");

    const report = await host.analyzeNodeThreats({ nodeId: "src/index.ts" });

    expect(sentMessage.type).toBe("request");
    expect(sentMessage.method).toBe("ai:analyzeThreats");
    expect(sentMessage.params).toEqual({ nodeId: "src/index.ts" });
    expect(report.nodeId).toBe("src/index.ts");
    expect(report.overallRisk).toBe("info");
  });

  it("wires describeNode in createVsCodeHost", async () => {
    const listeners: Array<(e: any) => void> = [];
    (globalThis as any).window = {
      addEventListener: (type: string, listener: (e: any) => void) => {
        if (type === "message") listeners.push(listener);
      },
    };

    let sentMessage: any;
    const api: VsCodeApi = {
      postMessage: (msg) => {
        sentMessage = msg;
        if (msg.type !== "request") return;
        const result: NodeDescriptionReport = {
          nodeId: "src/index.ts",
          nodeHash: "hash-1",
          provider: "chatgpt",
          model: "gpt-4o",
          analyzedAt: new Date().toISOString(),
          summary: "Application entry point.",
          purpose: "Start the application.",
          responsibilities: [],
          keySymbols: [],
          dependencies: [],
          dataFlow: [],
          notableDetails: [],
          confidence: "high",
          masked: false,
          redactions: 0,
        };
        setTimeout(() => {
          listeners.forEach((listener) => listener({
            data: { type: "response", id: msg.id, ok: true, result },
          }));
        }, 0);
      },
    };

    const host = createVsCodeHost(api);
    const report = await host.describeNode({ nodeId: "src/index.ts" });

    expect(sentMessage.method).toBe("ai:describeNode");
    expect(sentMessage.params).toEqual({ nodeId: "src/index.ts" });
    expect(report.summary).toBe("Application entry point.");
  });

  it("does not expose AI features from createBrowserHost", async () => {
    (globalThis as any).location = { hash: "#token=test-token-123" };
    const fetchSpy = vi.fn();
    globalThis.fetch = fetchSpy;
    const host = createBrowserHost();
    expect(host.kind).toBe("browser");
    await expect(host.getAiConfig()).rejects.toThrow("AI features are available in the VS Code extension only.");
    await expect(host.describeNode({ nodeId: "src/server.ts" })).rejects.toThrow(
      "AI features are available in the VS Code extension only.",
    );
    await expect(host.analyzeNodeThreats({ nodeId: "src/server.ts" })).rejects.toThrow(
      "AI features are available in the VS Code extension only.",
    );
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
