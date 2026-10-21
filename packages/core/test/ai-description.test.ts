import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildNodeDescriptionPrompt,
  describeNodeFile,
  DESCRIBE_NODE_NAME,
  DESCRIBE_NODE_SCHEMA,
} from "../src/ai-description";
import { NodeDescriptionError } from "../src/ai-types";
import type { GraphNode } from "../src/types";

function mockNode(overrides: Partial<GraphNode> = {}): GraphNode {
  return {
    id: "src/auth/login.ts",
    name: "login.ts",
    folder: "src/auth",
    ext: ".ts",
    language: "typescript",
    size: 256,
    lines: 12,
    hash: "node-hash-1",
    binary: false,
    sensitive: false,
    secretHints: 0,
    parsed: true,
    symbols: [
      {
        id: "loginHandler",
        name: "loginHandler",
        kind: "function",
        exported: true,
        signature: "export async function loginHandler(req: Request)",
        start: { line: 2, column: 0 },
        end: { line: 10, column: 1 },
      },
    ],
    packages: ["jsonwebtoken"],
    envReads: ["JWT_SECRET"],
    envDeclares: [],
    unresolved: ["./missing"],
    ...overrides,
  };
}

const structuredDescription = {
  summary: "Handles user login and returns a signed token.",
  purpose: "Authenticate a user request.",
  responsibilities: ["Validate credentials", "Sign a JWT"],
  keySymbols: [
    {
      name: "loginHandler",
      kind: "function",
      description: "Validates a request and creates a token.",
      line: 2,
    },
  ],
  dependencies: ["jsonwebtoken signs the token"],
  dataFlow: ["Request credentials are validated", "A token is returned"],
  notableDetails: ["Reads JWT_SECRET from configuration"],
  confidence: "high",
};

describe("ai-description", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => vi.restoreAllMocks());
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("builds a grounded prompt from sanitized source and indexed metadata", () => {
    const prompt = buildNodeDescriptionPrompt(mockNode(), {
      content: "const secret = '[SECRET_REDACTED]';\nexport function loginHandler() {}",
      masked: false,
      redactions: 1,
    });

    expect(prompt).toContain("src/auth/login.ts");
    expect(prompt).toContain("jsonwebtoken");
    expect(prompt).toContain("JWT_SECRET");
    expect(prompt).toContain("loginHandler (function, lines 2-10)");
    expect(prompt).toContain("1 secret-looking value(s) were replaced");
    expect(prompt).toContain("1 | const secret = '[SECRET_REDACTED]';");
    expect(prompt).toContain(DESCRIBE_NODE_NAME);
  });

  it("rejects sensitive, masked, binary, and empty files before a provider request", async () => {
    const common = {
      provider: "chatgpt" as const,
      apiKey: "sk-proj-test1234567890",
    };

    await expect(describeNodeFile({
      ...common,
      node: mockNode({ sensitive: true }),
      content: { content: "SECRET=value", masked: true, redactions: 0 },
    })).rejects.toMatchObject({ code: "SENSITIVE_NODE", status: 400 });

    await expect(describeNodeFile({
      ...common,
      node: mockNode(),
      content: { content: "masked", masked: true, redactions: 0 },
    })).rejects.toMatchObject({ code: "SENSITIVE_NODE", status: 400 });

    await expect(describeNodeFile({
      ...common,
      node: mockNode({ binary: true }),
      content: { content: "", masked: false, redactions: 0 },
    })).rejects.toMatchObject({ code: "UNSUPPORTED_NODE", status: 400 });

    expect(globalThis.fetch).toBe(originalFetch);
  });

  it("uses OpenAI structured tool output and sanitizes the report", async () => {
    let capturedBody: any;
    globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
      capturedBody = JSON.parse(init?.body as string);
      return {
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              tool_calls: [{
                function: {
                  name: DESCRIBE_NODE_NAME,
                  arguments: JSON.stringify({ ...structuredDescription, confidence: "unexpected" }),
                },
              }],
            },
          }],
        }),
      } as Response;
    });

    const report = await describeNodeFile({
      node: mockNode(),
      content: { content: "export function loginHandler() {}", masked: false, redactions: 1 },
      provider: "chatgpt",
      apiKey: "sk-proj-test1234567890",
      model: "gpt-test",
    });

    expect(capturedBody.tool_choice.function.name).toBe(DESCRIBE_NODE_NAME);
    expect(capturedBody.tools[0].function.parameters).toEqual(DESCRIBE_NODE_SCHEMA);
    expect(report.nodeId).toBe("src/auth/login.ts");
    expect(report.nodeHash).toBe("node-hash-1");
    expect(report.summary).toContain("Handles user login");
    expect(report.keySymbols[0]).toMatchObject({ name: "loginHandler", line: 2 });
    expect(report.confidence).toBe("medium");
    expect(report.redactions).toBe(1);
  });

  it("supports Gemini function calls without putting the key in the URL", async () => {
    let capturedUrl = "";
    let capturedHeaders: Record<string, string> = {};
    globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      capturedUrl = url;
      capturedHeaders = init?.headers as Record<string, string>;
      return {
        ok: true,
        json: async () => ({
          candidates: [{ content: { parts: [{ functionCall: { name: DESCRIBE_NODE_NAME, args: structuredDescription } }] } }],
        }),
      } as Response;
    });

    const report = await describeNodeFile({
      node: mockNode(),
      content: { content: "export const value = 1;", masked: false, redactions: 0 },
      provider: "gemini",
      apiKey: "AQ.fake-key",
      model: "gemini-test",
    });

    expect(capturedUrl).not.toContain("AQ.fake-key");
    expect(capturedHeaders["x-goog-api-key"]).toBe("AQ.fake-key");
    expect(report.provider).toBe("gemini");
  });

  it("supports Claude tool use", async () => {
    let capturedBody: any;
    globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
      capturedBody = JSON.parse(init?.body as string);
      return {
        ok: true,
        json: async () => ({
          content: [{ type: "tool_use", name: DESCRIBE_NODE_NAME, input: structuredDescription }],
        }),
      } as Response;
    });

    const report = await describeNodeFile({
      node: mockNode(),
      content: { content: "export const value = 1;", masked: false, redactions: 0 },
      provider: "claude",
      apiKey: "sk-ant-test",
    });

    expect(capturedBody.tools[0].input_schema).toEqual(DESCRIBE_NODE_SCHEMA);
    expect(capturedBody.tool_choice).toEqual({ type: "tool", name: DESCRIBE_NODE_NAME });
    expect(report.provider).toBe("claude");
  });

  it("uses the xAI endpoint and reports missing tool output safely", async () => {
    let capturedUrl = "";
    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      capturedUrl = url;
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: "plain text" } }] }),
      } as Response;
    });

    await expect(describeNodeFile({
      node: mockNode(),
      content: { content: "export const value = 1;", masked: false, redactions: 0 },
      provider: "grok",
      apiKey: "xai-test",
    })).rejects.toBeInstanceOf(NodeDescriptionError);
    expect(capturedUrl).toBe("https://api.x.ai/v1/chat/completions");
  });
});
