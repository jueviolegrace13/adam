import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  analyzeNodeSecurityThreats,
  buildThreatAnalysisPrompt,
  REPORT_SECURITY_THREATS_NAME,
  REPORT_SECURITY_THREATS_SCHEMA,
} from "../src/ai-threats";
import { ThreatAnalysisError } from "../src/ai-types";
import type { GraphNode } from "../src/types";

function mockNode(overrides?: Partial<GraphNode>): GraphNode {
  return {
    id: "src/auth/login.ts",
    name: "login.ts",
    folder: "src/auth",
    ext: ".ts",
    language: "typescript",
    size: 256,
    lines: 10,
    hash: "abc12345",
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
        signature: "export async function loginHandler(req: Request, res: Response)",
        start: { line: 1, column: 0 },
        end: { line: 10, column: 1 },
      },
    ],
    packages: ["jsonwebtoken", "bcrypt", "express"],
    envReads: ["JWT_SECRET", "DB_PASSWORD"],
    envDeclares: [],
    unresolved: [],
    ...overrides,
  };
}

describe("ai-threats", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe("buildThreatAnalysisPrompt", () => {
    it("formats node metadata, packages, envReads, symbols, and numbered code lines", () => {
      const node = mockNode();
      const content = {
        content: "const a = 1;\nconst b = 2;",
        masked: false,
        redactions: 0,
      };

      const prompt = buildThreatAnalysisPrompt(node, content);

      expect(prompt).toContain("src/auth/login.ts");
      expect(prompt).toContain("typescript");
      expect(prompt).toContain("jsonwebtoken, bcrypt, express");
      expect(prompt).toContain("JWT_SECRET, DB_PASSWORD");
      expect(prompt).toContain("loginHandler (function, lines 1-10)");
      expect(prompt).toContain("1 | const a = 1;");
      expect(prompt).toContain("2 | const b = 2;");
      expect(prompt).toContain("report_security_threats");
    });

    it("includes redaction and masked warnings when appropriate", () => {
      const node = mockNode();
      const content = {
        content: "const secret = '[SECRET_REDACTED]';",
        masked: true,
        redactions: 2,
      };

      const prompt = buildThreatAnalysisPrompt(node, content);

      expect(prompt).toContain("Node content has been masked for security");
      expect(prompt).toContain("2 potential secret(s) or credential(s) have been automatically redacted");
    });

    it("handles nodes without packages or symbols gracefully", () => {
      const node = mockNode({ packages: [], envReads: [], symbols: [] });
      const content = {
        content: "console.log('hello');",
        masked: false,
        redactions: 0,
      };

      const prompt = buildThreatAnalysisPrompt(node, content);

      expect(prompt).toContain("External Dependencies / Packages: None detected");
      expect(prompt).toContain("Environment Variables Read: None detected");
      expect(prompt).toContain("Symbols Defined: None detected");
    });
  });

  describe("analyzeNodeSecurityThreats validation", () => {
    it("rejects sensitive nodes immediately", async () => {
      const node = mockNode({ sensitive: true });
      await expect(
        analyzeNodeSecurityThreats({
          node,
          content: { content: "SECRET=123", masked: true, redactions: 0 },
          provider: "chatgpt",
          apiKey: "sk-proj-test1234567890123456",
        }),
      ).rejects.toThrowError(ThreatAnalysisError);

      try {
        await analyzeNodeSecurityThreats({
          node,
          content: { content: "SECRET=123", masked: true, redactions: 0 },
          provider: "chatgpt",
          apiKey: "sk-proj-test1234567890123456",
        });
      } catch (err: any) {
        expect(err.code).toBe("SENSITIVE_NODE");
        expect(err.status).toBe(400);
      }
    });

    it("rejects empty or whitespace-only api keys", async () => {
      const node = mockNode();
      await expect(
        analyzeNodeSecurityThreats({
          node,
          content: { content: "let x = 1;", masked: false, redactions: 0 },
          provider: "gemini",
          apiKey: "   ",
        }),
      ).rejects.toThrowError(ThreatAnalysisError);

      try {
        await analyzeNodeSecurityThreats({
          node,
          content: { content: "let x = 1;", masked: false, redactions: 0 },
          provider: "gemini",
          apiKey: "",
        });
      } catch (err: any) {
        expect(err.code).toBe("UNCONFIGURED");
        expect(err.status).toBe(400);
      }
    });
  });

  describe("Google Gemini function calling", () => {
    it("sends tools and toolConfig and parses functionCall response", async () => {
      let capturedUrl = "";
      let capturedBody: any;

      globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        capturedUrl = url;
        capturedBody = JSON.parse(init?.body as string);
        return {
          ok: true,
          json: async () => ({
            candidates: [
              {
                content: {
                  parts: [
                    {
                      functionCall: {
                        name: REPORT_SECURITY_THREATS_NAME,
                        args: {
                          summary: "SQL Injection found in query builder",
                          overallRisk: "high",
                          threats: [
                            {
                              id: "THREAT-1",
                              title: "Raw SQL concatenation in query",
                              category: "injection",
                              severity: "high",
                              description: "User input is directly interpolated into db.query.",
                              location: { lineStart: 5, lineEnd: 6, symbolName: "loginHandler" },
                              cwe: "CWE-89",
                              recommendation: "Use parameterized queries.",
                            },
                          ],
                        },
                      },
                    },
                  ],
                },
              },
            ],
          }),
        } as unknown as Response;
      });

      const node = mockNode();
      const report = await analyzeNodeSecurityThreats({
        node,
        content: { content: "db.query(`SELECT * FROM users WHERE id = ${req.body.id}`);", masked: false, redactions: 0 },
        provider: "gemini",
        apiKey: "AQ.fakeGeminiKey12345",
        model: "gemini-3.8-flash",
      });

      expect(capturedUrl).toBe("https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent");
      expect((globalThis.fetch as any).mock.calls[0][1].headers["x-goog-api-key"]).toBe("AQ.fakeGeminiKey12345");
      expect(capturedBody.tools[0].functionDeclarations[0].name).toBe("report_security_threats");
      expect(capturedBody.toolConfig.functionCallingConfig.mode).toBe("ANY");
      expect(capturedBody.toolConfig.functionCallingConfig.allowedFunctionNames).toEqual(["report_security_threats"]);

      expect(report.nodeId).toBe(node.id);
      expect(report.provider).toBe("gemini");
      expect(report.model).toBe("gemini-3.8-flash");
      expect(report.overallRisk).toBe("high");
      expect(report.threats).toHaveLength(1);
      expect(report.threats[0].category).toBe("injection");
      expect(report.threats[0].cwe).toBe("CWE-89");
    });

    it("retries once when Gemini stops without the function call, then succeeds", async () => {
      const calls: any[] = [];
      globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
        calls.push(JSON.parse(init.body as string));
        if (calls.length === 1) {
          return {
            ok: true,
            json: async () => ({ candidates: [{ finishReason: "MALFORMED_FUNCTION_CALL", content: { parts: [] } }] }),
          } as unknown as Response;
        }
        return {
          ok: true,
          json: async () => ({
            candidates: [
              {
                content: {
                  parts: [
                    {
                      functionCall: {
                        name: "report_security_threats",
                        args: { summary: "Clean.", overallRisk: "info", threats: [] },
                      },
                    },
                  ],
                },
              },
            ],
          }),
        } as unknown as Response;
      });

      const report = await analyzeNodeSecurityThreats({
        node: mockNode(),
        content: { content: "const a = 1;", masked: false, redactions: 0 },
        provider: "gemini",
        apiKey: "AQ.fakeGeminiKey12345",
      });

      expect(calls).toHaveLength(2);
      expect(calls[0].generationConfig.maxOutputTokens).toBeGreaterThanOrEqual(8192);
      expect(calls[0].generationConfig.temperature).toBeUndefined();
      expect(report.summary).toBe("Clean.");
      expect(report.threats).toHaveLength(0);
    });

    it("accepts a JSON report Gemini returns as text instead of a call", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          candidates: [
            {
              finishReason: "STOP",
              content: {
                parts: [
                  { text: "thinking...", thought: true },
                  {
                    text: '```json\n{"summary":"One issue.","overallRisk":"low","threats":[{"id":"T1","title":"Weak hash","category":"crypto","severity":"low","description":"md5","recommendation":"Use sha256."}]}\n```',
                  },
                ],
              },
            },
          ],
        }),
      } as unknown as Response);

      const report = await analyzeNodeSecurityThreats({
        node: mockNode(),
        content: { content: "md5(x)", masked: false, redactions: 0 },
        provider: "gemini",
        apiKey: "AQ.fakeGeminiKey12345",
      });

      expect(report.threats).toHaveLength(1);
      expect(report.threats[0].category).toBe("crypto");
    });

    it("explains why Gemini gave no function call after the retry", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ candidates: [{ finishReason: "MAX_TOKENS", content: { parts: [] } }] }),
      } as unknown as Response);

      await expect(
        analyzeNodeSecurityThreats({
          node: mockNode(),
          content: { content: "code", masked: false, redactions: 0 },
          provider: "gemini",
          apiKey: "AQ.fakeGeminiKey12345",
        }),
      ).rejects.toThrow("ran out of output tokens");
      expect(globalThis.fetch).toHaveBeenCalledTimes(2);
    });

    it("does not retry when Gemini's safety filter blocks the prompt", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ promptFeedback: { blockReason: "SAFETY" } }),
      } as unknown as Response);

      await expect(
        analyzeNodeSecurityThreats({
          node: mockNode(),
          content: { content: "code", masked: false, redactions: 0 },
          provider: "gemini",
          apiKey: "AQ.fakeGeminiKey12345",
        }),
      ).rejects.toThrow("safety filter");
      expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    });

    it("handles Gemini API errors", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        statusText: "Forbidden",
        json: async () => ({ error: { message: "API key expired" } }),
      } as unknown as Response);

      await expect(
        analyzeNodeSecurityThreats({
          node: mockNode(),
          content: { content: "code", masked: false, redactions: 0 },
          provider: "gemini",
          apiKey: "AQ.expiredKey12345",
        }),
      ).rejects.toThrow("Gemini request failed (HTTP 403). Check the API key and selected model, then try again.");
    });
  });

  describe("OpenAI function calling", () => {
    it("sends tools and tool_choice and parses tool_calls arguments", async () => {
      let capturedUrl = "";
      let capturedHeaders: Record<string, string> = {};
      let capturedBody: any;

      globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        capturedUrl = url;
        capturedHeaders = init?.headers as Record<string, string>;
        capturedBody = JSON.parse(init?.body as string);
        return {
          ok: true,
          json: async () => ({
            choices: [
              {
                message: {
                  tool_calls: [
                    {
                      function: {
                        name: "report_security_threats",
                        arguments: JSON.stringify({
                          summary: "Hardcoded secret detected",
                          overallRisk: "critical",
                          threats: [
                            {
                              id: "THREAT-1",
                              title: "Hardcoded JWT secret",
                              category: "sensitive_data",
                              severity: "critical",
                              description: "JWT signing secret is hardcoded in source.",
                              recommendation: "Load from process.env.",
                            },
                          ],
                        }),
                      },
                    },
                  ],
                },
              },
            ],
          }),
        } as unknown as Response;
      });

      const report = await analyzeNodeSecurityThreats({
        node: mockNode(),
        content: { content: "const secret = '12345';", masked: false, redactions: 0 },
        provider: "chatgpt",
        apiKey: "sk-proj-openaiKey12345678",
        model: "gpt-4o",
      });

      expect(capturedUrl).toBe("https://api.openai.com/v1/chat/completions");
      expect(capturedHeaders["Authorization"]).toBe("Bearer sk-proj-openaiKey12345678");
      expect(capturedBody.tool_choice).toEqual({ type: "function", function: { name: "report_security_threats" } });
      expect(report.overallRisk).toBe("critical");
      expect(report.threats[0].title).toBe("Hardcoded JWT secret");
    });
  });

  describe("xAI Grok function calling", () => {
    it("uses xAI endpoint with OpenAI format", async () => {
      let capturedUrl = "";
      globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        capturedUrl = url;
        return {
          ok: true,
          json: async () => ({
            choices: [
              {
                message: {
                  tool_calls: [
                    {
                      function: {
                        name: "report_security_threats",
                        arguments: JSON.stringify({
                          summary: "Clean node",
                          overallRisk: "info",
                          threats: [],
                        }),
                      },
                    },
                  ],
                },
              },
            ],
          }),
        } as unknown as Response;
      });

      const report = await analyzeNodeSecurityThreats({
        node: mockNode(),
        content: { content: "const clean = true;", masked: false, redactions: 0 },
        provider: "grok",
        apiKey: "xai-testKey1234567890",
      });

      expect(capturedUrl).toBe("https://api.x.ai/v1/chat/completions");
      expect(report.provider).toBe("grok");
      expect(report.overallRisk).toBe("info");
      expect(report.threats).toHaveLength(0);
    });
  });

  describe("Anthropic Claude function calling", () => {
    it("sends tools with input_schema and tool_choice and parses tool_use block", async () => {
      let capturedUrl = "";
      let capturedHeaders: Record<string, string> = {};
      let capturedBody: any;

      globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        capturedUrl = url;
        capturedHeaders = init?.headers as Record<string, string>;
        capturedBody = JSON.parse(init?.body as string);
        return {
          ok: true,
          json: async () => ({
            content: [
              {
                type: "tool_use",
                name: "report_security_threats",
                input: {
                  summary: "Insecure crypto algorithm used",
                  overallRisk: "medium",
                  threats: [
                    {
                      id: "THREAT-1",
                      title: "MD5 used for hashing password",
                      category: "crypto",
                      severity: "high",
                      description: "MD5 is collision prone and vulnerable to pre-image attacks.",
                      recommendation: "Use Argon2id or bcrypt.",
                    },
                  ],
                },
              },
            ],
          }),
        } as unknown as Response;
      });

      const report = await analyzeNodeSecurityThreats({
        node: mockNode(),
        content: { content: "crypto.createHash('md5')", masked: false, redactions: 0 },
        provider: "claude",
        apiKey: "sk-ant-testKey12345678",
      });

      expect(capturedUrl).toBe("https://api.anthropic.com/v1/messages");
      expect(capturedHeaders["x-api-key"]).toBe("sk-ant-testKey12345678");
      expect(capturedHeaders["anthropic-version"]).toBe("2023-06-01");
      expect(capturedBody.tools[0].name).toBe("report_security_threats");
      expect(capturedBody.tools[0].input_schema).toEqual(REPORT_SECURITY_THREATS_SCHEMA);
      expect(capturedBody.tool_choice).toEqual({ type: "tool", name: "report_security_threats" });
      expect(report.provider).toBe("claude");
      expect(report.threats[0].category).toBe("crypto");
      expect(report.overallRisk).toBe("high");
    });
  });

  describe("Missing or unexpected function call output", () => {
    it("throws PARSE_ERROR if model failed to invoke report_security_threats", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          choices: [
            {
              message: {
                content: "I didn't call any tools.",
              },
            },
          ],
        }),
      } as unknown as Response);

      await expect(
        analyzeNodeSecurityThreats({
          node: mockNode(),
          content: { content: "const a = 1;", masked: false, redactions: 0 },
          provider: "chatgpt",
          apiKey: "sk-proj-test1234567890",
        }),
      ).rejects.toThrow("did not invoke");
    });
  });
});
