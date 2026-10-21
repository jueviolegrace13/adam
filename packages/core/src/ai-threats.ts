import {
  AI_PROVIDER_METADATA,
  ThreatAnalysisError,
  type AiProvider,
  type NodeThreat,
  type NodeThreatReport,
  type ThreatCategory,
  type ThreatSeverity,
} from "./ai-types";
import { callGeminiFunction, describeGeminiStop } from "./ai-gemini";
import type { GraphNode } from "./types";

export const REPORT_SECURITY_THREATS_NAME = "report_security_threats";

export const REPORT_SECURITY_THREATS_DESCRIPTION =
  "Report detected security vulnerabilities, loopholes, and actionable remediation for a source code file.";

export const REPORT_SECURITY_THREATS_SCHEMA = {
  type: "object",
  properties: {
    summary: {
      type: "string",
      description: "Brief security posture summary (1-2 sentences).",
    },
    overallRisk: {
      type: "string",
      enum: ["critical", "high", "medium", "low", "info"],
      description: "Highest risk level.",
    },
    threats: {
      type: "array",
      description: "Detected vulnerabilities.",
      items: {
        type: "object",
        properties: {
          id: {
            type: "string",
            description: "ID e.g. THREAT-1",
          },
          title: {
            type: "string",
            description: "Short descriptive vulnerability title.",
          },
          category: {
            type: "string",
            enum: [
              "injection",
              "auth",
              "sensitive_data",
              "supply_chain",
              "crypto",
              "misconfiguration",
              "denial_of_service",
              "other",
            ],
            description: "Vulnerability category.",
          },
          severity: {
            type: "string",
            enum: ["critical", "high", "medium", "low", "info"],
            description: "Severity level.",
          },
          description: {
            type: "string",
            description: "Concise explanation of attack vector and impact (under 3 sentences).",
          },
          location: {
            type: "object",
            properties: {
              lineStart: {
                type: "integer",
                description: "1-based starting line number.",
              },
              lineEnd: {
                type: "integer",
                description: "1-based ending line number.",
              },
              symbolName: {
                type: "string",
                description: "Containing function or symbol.",
              },
            },
          },
          cwe: {
            type: "string",
            description: "CWE ID if applicable (e.g. CWE-89).",
          },
          recommendation: {
            type: "string",
            description: "Concrete, actionable code fix (under 3 sentences).",
          },
        },
        required: ["id", "title", "category", "severity", "description", "recommendation"],
      },
    },
  },
  required: ["summary", "overallRisk", "threats"],
} as const;

/**
 * Defensive prompt builder formatting node metadata (language, packages, envReads, symbols)
 * and sanitized code.
 */
export function buildThreatAnalysisPrompt(
  node: GraphNode,
  content: { content: string; masked: boolean; redactions: number },
): string {
  const metaSections: string[] = [];
  metaSections.push(`### File Information`);
  metaSections.push(`- Path: ${node.id}`);
  metaSections.push(`- Language: ${node.language || "unknown"}`);
  metaSections.push(`- Size: ${node.size} bytes (${node.lines} lines)`);

  if (node.packages && node.packages.length > 0) {
    metaSections.push(`- External Dependencies / Packages: ${node.packages.join(", ")}`);
  } else {
    metaSections.push(`- External Dependencies / Packages: None detected`);
  }

  if (node.envReads && node.envReads.length > 0) {
    metaSections.push(`- Environment Variables Read: ${node.envReads.join(", ")}`);
  } else {
    metaSections.push(`- Environment Variables Read: None detected`);
  }

  if (node.symbols && node.symbols.length > 0) {
    const symbolSummaries = node.symbols
      .slice(0, 30)
      .map((s) => `${s.id} (${s.kind}, lines ${s.start.line}-${s.end.line})`);
    metaSections.push(`- Symbols Defined:\n  * ` + symbolSummaries.join("\n  * "));
  } else {
    metaSections.push(`- Symbols Defined: None detected`);
  }

  if (content.masked) {
    metaSections.push(`\n**SECURITY NOTICE:** Node content has been masked for security.`);
  }
  if (content.redactions > 0) {
    metaSections.push(
      `\n**SANITIZATION NOTICE:** ${content.redactions} potential secret(s) or credential(s) have been automatically redacted as \`[SECRET_REDACTED]\` before analysis.`,
    );
  }

  const lines = content.content.split(/\r?\n/);
  const numberedLines = lines.map((line, idx) => `${idx + 1} | ${line}`).join("\n");

  return [
    `Perform a precise, token-efficient security analysis of this source code file.`,
    `Identify actionable security vulnerabilities (injection, auth flaws, SSRF, sensitive data exposure, crypto weaknesses, prototype pollution).`,
    `Invoke 'report_security_threats' with concise findings (under 3 sentences per description and recommendation). If no vulnerabilities exist, return an empty 'threats' list and a 1-sentence summary.`,
    ``,
    metaSections.join("\n"),
    ``,
    `### Source Code:`,
    `\`\`\`${node.language || ""}`,
    numberedLines,
    `\`\`\``,
  ].join("\n");
}

export interface AnalyzeThreatsOptions {
  node: GraphNode;
  content: { content: string; masked: boolean; redactions: number };
  provider: AiProvider;
  apiKey: string;
  model?: string;
}

const VALID_SEVERITIES: readonly ThreatSeverity[] = ["critical", "high", "medium", "low", "info"];
const VALID_CATEGORIES: readonly ThreatCategory[] = [
  "injection",
  "auth",
  "sensitive_data",
  "supply_chain",
  "crypto",
  "misconfiguration",
  "denial_of_service",
  "other",
];

const SEVERITY_RANK: Record<ThreatSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

function sanitizeReport(
  raw: any,
  node: GraphNode,
  provider: AiProvider,
  model: string,
  content: { masked: boolean; redactions: number },
): NodeThreatReport {
  let parsed = raw;
  if (typeof raw === "string") {
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = {};
    }
  }

  const threatsRaw = Array.isArray(parsed?.threats) ? parsed.threats : [];

  const threats: NodeThreat[] = threatsRaw.map((t: any, idx: number) => {
    const rawSev = typeof t.severity === "string" ? t.severity.toLowerCase() : "";
    const sev: ThreatSeverity = VALID_SEVERITIES.includes(rawSev as ThreatSeverity)
      ? (rawSev as ThreatSeverity)
      : "medium";

    const rawCat = typeof t.category === "string" ? t.category.toLowerCase() : "";
    const cat: ThreatCategory = VALID_CATEGORIES.includes(rawCat as ThreatCategory)
      ? (rawCat as ThreatCategory)
      : "other";

    const threat: NodeThreat = {
      id: typeof t.id === "string" && t.id.trim() ? t.id.trim() : `THREAT-${idx + 1}`,
      title: typeof t.title === "string" && t.title.trim() ? t.title.trim() : "Unspecified vulnerability",
      category: cat,
      severity: sev,
      description: typeof t.description === "string" ? t.description : "",
      recommendation:
        typeof t.recommendation === "string" && t.recommendation.trim()
          ? t.recommendation.trim()
          : "Review and remediate according to secure coding best practices.",
    };

    if (typeof t.cwe === "string" && t.cwe.trim()) {
      threat.cwe = t.cwe.trim();
    }

    if (t.location && typeof t.location === "object") {
      const loc: NodeThreat["location"] = {};
      if (typeof t.location.lineStart === "number") loc.lineStart = Math.max(1, Math.floor(t.location.lineStart));
      if (typeof t.location.lineEnd === "number") {
        loc.lineEnd = Math.max(loc.lineStart ?? 1, Math.floor(t.location.lineEnd));
      }
      if (typeof t.location.symbolName === "string" && t.location.symbolName.trim()) {
        loc.symbolName = t.location.symbolName.trim();
      }
      if (loc.lineStart !== undefined || loc.symbolName !== undefined) {
        threat.location = loc;
      }
    }

    return threat;
  });

  // Threat severities are the source of truth. Model-provided overallRisk can
  // contradict individual findings, so derive the report risk from normalized threats.
  const overallRisk = threats.reduce<ThreatSeverity>((highest, current) => {
    return SEVERITY_RANK[current.severity] > SEVERITY_RANK[highest] ? current.severity : highest;
  }, "info");

  const summary =
    typeof parsed?.summary === "string" && parsed.summary.trim()
      ? parsed.summary.trim()
      : threats.length === 0
        ? "No security threats identified in this node."
        : `Identified ${threats.length} potential threat${threats.length === 1 ? "" : "s"} with overall ${overallRisk} risk.`;

  return {
    nodeId: node.id,
    provider,
    model,
    analyzedAt: new Date().toISOString(),
    summary,
    threats,
    overallRisk,
    masked: content.masked,
    redactions: content.redactions,
  };
}

/**
 * Dispatches node security threat analysis to the configured AI provider via function calling.
 */
export async function analyzeNodeSecurityThreats(
  options: AnalyzeThreatsOptions,
): Promise<NodeThreatReport> {
  const { node, content, provider, apiKey } = options;

  if (node.sensitive) {
    throw new ThreatAnalysisError(
      "Sensitive files cannot be sent to an AI model",
      "SENSITIVE_NODE",
      400,
    );
  }

  const trimmedKey = apiKey?.trim();
  if (!trimmedKey) {
    throw new ThreatAnalysisError(
      `No API key configured for provider ${provider}`,
      "UNCONFIGURED",
      400,
    );
  }

  const model = options.model?.trim() || AI_PROVIDER_METADATA[provider].defaultModel;
  const prompt = buildThreatAnalysisPrompt(node, content);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 60_000);

  try {
    let rawArgs: unknown;

    switch (provider) {
      case "gemini": {
        const outcome = await callGeminiFunction(
          model,
          prompt,
          trimmedKey,
          {
            name: REPORT_SECURITY_THREATS_NAME,
            description: REPORT_SECURITY_THREATS_DESCRIPTION,
            parameters: REPORT_SECURITY_THREATS_SCHEMA,
            acceptsText: (parsed) => Array.isArray(parsed.threats),
          },
          controller.signal,
          (status) => new ThreatAnalysisError(`Gemini request failed (HTTP ${status}). Check the API key and selected model, then try again.`, "PROVIDER_ERROR", status),
        );
        rawArgs = outcome.args;
        if (rawArgs === undefined) {
          throw new ThreatAnalysisError(
            `Provider gemini did not invoke the ${REPORT_SECURITY_THREATS_NAME} function (${describeGeminiStop(outcome.reason)})`,
            "PARSE_ERROR",
            502,
          );
        }
        break;
      }

      case "chatgpt":
      case "grok": {
        const url =
          provider === "grok"
            ? "https://api.x.ai/v1/chat/completions"
            : "https://api.openai.com/v1/chat/completions";

        const body = {
          model,
          temperature: 0.1,
          max_tokens: 2048,
          messages: [
            {
              role: "system",
              content:
                "You are a senior application security engineer and code auditor. You evaluate source code for vulnerabilities and always report findings using the report_security_threats tool.",
            },
            {
              role: "user",
              content: prompt,
            },
          ],
          tools: [
            {
              type: "function",
              function: {
                name: REPORT_SECURITY_THREATS_NAME,
                description: REPORT_SECURITY_THREATS_DESCRIPTION,
                parameters: REPORT_SECURITY_THREATS_SCHEMA,
              },
            },
          ],
          tool_choice: {
            type: "function",
            function: { name: REPORT_SECURITY_THREATS_NAME },
          },
        };

        const res = await fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${trimmedKey}`,
            "User-Agent": "Adam-Code-Network/1.0",
          },
          body: JSON.stringify(body),
          signal: controller.signal,
        });

        if (!res.ok) {
          throw new ThreatAnalysisError(
            `${provider === "grok" ? "xAI Grok" : "OpenAI"} request failed (HTTP ${res.status}). Check the API key and selected model, then try again.`,
            "PROVIDER_ERROR",
            res.status,
          );
        }

        const data = (await res.json()) as any;
        const toolCalls = data.choices?.[0]?.message?.tool_calls ?? [];
        for (const tc of toolCalls) {
          if (tc.function?.name === REPORT_SECURITY_THREATS_NAME) {
            rawArgs =
              typeof tc.function.arguments === "string"
                ? JSON.parse(tc.function.arguments)
                : tc.function.arguments;
            break;
          }
        }
        break;
      }

      case "claude": {
        const url = "https://api.anthropic.com/v1/messages";
        const body = {
          model,
          max_tokens: 2048,
          temperature: 0,
          messages: [
            {
              role: "user",
              content: prompt,
            },
          ],
          tools: [
            {
              name: REPORT_SECURITY_THREATS_NAME,
              description: REPORT_SECURITY_THREATS_DESCRIPTION,
              input_schema: REPORT_SECURITY_THREATS_SCHEMA,
            },
          ],
          tool_choice: {
            type: "tool",
            name: REPORT_SECURITY_THREATS_NAME,
          },
        };

        const res = await fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": trimmedKey,
            "anthropic-version": "2023-06-01",
            "User-Agent": "Adam-Code-Network/1.0",
          },
          body: JSON.stringify(body),
          signal: controller.signal,
        });

        if (!res.ok) {
          throw new ThreatAnalysisError(`Anthropic request failed (HTTP ${res.status}). Check the API key and selected model, then try again.`, "PROVIDER_ERROR", res.status);
        }

        const data = (await res.json()) as any;
        const blocks = data.content ?? [];
        for (const block of blocks) {
          if (block.type === "tool_use" && block.name === REPORT_SECURITY_THREATS_NAME) {
            rawArgs =
              typeof block.input === "string" ? JSON.parse(block.input) : block.input;
            break;
          }
        }
        break;
      }
    }

    if (!rawArgs || typeof rawArgs !== "object") {
      throw new ThreatAnalysisError(
        `Provider ${provider} did not invoke the ${REPORT_SECURITY_THREATS_NAME} function`,
        "PARSE_ERROR",
        502,
      );
    }

    return sanitizeReport(rawArgs, node, provider, model, content);
  } catch (err: unknown) {
    if (err instanceof ThreatAnalysisError) throw err;
    const error = err as Error;
    if (error?.name === "AbortError") {
      throw new ThreatAnalysisError(
        "Threat analysis request timed out after 60 seconds",
        "PROVIDER_ERROR",
        504,
      );
    }
    throw new ThreatAnalysisError(
      "Threat analysis failed unexpectedly. Check the provider configuration and try again.",
      "PROVIDER_ERROR",
      500,
    );
  } finally {
    clearTimeout(timeout);
  }
}
