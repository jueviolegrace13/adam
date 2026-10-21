import {
  AI_PROVIDER_METADATA,
  NodeDescriptionError,
  type AiProvider,
  type NodeDescriptionConfidence,
  type NodeDescriptionReport,
  type NodeDescriptionSymbol,
} from "./ai-types";
import type { GraphNode } from "./types";

export const DESCRIBE_NODE_NAME = "describe_node_file";

export const DESCRIBE_NODE_DESCRIPTION =
  "Return a source-grounded explanation of a selected code file, its responsibilities, symbols, dependencies, and data flow.";

export const DESCRIBE_NODE_SCHEMA = {
  type: "object",
  properties: {
    summary: {
      type: "string",
      description: "A concise one or two sentence explanation of the file.",
    },
    purpose: {
      type: "string",
      description: "The primary role this file plays in the codebase.",
    },
    responsibilities: {
      type: "array",
      items: { type: "string" },
      description: "Concrete responsibilities directly supported by the source code.",
    },
    keySymbols: {
      type: "array",
      description: "Important functions, classes, types, or constants declared by the file.",
      items: {
        type: "object",
        properties: {
          name: { type: "string" },
          kind: { type: "string" },
          description: { type: "string" },
          line: { type: "integer", description: "1-based source line, when known." },
        },
        required: ["name", "kind", "description"],
      },
    },
    dependencies: {
      type: "array",
      items: { type: "string" },
      description: "Important local or external dependencies and why they are used.",
    },
    dataFlow: {
      type: "array",
      items: { type: "string" },
      description: "Grounded input, transformation, and output steps visible in this file.",
    },
    notableDetails: {
      type: "array",
      items: { type: "string" },
      description: "Configuration use, side effects, error handling, or other noteworthy behavior.",
    },
    confidence: {
      type: "string",
      enum: ["high", "medium", "low"],
      description: "Confidence that the explanation is fully supported by the supplied file.",
    },
  },
  required: [
    "summary",
    "purpose",
    "responsibilities",
    "keySymbols",
    "dependencies",
    "dataFlow",
    "notableDetails",
    "confidence",
  ],
} as const;

export interface DescribeNodeOptions {
  node: GraphNode;
  content: { content: string; masked: boolean; redactions: number };
  provider: AiProvider;
  apiKey: string;
  model?: string;
}

/** Builds a prompt from indexed metadata and already-sanitized source content. */
export function buildNodeDescriptionPrompt(
  node: GraphNode,
  content: { content: string; masked: boolean; redactions: number },
): string {
  const symbols = node.symbols.length
    ? node.symbols
        .slice(0, 40)
        .map((symbol) => `${symbol.name} (${symbol.kind}, lines ${symbol.start.line}-${symbol.end.line})`)
        .join("\n  * ")
    : "None detected";
  const numberedSource = content.content
    .split(/\r?\n/)
    .map((line, index) => `${index + 1} | ${line}`)
    .join("\n");
  const sanitization = content.redactions > 0
    ? `- Sanitization: ${content.redactions} secret-looking value(s) were replaced with [SECRET_REDACTED]. Do not infer or reconstruct them.`
    : "- Sanitization: No secret-looking values were detected.";

  return [
    "Inspect and describe this source file for a developer who is new to the codebase.",
    `Invoke '${DESCRIBE_NODE_NAME}' with a concise, structured explanation grounded only in the supplied metadata and source.`,
    "Do not invent callers, runtime behavior, business rules, or data that are not visible here.",
    "Never reproduce, infer, or speculate about credentials or redacted values.",
    "Use an empty list when a requested category is not supported by the file.",
    "",
    "### File Information",
    `- Path: ${node.id}`,
    `- Language: ${node.language || "unknown"}`,
    `- Size: ${node.size} bytes (${node.lines} lines)`,
    `- External packages: ${node.packages.length ? node.packages.join(", ") : "None detected"}`,
    `- Environment/configuration keys read: ${node.envReads.length ? node.envReads.join(", ") : "None detected"}`,
    `- Unresolved imports: ${node.unresolved.length ? node.unresolved.join(", ") : "None detected"}`,
    sanitization,
    `- Symbols:\n  * ${symbols}`,
    "",
    "### Sanitized Source Code",
    `\`\`\`${node.language || ""}`,
    numberedSource,
    "```",
  ].join("\n");
}

function parseObject(raw: unknown): Record<string, unknown> {
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw) as unknown;
      return parsed && typeof parsed === "object" ? parsed as Record<string, unknown> : {};
    } catch {
      return {};
    }
  }
  return raw && typeof raw === "object" ? raw as Record<string, unknown> : {};
}

function cleanText(value: unknown, fallback = "", maxLength = 1_500): string {
  return typeof value === "string" && value.trim()
    ? value.trim().slice(0, maxLength)
    : fallback;
}

function cleanList(value: unknown, maxItems = 12): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is string => typeof item === "string" && Boolean(item.trim()))
    .slice(0, maxItems)
    .map((item) => item.trim().slice(0, 600));
}

function sanitizeDescription(
  raw: unknown,
  node: GraphNode,
  provider: AiProvider,
  model: string,
  content: { masked: boolean; redactions: number },
): NodeDescriptionReport {
  const parsed = parseObject(raw);
  const rawSymbols = Array.isArray(parsed.keySymbols) ? parsed.keySymbols : [];
  const keySymbols: NodeDescriptionSymbol[] = rawSymbols
    .filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object")
    .slice(0, 20)
    .map((item) => {
      const symbol: NodeDescriptionSymbol = {
        name: cleanText(item.name, "Unnamed symbol", 200),
        kind: cleanText(item.kind, "symbol", 100),
        description: cleanText(item.description, "", 800),
      };
      if (typeof item.line === "number" && Number.isFinite(item.line)) {
        symbol.line = Math.min(Math.max(1, Math.floor(item.line)), Math.max(1, node.lines));
      }
      return symbol;
    });
  const confidenceValue = cleanText(parsed.confidence).toLowerCase();
  const confidence: NodeDescriptionConfidence =
    confidenceValue === "high" || confidenceValue === "low" ? confidenceValue : "medium";

  return {
    nodeId: node.id,
    nodeHash: node.hash,
    provider,
    model,
    analyzedAt: new Date().toISOString(),
    summary: cleanText(parsed.summary, "The provider did not return a summary."),
    purpose: cleanText(parsed.purpose, "Purpose could not be determined from this file."),
    responsibilities: cleanList(parsed.responsibilities),
    keySymbols,
    dependencies: cleanList(parsed.dependencies),
    dataFlow: cleanList(parsed.dataFlow),
    notableDetails: cleanList(parsed.notableDetails),
    confidence,
    masked: content.masked,
    redactions: content.redactions,
  };
}

/** Sends a non-sensitive selected file to the configured provider for structured explanation. */
export async function describeNodeFile(options: DescribeNodeOptions): Promise<NodeDescriptionReport> {
  const { node, content, provider } = options;

  if (node.sensitive || content.masked) {
    throw new NodeDescriptionError(
      "Sensitive files cannot be sent to an AI model",
      "SENSITIVE_NODE",
      400,
    );
  }
  if (node.binary || !content.content.trim()) {
    throw new NodeDescriptionError(
      "Binary or empty files cannot be described by the AI model",
      "UNSUPPORTED_NODE",
      400,
    );
  }

  const apiKey = options.apiKey?.trim();
  if (!apiKey) {
    throw new NodeDescriptionError(
      `No API key configured for provider ${provider}`,
      "UNCONFIGURED",
      400,
    );
  }

  const model = options.model?.trim() || AI_PROVIDER_METADATA[provider].defaultModel;
  const prompt = buildNodeDescriptionPrompt(node, content);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 60_000);

  try {
    let rawArgs: unknown;

    switch (provider) {
      case "gemini": {
        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "User-Agent": "Adam-Code-Network/1.0",
              "x-goog-api-key": apiKey,
            },
            body: JSON.stringify({
              contents: [{ role: "user", parts: [{ text: prompt }] }],
              generationConfig: { maxOutputTokens: 2500, temperature: 0.1 },
              tools: [{
                functionDeclarations: [{
                  name: DESCRIBE_NODE_NAME,
                  description: DESCRIBE_NODE_DESCRIPTION,
                  parameters: DESCRIBE_NODE_SCHEMA,
                }],
              }],
              toolConfig: {
                functionCallingConfig: {
                  mode: "ANY",
                  allowedFunctionNames: [DESCRIBE_NODE_NAME],
                },
              },
            }),
            signal: controller.signal,
          },
        );
        if (!response.ok) {
          throw new NodeDescriptionError(
            `Gemini request failed (HTTP ${response.status}). Check the API key and selected model, then try again.`,
            "PROVIDER_ERROR",
            response.status,
          );
        }
        const data = await response.json() as {
          candidates?: Array<{ content?: { parts?: Array<{ functionCall?: { name?: string; args?: unknown } }> } }>;
        };
        rawArgs = data.candidates?.[0]?.content?.parts?.find(
          (part) => part.functionCall?.name === DESCRIBE_NODE_NAME,
        )?.functionCall?.args;
        break;
      }

      case "chatgpt":
      case "grok": {
        const response = await fetch(
          provider === "grok" ? "https://api.x.ai/v1/chat/completions" : "https://api.openai.com/v1/chat/completions",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${apiKey}`,
              "User-Agent": "Adam-Code-Network/1.0",
            },
            body: JSON.stringify({
              model,
              temperature: 0.1,
              max_tokens: 2500,
              messages: [
                {
                  role: "system",
                  content: "You are a senior software architect. Explain source files accurately and only from supplied evidence. Always use the describe_node_file tool.",
                },
                { role: "user", content: prompt },
              ],
              tools: [{
                type: "function",
                function: {
                  name: DESCRIBE_NODE_NAME,
                  description: DESCRIBE_NODE_DESCRIPTION,
                  parameters: DESCRIBE_NODE_SCHEMA,
                },
              }],
              tool_choice: { type: "function", function: { name: DESCRIBE_NODE_NAME } },
            }),
            signal: controller.signal,
          },
        );
        if (!response.ok) {
          throw new NodeDescriptionError(
            `${provider === "grok" ? "xAI Grok" : "OpenAI"} request failed (HTTP ${response.status}). Check the API key and selected model, then try again.`,
            "PROVIDER_ERROR",
            response.status,
          );
        }
        const data = await response.json() as {
          choices?: Array<{ message?: { tool_calls?: Array<{ function?: { name?: string; arguments?: unknown } }> } }>;
        };
        const args = data.choices?.[0]?.message?.tool_calls?.find(
          (call) => call.function?.name === DESCRIBE_NODE_NAME,
        )?.function?.arguments;
        rawArgs = typeof args === "string" ? parseObject(args) : args;
        break;
      }

      case "claude": {
        const response = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": apiKey,
            "anthropic-version": "2023-06-01",
            "User-Agent": "Adam-Code-Network/1.0",
          },
          body: JSON.stringify({
            model,
            max_tokens: 2500,
            temperature: 0,
            messages: [{ role: "user", content: prompt }],
            tools: [{
              name: DESCRIBE_NODE_NAME,
              description: DESCRIBE_NODE_DESCRIPTION,
              input_schema: DESCRIBE_NODE_SCHEMA,
            }],
            tool_choice: { type: "tool", name: DESCRIBE_NODE_NAME },
          }),
          signal: controller.signal,
        });
        if (!response.ok) {
          throw new NodeDescriptionError(
            `Anthropic request failed (HTTP ${response.status}). Check the API key and selected model, then try again.`,
            "PROVIDER_ERROR",
            response.status,
          );
        }
        const data = await response.json() as {
          content?: Array<{ type?: string; name?: string; input?: unknown }>;
        };
        const input = data.content?.find(
          (block) => block.type === "tool_use" && block.name === DESCRIBE_NODE_NAME,
        )?.input;
        rawArgs = typeof input === "string" ? parseObject(input) : input;
        break;
      }
    }

    if (!rawArgs || typeof rawArgs !== "object") {
      throw new NodeDescriptionError(
        `Provider ${provider} did not invoke the ${DESCRIBE_NODE_NAME} function`,
        "PARSE_ERROR",
        502,
      );
    }

    return sanitizeDescription(rawArgs, node, provider, model, content);
  } catch (error: unknown) {
    if (error instanceof NodeDescriptionError) throw error;
    if ((error as Error)?.name === "AbortError") {
      throw new NodeDescriptionError(
        "Node description request timed out after 60 seconds",
        "PROVIDER_ERROR",
        504,
      );
    }
    throw new NodeDescriptionError(
      "Node description failed unexpectedly. Check the provider configuration and try again.",
      "PROVIDER_ERROR",
      500,
    );
  } finally {
    clearTimeout(timeout);
  }
}
