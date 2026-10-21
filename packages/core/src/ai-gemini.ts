/** Output budget for Gemini. Current Gemini models think before answering and the
 * thinking tokens count against maxOutputTokens, so a small budget can run out
 * before the function call is written. */
export const GEMINI_MAX_OUTPUT_TOKENS = 16384;

export interface GeminiFunction {
  name: string;
  description: string;
  parameters: unknown;
  /** Accepts a JSON object the model wrote as text instead of calling the function. */
  acceptsText: (parsed: Record<string, unknown>) => boolean;
}

export interface GeminiOutcome {
  args: unknown;
  /** finishReason or promptFeedback.blockReason when no call came back. */
  reason?: string;
  retryable: boolean;
}

/** One Gemini generateContent request that must answer by calling `fn`. Throws `onHttpError` when the request fails. */
export async function requestGeminiFunctionCall(
  model: string,
  prompt: string,
  apiKey: string,
  fn: GeminiFunction,
  signal: AbortSignal,
  onHttpError: (status: number) => Error,
): Promise<GeminiOutcome> {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
  const body = {
    contents: [
      {
        role: "user",
        parts: [{ text: prompt }],
      },
    ],
    // No temperature override: Gemini 3 models are tuned for the default and
    // can loop or skip tool calls at low temperatures.
    generationConfig: {
      maxOutputTokens: GEMINI_MAX_OUTPUT_TOKENS,
    },
    tools: [
      {
        functionDeclarations: [
          {
            name: fn.name,
            description: fn.description,
            parameters: fn.parameters,
          },
        ],
      },
    ],
    toolConfig: {
      functionCallingConfig: {
        mode: "ANY",
        allowedFunctionNames: [fn.name],
      },
    },
  };

  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": "Adam-Code-Network/1.0",
      "x-goog-api-key": apiKey,
    },
    body: JSON.stringify(body),
    signal,
  });

  if (!res.ok) throw onHttpError(res.status);

  const data = (await res.json()) as any;
  const blockReason: string | undefined = data.promptFeedback?.blockReason;
  if (blockReason) {
    return { args: undefined, reason: blockReason, retryable: false };
  }

  const candidate = data.candidates?.[0];
  const parts: any[] = candidate?.content?.parts ?? [];
  for (const part of parts) {
    if (part.functionCall && part.functionCall.name === fn.name) {
      const args = part.functionCall.args;
      if (args && typeof args === "object") return { args, retryable: false };
    }
  }

  // Some models answer with the report as JSON text instead of a call.
  for (const part of parts) {
    if (part.thought || typeof part.text !== "string") continue;
    const parsed = parseJsonObject(part.text);
    if (parsed && fn.acceptsText(parsed)) return { args: parsed, retryable: false };
  }

  const reason: string | undefined = candidate?.finishReason;
  return {
    args: undefined,
    reason,
    retryable: reason !== "SAFETY" && reason !== "PROHIBITED_CONTENT" && reason !== "BLOCKLIST",
  };
}

/**
 * Calls `fn` on Gemini and retries once when the turn ends without the call (thinking
 * used up the output budget, or a malformed call). Returns the outcome of the last try.
 */
export async function callGeminiFunction(
  model: string,
  prompt: string,
  apiKey: string,
  fn: GeminiFunction,
  signal: AbortSignal,
  onHttpError: (status: number) => Error,
): Promise<GeminiOutcome> {
  let outcome = await requestGeminiFunctionCall(model, prompt, apiKey, fn, signal, onHttpError);
  if (outcome.args === undefined && outcome.retryable) {
    outcome = await requestGeminiFunctionCall(model, prompt, apiKey, fn, signal, onHttpError);
  }
  return outcome;
}

/** Parses an object out of model text, with or without a ```json fence. */
function parseJsonObject(text: string): Record<string, unknown> | undefined {
  const fenced = /```(?:json)?\s*([\s\S]*?)```/.exec(text);
  const candidate = (fenced ? fenced[1] : text).trim();
  if (!candidate.startsWith("{")) return undefined;
  try {
    const parsed = JSON.parse(candidate);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed;
  } catch {
    // not JSON
  }
  return undefined;
}

export function describeGeminiStop(reason: string | undefined): string {
  switch (reason) {
    case "MAX_TOKENS":
      return "the model ran out of output tokens; try a smaller file or another model";
    case "MALFORMED_FUNCTION_CALL":
      return "the model produced a malformed function call; try again or pick another model";
    case "SAFETY":
    case "PROHIBITED_CONTENT":
    case "BLOCKLIST":
      return "Gemini's safety filter blocked the response";
    case undefined:
    case "":
      return "no function call in the response";
    default:
      return `finish reason ${reason}`;
  }
}
