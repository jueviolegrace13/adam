/** Supported AI Provider Identifiers */
export type AiProvider = "chatgpt" | "claude" | "grok" | "gemini";

export const AI_PROVIDERS: readonly AiProvider[] = [
  "chatgpt",
  "claude",
  "grok",
  "gemini",
] as const;

/** Display metadata for UI rendering */
export interface AiProviderMeta {
  readonly id: AiProvider;
  readonly name: string;
  readonly description: string;
  readonly placeholder: string;
  readonly keyPrefixHint?: string;
  readonly consoleUrl: string;
  readonly defaultModel: string;
  readonly availableModels: readonly string[];
}

export const AI_PROVIDER_METADATA: Record<AiProvider, AiProviderMeta> = {
  chatgpt: {
    id: "chatgpt",
    name: "OpenAI ChatGPT",
    description: "Current OpenAI models for code analysis and tool calling",
    placeholder: "sk-proj-...",
    keyPrefixHint: "sk-",
    consoleUrl: "https://platform.openai.com/api-keys",
    defaultModel: "gpt-5.6-sol",
    availableModels: [
      "gpt-5.6-sol",
      "gpt-5.6-terra",
      "gpt-5.6-luna",
      "gpt-5.5",
      "gpt-5.4",
    ],
  },
  claude: {
    id: "claude",
    name: "Anthropic Claude",
    description: "Current Claude models for code analysis and tool calling",
    placeholder: "sk-ant-api03-...",
    keyPrefixHint: "sk-ant-",
    consoleUrl: "https://console.anthropic.com/settings/keys",
    defaultModel: "claude-sonnet-5-5",
    availableModels: [
      "claude-sonnet-5-5",
      "claude-opus-5-5",
      "claude-haiku-5-5",
      "claude-fable-5-1",
    ],
  },
  grok: {
    id: "grok",
    name: "xAI Grok",
    description: "Current Grok models for code analysis and tool calling",
    placeholder: "xai-...",
    keyPrefixHint: "xai-",
    consoleUrl: "https://console.x.ai/",
    defaultModel: "grok-4.7",
    availableModels: [
      "grok-4.7",
      "grok-4.6",
      "grok-4.5",
      "grok-4.3",
    ],
  },
  gemini: {
    id: "gemini",
    name: "Google Gemini",
    description: "Current Gemini models for code analysis and tool calling",
    placeholder: "AQ... or AIza...",
    keyPrefixHint: "AQ. or AIza",
    consoleUrl: "https://aistudio.google.com/app/apikey",
    defaultModel: "gemini-3.8-flash",
    availableModels: [
      "gemini-3.8-flash",
      "gemini-4-argon",
      "gemini-3.6-flash",
      "gemini-3.5-flash-lite",
      "gemini-3.1-pro-preview",
      "gemini-2.5-pro",
      "gemini-2.5-flash",
    ],
  },
};

/** Safe summary of a single provider returned to the UI */
export interface AiProviderStatus {
  provider: AiProvider;
  configured: boolean;
  /** Masked key representation, e.g. "sk-...4a2b" or undefined if unconfigured */
  maskedKey?: string;
  selectedModel?: string;
  updatedAt?: string;
  lastTestedAt?: string;
  lastTestStatus?: "ok" | "error";
  lastTestError?: string;
}

/** Global configuration summary sent to UI */
export interface AiConfigSummary {
  activeProvider?: AiProvider;
  providers: Record<AiProvider, AiProviderStatus>;
}

/** Mutation payload to save or update provider settings */
export interface SaveAiConfigRequest {
  provider: AiProvider;
  /** Plaintext key provided when updating or setting new key */
  apiKey?: string;
  selectedModel?: string;
  /** If true, immediately set this provider as the active engine */
  setActive?: boolean;
}

/** Payload to delete a configured key */
export interface DeleteAiConfigRequest {
  provider: AiProvider;
}

/** Payload to test a key (either newly input or previously stored) */
export interface ValidateAiKeyRequest {
  provider: AiProvider;
  /** If omitted, tests the currently stored key */
  apiKey?: string;
}

/** Result of a key validation probe */
export interface AiValidationResult {
  provider: AiProvider;
  ok: boolean;
  message: string;
  testedModel?: string;
  latencyMs?: number;
}

/** Confidence assigned by the model to a source-grounded node description. */
export type NodeDescriptionConfidence = "high" | "medium" | "low";

export interface NodeDescriptionSymbol {
  name: string;
  kind: string;
  description: string;
  line?: number;
}

/** Structured explanation of one selected, non-sensitive source file. */
export interface NodeDescriptionReport {
  nodeId: string;
  /** Used by the UI to discard a cached report after the file changes. */
  nodeHash: string;
  provider: AiProvider;
  model: string;
  analyzedAt: string;
  summary: string;
  purpose: string;
  responsibilities: string[];
  keySymbols: NodeDescriptionSymbol[];
  dependencies: string[];
  dataFlow: string[];
  notableDetails: string[];
  confidence: NodeDescriptionConfidence;
  masked: boolean;
  redactions: number;
}

export interface DescribeNodeRequest {
  nodeId: string;
  forceRefresh?: boolean;
}

export class NodeDescriptionError extends Error {
  constructor(
    message: string,
    readonly code?: "UNCONFIGURED" | "SENSITIVE_NODE" | "UNSUPPORTED_NODE" | "PROVIDER_ERROR" | "PARSE_ERROR" | "INVALID_REQUEST",
    readonly status?: number,
  ) {
    super(message);
    this.name = "NodeDescriptionError";
  }
}

/** Security Threat Severity Levels */
export type ThreatSeverity = "critical" | "high" | "medium" | "low" | "info";

/** Security Threat Categories */
export type ThreatCategory =
  | "injection"
  | "auth"
  | "sensitive_data"
  | "supply_chain"
  | "crypto"
  | "misconfiguration"
  | "denial_of_service"
  | "other";

export interface NodeThreatLocation {
  line?: number;
  lineStart?: number;
  lineEnd?: number;
  symbolName?: string;
}

export interface NodeThreat {
  id: string;
  title: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  description: string;
  location?: NodeThreatLocation;
  cwe?: string;
  recommendation: string;
}

export interface NodeThreatReport {
  nodeId: string;
  provider: AiProvider;
  model: string;
  analyzedAt: string;
  summary: string;
  threats: NodeThreat[];
  overallRisk: ThreatSeverity;
  masked: boolean;
  redactions: number;
}

export interface AnalyzeThreatsRequest {
  nodeId: string;
  forceRefresh?: boolean;
}

export class ThreatAnalysisError extends Error {
  constructor(
    message: string,
    readonly code?: "UNCONFIGURED" | "SENSITIVE_NODE" | "PROVIDER_ERROR" | "PARSE_ERROR" | "INVALID_REQUEST",
    readonly status?: number,
  ) {
    super(message);
    this.name = "ThreatAnalysisError";
  }
}
