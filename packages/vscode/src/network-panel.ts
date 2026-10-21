import { randomBytes } from "node:crypto";
import * as path from "node:path";
import * as vscode from "vscode";
import {
  AI_PROVIDERS,
  analyzeNodeSecurityThreats,
  describeNodeFile,
  listAiProviderModels,
  probeAiProviderKey,
  type AiProvider,
  type GraphNode,
} from "@adam/core";
import { sensitiveReason } from "@adam/core/src/sensitive";
import type { ExtensionMessage, WebviewRequest } from "@adam/ui/src/host";
import type { VsCodeAiSecretManager } from "./ai-secret-manager";
import type { ServiceClient } from "./service-client";

/** The full-window network view for one workspace folder. */
export class NetworkPanel implements vscode.Disposable {
  private static readonly panels = new Map<string, NetworkPanel>();
  private readonly disposables: vscode.Disposable[] = [];

  static show(
    extensionUri: vscode.Uri,
    client: ServiceClient,
    secretManager: VsCodeAiSecretManager,
  ): void {
    const key = client.folder.uri.toString();
    const existing = NetworkPanel.panels.get(key);
    if (existing) {
      existing.panel.reveal();
      return;
    }
    NetworkPanel.panels.set(key, new NetworkPanel(extensionUri, client, secretManager));
  }

  private readonly panel: vscode.WebviewPanel;

  private constructor(
    extensionUri: vscode.Uri,
    private readonly client: ServiceClient,
    private readonly secretManager: VsCodeAiSecretManager,
  ) {
    const uiRoot = vscode.Uri.joinPath(extensionUri, "dist", "ui");
    this.panel = vscode.window.createWebviewPanel("adam.network", `Adam: ${client.folder.name}`, vscode.ViewColumn.One, {
      enableScripts: true,
      retainContextWhenHidden: true,
      localResourceRoots: [uiRoot],
    });
    this.panel.iconPath = vscode.Uri.joinPath(extensionUri, "media", "icon.png");
    this.panel.webview.html = this.html(uiRoot);

    this.disposables.push(
      this.panel.webview.onDidReceiveMessage((msg: WebviewRequest) => void this.onMessage(msg)),
      client.onGraphChanged(() => this.post({ type: "event", event: "graph" })),
      this.panel.onDidDispose(() => this.dispose()),
    );
  }

  dispose(): void {
    NetworkPanel.panels.delete(this.client.folder.uri.toString());
    this.disposables.forEach((d) => d.dispose());
  }

  private post(msg: ExtensionMessage): void {
    void this.panel.webview.postMessage(msg);
  }

  private async onMessage(msg: WebviewRequest): Promise<void> {
    if (msg.type === "openFile") return this.openFile(msg.path, msg.line);
    try {
      let result: unknown;
      switch (msg.method) {
        case "graph":
          result = await this.client.request("GET", "/api/graph");
          break;
        case "node":
          result = await this.client.request("GET", `/api/node?id=${encodeURIComponent(msg.params.id)}`);
          break;
        case "symbol":
          result = await this.client.request(
            "GET",
            `/api/symbol?node=${encodeURIComponent(msg.params.node)}&id=${encodeURIComponent(msg.params.id)}`,
          );
          break;
        case "reindex":
          result = await this.client.request("POST", "/api/reindex");
          break;
        case "ai:getConfig":
          result = await this.secretManager.getConfigSummary();
          break;
        case "ai:saveConfig":
          assertAiProvider(msg.params?.provider);
          await this.secretManager.saveKey(msg.params);
          result = await this.secretManager.getConfigSummary();
          break;
        case "ai:deleteConfig":
          assertAiProvider(msg.params?.provider);
          await this.secretManager.deleteKey(msg.params.provider);
          result = await this.secretManager.getConfigSummary();
          break;
        case "ai:setActive":
          assertAiProvider(msg.params?.provider);
          await this.secretManager.setActiveProvider(msg.params.provider);
          result = await this.secretManager.getConfigSummary();
          break;
        case "ai:listModels": {
          assertAiProvider(msg.params?.provider);
          const apiKey = msg.params.apiKey || (await this.secretManager.getRawKey(msg.params.provider));
          if (!apiKey) throw new Error("Enter or save an API key before refreshing models.");
          result = await listAiProviderModels(msg.params.provider, apiKey);
          break;
        }
        case "ai:validateKey": {
          assertAiProvider(msg.params?.provider);
          const key = msg.params.apiKey || (await this.secretManager.getRawKey(msg.params.provider));
          if (!key) {
            result = {
              provider: msg.params.provider,
              ok: false,
              message: "No API key configured for provider",
            };
          } else {
            const probeResult = await probeAiProviderKey(msg.params.provider, key);
            await this.secretManager.recordTestResult(
              msg.params.provider,
              probeResult.ok,
              probeResult.ok ? undefined : probeResult.message,
            );
            result = probeResult;
          }
          break;
        }
        case "ai:describeNode": {
          if (!msg.params?.nodeId) throw new Error("Missing nodeId");
          const summary = await this.secretManager.getConfigSummary();
          const activeProvider = summary.activeProvider;
          if (!activeProvider) {
            throw new Error("No active AI provider configured");
          }
          const apiKey = await this.secretManager.getRawKey(activeProvider);
          if (!apiKey) {
            throw new Error(`No API key configured for provider ${activeProvider}`);
          }
          const nodeRes = await this.client.request<{
            node: GraphNode;
            content: string;
            masked: boolean;
            redactions: number;
          }>("GET", `/api/node?id=${encodeURIComponent(msg.params.nodeId)}`);

          if (nodeRes.node.sensitive || nodeRes.masked) {
            throw new Error("Sensitive files cannot be sent to an AI model");
          }
          if (nodeRes.node.binary) {
            throw new Error("Binary files cannot be described by an AI model");
          }

          result = await describeNodeFile({
            node: nodeRes.node,
            content: {
              content: nodeRes.content,
              masked: nodeRes.masked,
              redactions: nodeRes.redactions,
            },
            provider: activeProvider,
            apiKey,
            model: summary.providers[activeProvider]?.selectedModel,
          });
          break;
        }
        case "ai:analyzeThreats": {
          if (!msg.params?.nodeId) throw new Error("Missing nodeId");
          const summary = await this.secretManager.getConfigSummary();
          const activeProvider = summary.activeProvider;
          if (!activeProvider) {
            throw new Error("No active AI provider configured");
          }
          const apiKey = await this.secretManager.getRawKey(activeProvider);
          if (!apiKey) {
            throw new Error(`No API key configured for provider ${activeProvider}`);
          }
          const model = summary.providers[activeProvider]?.selectedModel;
          const nodeRes = await this.client.request<{
            node: GraphNode;
            content: string;
            masked: boolean;
            redactions: number;
          }>("GET", `/api/node?id=${encodeURIComponent(msg.params.nodeId)}`);

          if (nodeRes.node.sensitive) {
            throw new Error("Sensitive files cannot be sent to an AI model");
          }

          result = await analyzeNodeSecurityThreats({
            node: nodeRes.node,
            content: {
              content: nodeRes.content,
              masked: nodeRes.masked,
              redactions: nodeRes.redactions,
            },
            provider: activeProvider,
            apiKey,
            model,
          });
          break;
        }
      }
      this.post({ type: "response", id: msg.id, ok: true, result });
    } catch (err) {
      const message = err instanceof Error ? err.message : "AI operation failed.";
      this.post({ type: "response", id: msg.id, ok: false, error: message.slice(0, 240) });
    }
  }

  /** Opens a node in the real editor so the engineer can edit it by hand. */
  private async openFile(relPath: string, line?: number): Promise<void> {
    const normalized = path.posix.normalize(relPath);
    if (normalized.startsWith("..") || path.posix.isAbsolute(normalized)) return;
    if (sensitiveReason(normalized)) {
      const choice = await vscode.window.showWarningMessage(
        `${normalized} holds secrets. Opening it shows the real values on screen.`,
        { modal: true },
        "Open anyway",
      );
      if (choice !== "Open anyway") return;
    }
    const uri = vscode.Uri.joinPath(this.client.folder.uri, ...normalized.split("/"));
    const position = new vscode.Position(Math.max(0, (line ?? 1) - 1), 0);
    await vscode.window.showTextDocument(uri, {
      viewColumn: vscode.ViewColumn.Beside,
      selection: new vscode.Range(position, position),
      preview: false,
    });
  }

  private html(uiRoot: vscode.Uri): string {
    const webview = this.panel.webview;
    const nonce = randomBytes(16).toString("base64");
    const script = webview.asWebviewUri(vscode.Uri.joinPath(uiRoot, "main.js"));
    const style = webview.asWebviewUri(vscode.Uri.joinPath(uiRoot, "main.css"));
    const csp = [
      "default-src 'none'",
      `img-src ${webview.cspSource} data:`,
      `style-src ${webview.cspSource} 'unsafe-inline'`,
      `font-src ${webview.cspSource}`,
      `script-src 'nonce-${nonce}'`,
    ].join("; ");
    return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="Content-Security-Policy" content="${csp}" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="stylesheet" href="${style}" />
    <title>Adam</title>
  </head>
  <body>
    <script nonce="${nonce}" src="${script}"></script>
  </body>
</html>`;
  }
}

function assertAiProvider(value: unknown): asserts value is AiProvider {
  if (typeof value !== "string" || !AI_PROVIDERS.includes(value as AiProvider)) {
    throw new Error("Unsupported AI provider.");
  }
}
