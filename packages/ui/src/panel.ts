import type {
  CodeSymbol,
  GraphEdge,
  GraphNode,
  NodeDescriptionReport,
  NodeThreat,
  NodeThreatReport,
  ThreatCategory,
  ThreatSeverity,
} from "@adam/core";
import { getProviderDisplayName, openAiSettingsDialog } from "./ai-settings";
import { collapsible, formatBytes, h } from "./dom";
import type { Host } from "./host";
import type { UnitLink } from "./network";

const KIND_LABEL: Record<CodeSymbol["kind"], string> = {
  function: "fn",
  method: "method",
  constructor: "ctor",
  accessor: "get/set",
  class: "class",
  interface: "interface",
  type: "type",
  enum: "enum",
  variable: "const",
};

export interface PanelContext {
  host: Host;
  incoming: GraphEdge[];
  outgoing: GraphEdge[];
  onSelect: (id: string) => void;
  /** Extra buttons for the panel header, such as collapsing the node into its folder. */
  actions?: HTMLElement[];
}

export const threatCache = new Map<string, NodeThreatReport>();
export const patchedThreats = new Set<string>();
export const descriptionCache = new Map<string, NodeDescriptionReport>();

const LANGUAGE_LABELS: Record<string, string> = {
  typescript: "TypeScript source",
  javascript: "JavaScript source",
  csharp: "C# source",
  msbuild: "MSBuild project file",
  solution: ".NET solution file",
  json: "JSON file",
  markdown: "Markdown document",
  css: "CSS stylesheet",
  scss: "SCSS stylesheet",
  html: "HTML document",
  python: "Python source",
  java: "Java source",
  go: "Go source",
  rust: "Rust source",
  sql: "SQL script",
  yaml: "YAML configuration file",
  xml: "XML file",
  dotenv: "environment configuration file",
};

function countLabel(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

function symbolSummary(node: GraphNode): string | undefined {
  if (!node.symbols.length) return undefined;
  const counts = new Map<string, number>();
  for (const symbol of node.symbols) counts.set(symbol.kind, (counts.get(symbol.kind) ?? 0) + 1);
  const pair = (singular: string, plural: string): readonly [string, string] => [singular, plural];
  const labels: Record<string, readonly [string, string]> = {
    function: pair("function", "functions"),
    method: pair("method", "methods"),
    constructor: pair("constructor", "constructors"),
    accessor: pair("accessor", "accessors"),
    class: pair("class", "classes"),
    interface: pair("interface", "interfaces"),
    type: pair("type", "types"),
    enum: pair("enum", "enums"),
    variable: pair("constant", "constants"),
  };
  return [...counts]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([kind, count]) => {
      const [singular, plural] = labels[kind] ?? ([kind, `${kind}s`] as [string, string]);
      return countLabel(count, singular, plural);
    })
    .join(", ");
}

/** Builds a safe summary from indexed metadata; it never reads or includes file contents. */
function describeNode(node: GraphNode, incoming: number, outgoing: number): string {
  if (node.sensitive) {
    const declared = node.envDeclares.length
      ? ` Adam can show ${countLabel(node.envDeclares.length, "declared key")} only; its values remain hidden.`
      : " Its values remain hidden.";
    return `This protected ${node.language} file is masked to keep its contents private.${declared}`;
  }
  if (node.binary) return `This binary ${node.language} file is kept as a node but is not parsed for code symbols or imports.`;

  const kind = LANGUAGE_LABELS[node.language] ?? `${node.language[0]?.toUpperCase() ?? ""}${node.language.slice(1)} file`;
  const location = node.folder ? ` in the ${node.folder} folder` : " at the repository root";
  const parts = [`This ${kind} is${location}.`];
  const symbols = symbolSummary(node);
  if (symbols) parts.push(`It defines ${symbols}.`);
  else if (node.parsed) parts.push("It does not declare any indexed functions, classes, or types.");
  else parts.push("It was indexed as a file, but its language is not parsed for symbols.");
  if (outgoing) parts.push(`It imports ${countLabel(outgoing, "local file")}.`);
  if (incoming) parts.push(`It is imported by ${countLabel(incoming, "file")}.`);
  if (node.packages.length) {
    const packageNames = node.packages.slice(0, 3).join(", ");
    const suffix = node.packages.length > 3 ? `, and ${node.packages.length - 3} more` : "";
    parts.push(`It uses ${packageNames}${suffix}.`);
  }
  if (node.envReads.length) parts.push(`It reads ${countLabel(node.envReads.length, "environment or configuration value")}.`);
  return parts.join(" ");
}

/**
 * The node panel: what a file is, what it connects to, and its symbols collapsed by default.
 * Expanding a symbol fetches just that symbol's code.
 */
export function renderNodePanel(container: HTMLElement, node: GraphNode, ctx: PanelContext): void {
  const { host } = ctx;
  container.replaceChildren();
  const descriptionBody = h("div", { class: "node-description" });
  renderNodeDescriptionSection(descriptionBody, node, ctx);

  const openButton =
    host.openFile && !node.binary
      ? h(
          "button",
          { class: "primary", onclick: () => host.openFile!(node.id), title: "Open in the editor to edit by hand" },
          node.sensitive ? "Open in editor (shows values)" : "Open in editor",
        )
      : null;

  container.append(
    h(
      "header",
      { class: "panel-head" },
      h("div", { class: "panel-title" }, node.sensitive ? `🔒 ${node.name}` : node.name),
      h("div", { class: "panel-path" }, node.id),
      h(
        "div",
        { class: "chips" },
        h("span", { class: "chip" }, node.language),
        h("span", { class: "chip" }, formatBytes(node.size)),
        !node.binary && h("span", { class: "chip" }, `${node.lines} lines`),
        node.binary && h("span", { class: "chip" }, "binary"),
        node.sensitive && h("span", { class: "chip danger" }, "sensitive"),
        node.secretHints > 0 &&
          h("span", { class: "chip warn", title: "Secret-looking values in this file are masked" }, `${node.secretHints} secret${node.secretHints > 1 ? "s" : ""} masked`),
      ),
      h("div", { class: "panel-actions" }, openButton, ...(ctx.actions ?? [])),
    ),
    section("Description", descriptionBody),
  );

  if (node.sensitive) {
    container.append(
      h(
        "p",
        { class: "notice danger" },
        `${node.sensitiveReason ?? "Protected file"}. Values are never shown in Adam or sent to a model.`,
      ),
    );
    if (node.envDeclares.length) container.append(section("Declares (values hidden)", tagList(node.envDeclares)));
  }

  const threatsSection = h("section", { class: "panel-section panel-threats-section" });
  renderThreatsSection(threatsSection, node, ctx);
  container.append(threatsSection);

  if (node.symbols.length) {
    const list = h("div", { class: "symbols" });
    const topLevel = node.symbols.filter((s) => !s.parent);
    for (const sym of topLevel) {
      const members = node.symbols.filter((s) => s.parent === sym.id);
      list.append(symbolRow(node, sym, ctx, members));
    }
    container.append(section(`Symbols (${node.symbols.length})`, list));
  } else if (node.parsed) {
    container.append(section("Symbols", h("p", { class: "muted" }, "No functions, classes or types declared here.")));
  } else if (!node.binary && !node.sensitive) {
    container.append(
      section("Symbols", h("p", { class: "muted" }, `Symbols for ${node.language} files come in a later release. The file is still a node with its connections.`)),
    );
  }

  container.append(
    section(`Imports (${ctx.outgoing.length})`, edgeList(ctx.outgoing, "target", ctx)),
    section(`Imported by (${ctx.incoming.length})`, edgeList(ctx.incoming, "source", ctx)),
  );
  if (node.project) {
    container.append(section("Project", h("button", { class: "link", onclick: () => ctx.onSelect(node.project!) }, node.project)));
  }
  if (node.packages.length) {
    const title = node.language === "csharp" ? "Namespaces from outside the repo" : "Packages";
    container.append(section(`${title} (${node.packages.length})`, tagList(node.packages)));
  }
  if (node.envReads.length) container.append(section(`Reads env (${node.envReads.length})`, tagList(node.envReads)));
  if (node.unresolved.length) {
    container.append(
      section(`Unresolved imports (${node.unresolved.length})`, tagList(node.unresolved, "warn"), "These look local but no file matched. A broken path, or an alias Adam could not read."),
    );
  }
}

function symbolRow(node: GraphNode, sym: CodeSymbol, ctx: PanelContext, members: CodeSymbol[]): HTMLElement {
  const code = h("pre", { class: "code" });
  const body = h("div", { class: "symbol-body" }, code);
  const details = h(
    "details",
    { class: "symbol" },
    h(
      "summary",
      {},
      h("span", { class: `kind kind-${sym.kind}` }, KIND_LABEL[sym.kind]),
      h("span", { class: "symbol-name" }, sym.name),
      sym.exported && !sym.parent ? h("span", { class: "exported", title: "Exported" }, "export") : null,
      h("span", { class: "line" }, `L${sym.start.line}`),
    ),
    h("div", { class: "signature" }, sym.signature),
    body,
  );

  let loaded = false;
  details.addEventListener("toggle", () => {
    if (!details.open || loaded) return;
    loaded = true;
    code.textContent = "Loading…";
    ctx.host
      .getSymbol(node.id, sym.id)
      .then((res) => {
        code.textContent = res.content;
        if (res.redactions) body.prepend(h("p", { class: "notice warn" }, "Secret-looking values in this code are masked."));
      })
      .catch((err: Error) => {
        loaded = false;
        code.textContent = `Could not load: ${err.message}`;
      });
  });

  if (ctx.host.openFile) {
    body.append(h("button", { class: "link", onclick: () => ctx.host.openFile!(node.id, sym.start.line) }, `Open at line ${sym.start.line}`));
  }
  if (members.length) {
    const nested = h("div", { class: "symbols nested" });
    for (const m of members) nested.append(symbolRow(node, m, ctx, []));
    body.append(nested);
  }
  return details;
}

function edgeList(edges: GraphEdge[], end: "source" | "target", ctx: PanelContext): HTMLElement {
  if (!edges.length) return h("p", { class: "muted" }, end === "source" ? "Nothing imports this node." : "No local imports.");
  const ul = h("ul", { class: "edges" });
  for (const e of [...edges].sort((a, b) => a[end].localeCompare(b[end]))) {
    const label = e.kind === "imports" ? (e.typeOnly ? "type" : "") : e.kind;
    ul.append(
      h(
        "li",
        {},
        h("button", { class: "link", onclick: () => ctx.onSelect(e[end]), title: `${e.kind} "${e.specifier}"` }, e[end]),
        label ? h("span", { class: "edge-kind" }, label) : null,
      ),
    );
  }
  return ul;
}

function tagList(items: string[], tone = ""): HTMLElement {
  return h("div", { class: "tags" }, ...items.map((i) => h("span", { class: `tag ${tone}` }, i)));
}

function section(title: string, content: HTMLElement, hint?: string): HTMLElement {
  return collapsible(title, { class: "panel-section" }, hint ? h("p", { class: "muted small" }, hint) : null, content);
}

interface GroupPanelContext {
  folder: string;
  files: GraphNode[];
  outgoing: UnitLink[];
  incoming: UnitLink[];
  onExpand: () => void;
  onSelect: (id: string) => void;
  /** Replaces the Expand folder button, such as View in network in the Folders view. */
  primary?: HTMLElement;
  actions?: HTMLElement[];
}

/** The panel for a collapsed folder: its size, the folders it talks to, and its files. */
export function renderGroupPanel(container: HTMLElement, ctx: GroupPanelContext): void {
  const sensitive = ctx.files.filter((f) => f.sensitive).length;
  const lines = ctx.files.reduce((sum, f) => sum + (f.binary ? 0 : f.lines), 0);
  container.replaceChildren(
    h(
      "header",
      { class: "panel-head" },
      h("div", { class: "panel-title" }, `${ctx.folder.split("/").at(-1)}/`),
      h("div", { class: "panel-path" }, `${ctx.folder}/`),
      h(
        "div",
        { class: "chips" },
        h("span", { class: "chip" }, "folder"),
        h("span", { class: "chip" }, `${ctx.files.length} files`),
        h("span", { class: "chip" }, `${lines.toLocaleString()} lines`),
        sensitive > 0 && h("span", { class: "chip danger" }, `${sensitive} sensitive`),
      ),
      h(
        "div",
        { class: "panel-actions" },
        ctx.primary ?? h("button", { class: "primary", onclick: ctx.onExpand, title: "Show this folder's files and subfolders (or double-click it)" }, "Expand folder"),
        ...(ctx.actions ?? []),
      ),
    ),
    section(`Imports from (${ctx.outgoing.length})`, linkList(ctx.outgoing, "No imports leave this folder.", ctx)),
    section(`Imported by (${ctx.incoming.length})`, linkList(ctx.incoming, "Nothing outside this folder imports it.", ctx)),
    section(
      `Files (${ctx.files.length})`,
      h(
        "ul",
        { class: "edges" },
        ...[...ctx.files]
          .sort((a, b) => a.id.localeCompare(b.id))
          .map((f) =>
            h(
              "li",
              {},
              h("button", { class: "link", onclick: () => ctx.onSelect(f.id), title: f.id }, f.id.slice(ctx.folder.length + 1)),
            ),
          ),
      ),
    ),
  );
}

function linkList(links: UnitLink[], empty: string, ctx: GroupPanelContext): HTMLElement {
  if (!links.length) return h("p", { class: "muted" }, empty);
  return h(
    "ul",
    { class: "edges" },
    ...links.map((l) =>
      h(
        "li",
        {},
        h("button", { class: "link", onclick: () => ctx.onSelect(l.unit) }, l.label),
        h("span", { class: "edge-kind", title: "File-level imports" }, `${l.count}`),
      ),
    ),
  );
}

function renderNodeDescriptionSection(
  container: HTMLElement,
  node: GraphNode,
  ctx: PanelContext,
): void {
  const localSummary = () => h(
    "p",
    { class: "panel-description" },
    describeNode(node, ctx.incoming.length, ctx.outgoing.length),
  );

  if (node.sensitive) {
    descriptionCache.delete(node.id);
    container.replaceChildren(
      localSummary(),
      h(
        "p",
        { class: "notice warn node-description-sensitive-notice" },
        "🔒 AI description unavailable: this file is classified as sensitive and will not be sent to an external model.",
      ),
    );
    return;
  }

  if (node.binary) {
    container.replaceChildren(
      localSummary(),
      h("p", { class: "muted small" }, "AI description is unavailable for binary files."),
    );
    return;
  }

  const cached = descriptionCache.get(node.id);
  if (cached && cached.nodeHash !== node.hash) descriptionCache.delete(node.id);
  const current = descriptionCache.get(node.id);
  if (current) renderReport(current);
  else renderReady();

  function renderReady(error?: string): void {
    const children: HTMLElement[] = [localSummary()];
    if (error) {
      const isUnconfigured = /unconfigured|no active ai provider|no api key|not configured/i.test(error);
      children.push(
        h(
          "div",
          { class: "notice danger node-description-error" },
          h("p", {}, error),
          isUnconfigured && ctx.host.kind === "vscode"
            ? h(
                "button",
                {
                  class: "primary node-description-config-btn",
                  onclick: () => void openAiSettingsDialog(ctx.host),
                },
                "✨ Configure AI Provider",
              )
            : null,
        ),
      );
    }

    if (ctx.host.kind !== "vscode") {
      children.push(h("p", { class: "muted small" }, "AI file descriptions are available in the VS Code extension."));
      container.replaceChildren(...children);
      return;
    }

    children.push(
      h(
        "button",
        {
          class: "primary node-describe-btn",
          title: "Inspect this file and generate a source-grounded explanation",
          onclick: () => void startDescription(false),
        },
        "✨ Check & Describe",
      ),
      h(
        "p",
        { class: "muted small node-description-disclosure" },
        node.secretHints > 0
          ? "Secret-looking values will be removed before the sanitized source is sent to your active AI provider."
          : "The sanitized source is sent to your active AI provider only when you choose this action.",
      ),
    );
    container.replaceChildren(...children);
  }

  async function startDescription(forceRefresh: boolean): Promise<void> {
    container.replaceChildren(
      localSummary(),
      h(
        "div",
        { class: "node-description-loading", role: "status" },
        h("span", { class: "node-description-spinner", "aria-hidden": "true" }, "✨"),
        h("span", {}, "Checking the selected file and preparing its description…"),
      ),
    );

    try {
      const report = await ctx.host.describeNode({ nodeId: node.id, forceRefresh });
      if (report.nodeHash !== node.hash) {
        renderReady("The file changed while it was being described. Run the check again.");
        return;
      }
      descriptionCache.set(node.id, report);
      renderReport(report);
    } catch (error) {
      renderReady((error as Error)?.message || "Could not describe this file.");
    }
  }

  function renderReport(report: NodeDescriptionReport): void {
    const actions = h(
      "div",
      { class: "node-description-actions" },
      h(
        "button",
        { class: "node-description-refresh-btn", onclick: () => void startDescription(true) },
        "↻ Check again",
      ),
      h(
        "button",
        {
          class: "node-description-clear-btn",
          onclick: () => {
            descriptionCache.delete(node.id);
            renderReady();
          },
        },
        "Clear",
      ),
    );
    const provider = `${getProviderDisplayName(report.provider)} · ${report.model}`;
    const details = h("div", { class: "node-description-report" });
    details.append(
      h(
        "div",
        { class: "node-description-report-head" },
        h("span", { class: "chip success" }, `${report.confidence} confidence`),
        h("span", { class: "muted small" }, provider),
      ),
      h("p", { class: "node-description-summary" }, report.summary),
      descriptionBlock("Purpose", h("p", {}, report.purpose)),
    );
    if (report.responsibilities.length) {
      details.append(descriptionBlock("Responsibilities", descriptionList(report.responsibilities)));
    }
    if (report.keySymbols.length) {
      details.append(
        descriptionBlock(
          "Key symbols",
          h(
            "ul",
            { class: "node-description-list node-description-symbols" },
            ...report.keySymbols.map((symbol) =>
              h(
                "li",
                {},
                symbol.line && ctx.host.openFile
                  ? h(
                      "button",
                      {
                        class: "link",
                        onclick: () => ctx.host.openFile?.(node.id, symbol.line),
                      },
                      `${symbol.name} · ${symbol.kind} · L${symbol.line}`,
                    )
                  : h("strong", {}, `${symbol.name} · ${symbol.kind}`),
                h("span", {}, symbol.description),
              ),
            ),
          ),
        ),
      );
    }
    if (report.dependencies.length) {
      details.append(descriptionBlock("Dependencies", descriptionList(report.dependencies)));
    }
    if (report.dataFlow.length) {
      details.append(descriptionBlock("Data flow", descriptionList(report.dataFlow)));
    }
    if (report.notableDetails.length) {
      details.append(descriptionBlock("Notable details", descriptionList(report.notableDetails)));
    }
    if (report.redactions > 0) {
      details.append(
        h(
          "p",
          { class: "notice warn node-description-redactions" },
          `${report.redactions} secret-looking value${report.redactions === 1 ? " was" : "s were"} excluded before analysis.`,
        ),
      );
    }
    container.replaceChildren(localSummary(), actions, details);
  }
}

function descriptionBlock(title: string, content: HTMLElement): HTMLElement {
  return h("div", { class: "node-description-block" }, h("h4", {}, title), content);
}

function descriptionList(items: string[]): HTMLElement {
  return h(
    "ul",
    { class: "node-description-list" },
    ...items.map((item) => h("li", {}, item)),
  );
}

export function renderThreatsSection(
  container: HTMLElement,
  node: GraphNode,
  ctx: PanelContext,
): void {
  // If the node is sensitive, security analysis is blocked
  if (node.sensitive) {
    container.replaceChildren(
      h("h3", {}, "Security & Threats"),
      h(
        "p",
        { class: "notice warn threat-sensitive-notice" },
        "🔒 Security Analysis unavailable: Sensitive files are protected and never sent to external AI models.",
      ),
    );
    return;
  }

  let activeScanTimers: { stop: () => void } | null = null;

  function stopActiveScanTimers() {
    if (activeScanTimers) {
      activeScanTimers.stop();
      activeScanTimers = null;
    }
  }

  stopActiveScanTimers();

  const cached = threatCache.get(node.id);
  if (cached) {
    renderScanned(cached);
  } else {
    renderUnscanned();
  }

  function renderUnscanned(errorBanner?: HTMLElement) {
    stopActiveScanTimers();
    const children: (HTMLElement | string)[] = [h("h3", {}, "Security & Threats")];
    if (errorBanner) children.push(errorBanner);
    children.push(
      h(
        "button",
        {
          class: "primary threat-scan-btn",
          title: "Audit this file for vulnerabilities, loopholes, and attack vectors",
          onclick: () => void startScan(false),
        },
        "🛡️ Trace Potential Threats",
      ),
      h(
        "p",
        { class: "threat-scan-subtitle muted small" },
        "Audit this file for vulnerabilities, loopholes, and attack vectors",
      ),
    );
    container.replaceChildren(...children);
  }

  function startScan(forceRefresh: boolean) {
    stopActiveScanTimers();

    let providerName = "Active AI Provider";
    let modelName = "";

    const stages = [
      {
        icon: "🔍",
        step: "1/4",
        title: "Scanning AST & scrubbing sensitive secrets…",
        detail: "Verifying local boundaries and redacting tokens/credentials",
        pct: 25,
      },
      {
        icon: "🧩",
        step: "2/4",
        title: "Synthesizing dependencies, env & symbol scope…",
        detail: "Enriching graph context with declared packages, envReads, and symbol scope",
        pct: 50,
      },
      {
        icon: "🤖",
        step: "3/4",
        title: () => `Querying ${providerName}${modelName ? ` (${modelName})` : ""} threat model…`,
        detail: "Executing 'report_security_threats' structured tool call over secure HTTPS",
        pct: 75,
      },
      {
        icon: "🛡️",
        step: "4/4",
        title: "Evaluating threat vectors, CWEs & remediation…",
        detail: "Validating severity rankings, line references, and actionable patches",
        pct: 90,
      },
    ];

    let currentStageIndex = 0;
    const startTime = Date.now();

    const getStageTitle = (stage: (typeof stages)[0]) =>
      typeof stage.title === "function" ? stage.title() : stage.title;

    const stageIconEl = h("span", { class: "threat-stage-icon" }, stages[0].icon);
    const stageTitleEl = h("span", { class: "threat-stage-title" }, getStageTitle(stages[0]));
    const stageBadgeEl = h("span", { class: "threat-stage-badge" }, stages[0].step);
    const stageTimerEl = h("span", { class: "threat-stage-timer" }, "0.0s");
    const stageDetailEl = h("div", { class: "threat-stage-detail" }, stages[0].detail);
    const progressBarFill = h("div", { class: "threat-progress-fill" });
    const setProgressWidth = (pct: number) => {
      try {
        if ((progressBarFill as HTMLElement).style) {
          (progressBarFill as HTMLElement).style.width = `${pct}%`;
        }
      } catch {}
      progressBarFill.setAttribute("style", `width: ${pct}%`);
    };
    setProgressWidth(stages[0].pct);

    const noticeEl = h(
      "div",
      { class: "threat-loading-notice" },
      h(
        "div",
        { class: "threat-stage-head" },
        h("div", { class: "threat-stage-title-wrap" }, stageIconEl, stageTitleEl),
        h("div", { class: "threat-stage-meta" }, stageBadgeEl, stageTimerEl),
      ),
      stageDetailEl,
      h("div", { class: "threat-progress-bar" }, progressBarFill),
    );

    container.replaceChildren(
      h("h3", {}, "Security & Threats"),
      h(
        "div",
        { class: "threat-loading-state" },
        h(
          "button",
          {
            class: "primary threat-scan-btn",
            disabled: true,
            title: "Audit this file for vulnerabilities, loopholes, and attack vectors",
          },
          "🛡️ Trace Potential Threats",
        ),
        noticeEl,
      ),
    );

    const updateStageUI = (index: number) => {
      const stage = stages[index];
      stageIconEl.textContent = stage.icon;
      stageTitleEl.textContent = typeof stage.title === "function" ? stage.title() : stage.title;
      stageBadgeEl.textContent = stage.step;
      stageDetailEl.textContent = stage.detail;
      setProgressWidth(stage.pct);
    };

    const timeouts = [
      setTimeout(() => {
        currentStageIndex = 1;
        updateStageUI(1);
      }, 700),
      setTimeout(() => {
        currentStageIndex = 2;
        updateStageUI(2);
      }, 1600),
      setTimeout(() => {
        currentStageIndex = 3;
        updateStageUI(3);
      }, 3200),
    ];

    const timerInterval = setInterval(() => {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      stageTimerEl.textContent = `${elapsed}s`;
    }, 100);

    activeScanTimers = {
      stop: () => {
        timeouts.forEach((t) => clearTimeout(t));
        clearInterval(timerInterval);
      },
    };

    if (typeof ctx.host.getAiConfig === "function") {
      ctx.host
        .getAiConfig()
        .then((cfg) => {
          if (cfg?.activeProvider) {
            providerName = getProviderDisplayName(cfg.activeProvider);
            const status = cfg.providers?.[cfg.activeProvider];
            if (status?.selectedModel) {
              modelName = status.selectedModel;
            }
            if (currentStageIndex === 2) {
              updateStageUI(2);
            }
          }
        })
        .catch(() => {});
    }

    ctx.host
      .analyzeNodeThreats({
        nodeId: node.id,
        forceRefresh,
      })
      .then((report) => {
        stopActiveScanTimers();
        threatCache.set(node.id, report);
        renderScanned(report);
      })
      .catch((err: any) => {
        stopActiveScanTimers();
        renderError(err);
      });
  }

  function renderError(err: any) {
    const errMsg = err?.message || "Failed to analyze security threats.";
    const isUnconfigured =
      err?.code === "UNCONFIGURED" ||
      /unconfigured|no active ai provider|no api key|not configured/i.test(errMsg);

    const errorBanner = h(
      "div",
      { class: "threat-error-banner notice danger" },
      h("p", { class: "threat-error-text" }, errMsg),
      isUnconfigured
        ? h(
            "button",
            {
              class: "primary threat-config-btn",
              onclick: () => {
                void openAiSettingsDialog(ctx.host, (summary) => {
                  if (summary.activeProvider && summary.providers?.[summary.activeProvider]?.configured) {
                    void startScan(false);
                  }
                });
              },
            },
            "✨ Configure AI Provider",
          )
        : null,
    );

    renderUnscanned(errorBanner);
  }

  function renderScanned(report: NodeThreatReport) {
    const severities: ThreatSeverity[] = ["critical", "high", "medium", "low", "info"];
    const breakdownChips: HTMLElement[] = [];
    for (const sev of severities) {
      const count = report.threats.filter((t) => t.severity.toLowerCase() === sev).length;
      if (count > 0) {
        breakdownChips.push(
          h(
            "span",
            { class: `chip threat-severity-badge ${sev} severity-${sev}` },
            `${count} ${sev}`,
          ),
        );
      }
    }

    const headTitle = h("h3", {}, `Security Threats (${report.threats.length})`);
    const headerEl = h(
      "div",
      { class: "threats-header" },
      headTitle,
      breakdownChips.length > 0 ? h("div", { class: "chips" }, ...breakdownChips) : null,
    );

    const rescanBtn = h(
      "button",
      {
        class: "threat-rescan-btn",
        title: "Re-run threat analysis on this file",
        onclick: () => void startScan(true),
      },
      "🔄 Re-scan",
    );

    const clearBtn = h(
      "button",
      {
        class: "threat-clear-btn",
        title: "Clear threat findings for this file and return to unscanned state",
        onclick: () => {
          threatCache.delete(node.id);
          for (const key of Array.from(patchedThreats)) {
            if (key.startsWith(`${node.id}:`)) {
              patchedThreats.delete(key);
            }
          }
          renderUnscanned();
        },
      },
      "🧹 Clear Threats",
    );

    const actionsRow = h("div", { class: "threat-actions-row" }, rescanBtn, clearBtn);

    if (report.threats.length === 0) {
      const zeroCallout = h(
        "div",
        { class: "threat-summary-callout success" },
        "✓ No security vulnerabilities or loopholes detected in this node.",
      );
      container.replaceChildren(headerEl, actionsRow, zeroCallout);
      return;
    }

    const summaryCallout = h(
      "div",
      { class: "threat-summary-callout" },
      report.summary,
    );

    const listEl = h("div", { class: "threat-cards-list" });
    for (const threat of report.threats) {
      const patchKey = `${node.id}:${threat.id}`;
      const isPatched = patchedThreats.has(patchKey);
      const card = renderThreatCard(
        threat,
        node,
        ctx,
        () => {
          if (patchedThreats.has(patchKey)) {
            patchedThreats.delete(patchKey);
          } else {
            patchedThreats.add(patchKey);
          }
          renderScanned(report);
        },
        isPatched,
      );
      listEl.append(card);
    }

    container.replaceChildren(headerEl, actionsRow, summaryCallout, listEl);
  }
}

function renderThreatCard(
  threat: NodeThreat,
  node: GraphNode,
  ctx: PanelContext,
  onTogglePatch: () => void,
  isPatched: boolean,
): HTMLElement {
  const card = h("div", { class: `threat-card${isPatched ? " patched" : ""}` });

  const sevLower = threat.severity.toLowerCase();
  const metaRow = h(
    "div",
    { class: "threat-card-meta" },
    h(
      "span",
      { class: `threat-severity-badge ${sevLower} severity-${sevLower}` },
      threat.severity.toUpperCase(),
    ),
    h(
      "span",
      { class: "threat-category-chip chip" },
      formatThreatCategory(threat.category),
    ),
  );

  const line = threat.location?.line ?? threat.location?.lineStart;
  if (typeof line === "number") {
    const locBtn = h(
      "button",
      {
        class: "threat-location-link link",
        title: `Open ${node.id} at line ${line}`,
        onclick: (e) => {
          e.stopPropagation();
          ctx.host.openFile?.(node.id, line);
        },
      },
      `Line ${line}`,
    );
    metaRow.append(locBtn);
  }

  if (isPatched) {
    const patchedBadge = h("span", { class: "threat-patched-badge chip success" }, "✓ Patched");
    metaRow.append(patchedBadge);
  }

  const titleEl = h("h4", { class: "threat-title" }, threat.title);
  if (threat.cwe) {
    titleEl.append(h("span", { class: "threat-cwe muted small" }, ` (${threat.cwe})`));
  }

  const descEl = h("p", { class: "threat-description" }, threat.description);

  const remediationBox = h(
    "div",
    { class: "threat-remediation-box" },
    h("strong", {}, "💡 Remediation: "),
    threat.recommendation,
  );

  const patchBtn = h(
    "button",
    {
      class: `threat-patch-btn${isPatched ? " patched" : ""}`,
      onclick: onTogglePatch,
    },
    isPatched ? "Unmark as Patched" : "✓ Mark as Patched",
  );

  const actionsRow = h("div", { class: "threat-card-actions" }, patchBtn);

  card.append(metaRow, titleEl, descEl, remediationBox, actionsRow);
  return card;
}

function formatThreatCategory(category: ThreatCategory | string): string {
  const map: Record<string, string> = {
    injection: "Injection",
    auth: "Auth",
    sensitive_data: "Sensitive Data",
    supply_chain: "Supply Chain",
    crypto: "Crypto",
    misconfiguration: "Misconfiguration",
    denial_of_service: "Denial of Service",
    other: "Other",
  };
  return map[category] ?? (category.charAt(0).toUpperCase() + category.slice(1));
}
