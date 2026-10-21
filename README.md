# Adam

Adam shows a codebase as a live **network of nodes** instead of a folder tree. Every file is a
node, every import is an edge, and clicking a node opens a panel with its functions collapsed until
you need them. Later phases add an agent that proposes changes with its reasoning (never writing
without your accept), an onboarding report, an API explorer and security overlays.

![Excalidraw's 1,318 files as a network, opened as one node per package](docs/images/network-excalidraw.png)

This repository holds the MVP: a **VS Code extension** backed by a separate **local service**, so
the same core can later ship as a standalone desktop app.

## Status

Phase 0 slice, working end to end:

- Index a TypeScript or JavaScript repo: every file is a node; imports, re-exports, `import()` and
  `require` are edges, resolved through `tsconfig`/`jsconfig` paths and across monorepo packages.
- Network view (Sigma.js, WebGL) coloured by module, with search, filters and a folder view.
  Big repos open as collapsible clusters, and a focused node keeps its links on screen while you
  click around its neighbours.
- Node panel with symbols collapsed by default; open one to read only its code, or jump to the
  editor to change it by hand.
- VS Code AI tools with bring-your-own provider keys: check and describe a selected file, or scan
  it for structured security findings. Sensitive files are excluded, and secret-looking values in
  ordinary source files are redacted before any provider request.
- C# and .NET: classes, records, interfaces, methods and properties as symbols; edges from the
  types each file uses (through namespaces, usings, aliases and project references), extension
  method calls and partial types; `.sln`/`.slnx` → project and `<ProjectReference>` edges;
  NuGet packages on project nodes. dotnet/eShop (547 C# files) indexes in about 1.6 s cold and
  0.4 s warm.
- Sensitive nodes masked (`.env` and `appsettings*.json` show keys, never values) and
  secret-looking values redacted, including ADO.NET connection string passwords.
- Incremental cache in `.adam/`: Excalidraw (1,318 files) indexes in about 1.8 s cold and 0.2 s
  warm.

![Node panel with collapsed symbols](docs/images/node-panel.png)

![A C# node from dotnet/eShop with its type references](docs/images/csharp-node-panel.png)

## Try it

Requires Node 22.12 or newer to build. The packaged extension runs on VS Code 1.90 or newer.

```sh
npm install
npm run check                 # typecheck + tests + bundles

# Standalone: index a folder and open the printed URL in a browser
node packages/service/dist/main.js --root /path/to/repo

# VS Code: build the .vsix and install it
npm run package
code --install-extension packages/vscode/adam-0.1.0.vsix
```

Then run **Adam: Open Network View** from the command palette. Step-by-step instructions, including
running the extension with F5, are in [docs/testing-locally.md](docs/testing-locally.md).

## Layout

| Package | What it is |
| --- | --- |
| `packages/core` | Indexer and masking rules. No UI, no VS Code |
| `packages/service` | Local service: owns the index, serves the API and web UI on `127.0.0.1` |
| `packages/ui` | The network view, for a VS Code webview or a browser |
| `packages/vscode` | The extension and its marketplace listing |

See [docs/architecture.md](docs/architecture.md) for the design and
[docs/publishing.md](docs/publishing.md) for releasing to the VS Code Marketplace and Open VSX.

## License

Proprietary, all rights reserved. See [LICENSE.md](LICENSE.md).
