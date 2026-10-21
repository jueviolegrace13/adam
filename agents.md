# Agent guidance

## Project overview

Adam is a TypeScript monorepo for a codebase network viewer. The main packages are:

- `packages/core`: repository indexing, parsing, graph construction, and secret masking.
- `packages/service`: local HTTP service that owns an index and serves the UI.
- `packages/ui`: browser and VS Code webview network view.
- `packages/vscode`: VS Code extension integration and packaging.

Read `README.md` and the relevant sections of `docs/architecture.md` before making changes that
cross package boundaries.

## Development workflow

- Requirements: Node.js `>=22.12`.
- Install dependencies with `npm install`.
- Run the full validation suite with `npm run check` (typecheck, tests, and build).
- Run tests with `npm test`; use Vitest filters when iterating on one area.
- Build artifacts with `npm run build`.
- Use `npm run serve` to inspect the standalone service locally.
- Keep changes focused and update tests or documentation when behavior changes.

## Code conventions

- Follow the existing TypeScript style and package boundaries.
- Prefer small, composable functions and explicit types over broad casts.
- Keep UI code independent of VS Code-specific APIs; use the existing host abstraction.
- Preserve deterministic indexing and layout behavior so tests and cached results remain stable.
- Add or update tests beside the affected package in its `test/` directory.

## Security requirements

- Never expose secret values through the index, service API, UI, logs, or tests.
- Preserve masking and redaction behavior for `.env*`, settings files, credentials, certificates,
  tokens, connection strings, and other sensitive content.
- Do not weaken service token, Host, Origin, or indexed-file checks without an explicit design
  change and corresponding tests.
- Treat `.adam/` cache contents as sensitive; do not add raw file contents or secret hashes.

## Verification

Before handing off a change, run the narrowest relevant tests and then `npm run check` when
practical. For UI or extension changes, also follow the local testing instructions in
`docs/testing-locally.md` and verify the affected flow manually.
