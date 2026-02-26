# AGENTS.md

## Project Overview
- `claw-guardrails` is an OpenClaw plugin that enforces multi-layer permission checks before potentially destructive actions.
- Stack: TypeScript (ESM), Node.js, `@sinclair/typebox`, `minimatch`, `date-fns`.
- Architecture: tool wrappers (`safe_exec`, `safe_send`, `safe_action`) -> permission resolver -> approval queue -> runtime execution + audit logging.
- Registered surfaces: `safe_exec`, `safe_send`, `safe_action`, `/perms`, `/approve`, `/deny`, `guardrails.*` RPC, `guardrails` service/CLI.

## Dev Environment Tips
- Node.js 20+ recommended.
- Install deps: `npm install`.
- Project root contains `openclaw.plugin.json`, `index.ts`, and `src/` modules.
- OpenClaw loads this plugin via `openclaw.extensions` from `package.json`.
- Plugin config is validated from inline `configSchema` in `openclaw.plugin.json`.

## Build & Run Commands
- Type-check build: `npm run build`
- Check alias: `npm run check`
- No bundler is required; OpenClaw executes plugin source module directly.
- Runtime CLI surface: `openclaw guardrails status|audit|policy`

## Testing Instructions
- Current baseline validation: TypeScript checks via `npm run check`.
- For manual functional checks, verify:
  - `safe_exec` allows low-risk commands and blocks denylisted commands.
  - medium/high risk actions produce approval entries.
  - `/approve` and `/deny` resolve pending requests.
  - `guardrails.approve` / `guardrails.deny` RPC resolves the same queue entries.
  - `openclaw guardrails status` reflects queue counters.
  - audit log file receives JSONL decision entries.
- If CI is added later, keep workflows in `.github/workflows`.

## Code Style Guidelines
- TypeScript strict mode; keep exported interfaces in `src/types.ts`.
- Naming: `camelCase` vars/functions, `PascalCase` types/classes, `kebab-case` filenames.
- Keep engine stages isolated by file (`context-matcher`, `tool-checker`, `resource-checker`, `policy-engine`, `resolver`).
- Prefer pure functions for matching/classification and explicit return objects for decisions.
- Keep imports grouped: node built-ins -> third-party -> local modules.

## Git & PR Instructions
- Branch naming suggestion: `feature/guardrails-<scope>` or `fix/guardrails-<scope>`.
- Commit style suggestion: imperative mood (`add approval queue persistence`).
- Before PR: run `npm run check` and validate at least one approval flow manually.
- PR description should include changed guardrail policies and risk implications.

## Security & Best Practices
- Default-deny policy unless explicitly allowed.
- Never bypass permission resolver for runtime actions.
- Treat inbound content/tool arguments as untrusted input.
- Keep sensitive paths denied by default (`~/.ssh/**`, credentials, system dirs).
- Record every decision (allow/deny/require_approval) with reason and source stage.
