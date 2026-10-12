# AI-BOM: notes for Claude

Local-first TypeScript CLI + React dashboard that inventories the AI assets on one person's machine (MCP servers, skills, plugins, hooks, connectors, models, API keys, apps) and checks them for security issues. Audience: individual users ("enterprise grade, not built for enterprises"). Read `docs/HANDOFF.md` for the current state and open work.

## Commands

```bash
npm install
npm test              # vitest: unit tests + full scans of a synthetic home (test/fixture.ts)
npm run test:e2e      # dashboard browser tests (Playwright; `npm run e2e:install` once)
npm run typecheck     # root + web
npm run build         # dist/cli.js and dist/web (the dashboard serves dist/web; rebuild after UI changes)
npm run demo          # dashboard on http://127.0.0.1:7655 against the fixture (state in ~/.ai-bom/demo, --reset)
npm run dummy         # plant removable dummy assets in the REAL home dir; `npm run dummy -- remove` undoes
npm start             # node dist/cli.js (scan + dashboard)
npx tsx src/cli.ts <command>   # run the CLI from source
```

Run typecheck, tests and build before every commit (CI runs the same on Linux and macOS). For UI changes, also look at the demo in light, dark and phone widths.

## Rules

- **Local first.** Nothing leaves the machine except explicit opt-ins: `--online` sends package names/versions only; `explain` sends one item's redacted text to the Claude API (or Ollama locally).
- **Never print secret values.** Redact with `src/util/secrets.ts`; findings keep short redacted evidence only.
- **Every change to user config is reversible.** Go through `applyChanges` in `src/fix/` (snapshot + undo); JSONC edits via `jsonc-parser` (`src/fix/jsonedit.ts`).
- **State lives in `dataDir()`** (`$AI_BOM_HOME` or `~/.ai-bom`), owner-only permissions. Portable state (triage, connectors, preferences, attestations) is in `ai-bom state export`.
- **Don't start untrusted servers** except through `src/inspect.ts` (sandbox, no network, empty home, user consent).
- **Honest output.** Framework mappings (OWASP, MITRE ATLAS, NIST AI RMF, ISO 42001) must stay accurate; ATLAS IDs come from the official data (`src/frameworks/atlas-data.ts` is generated from MITRE's `dist/v6/ATLAS-<version>.yaml`; a test checks every mapping exists). Baselines are a self-assessment, never "compliant".
- **UI:** Apple-style restraint (`anthropic-skills:apple-design`); charts follow the dataviz skill (single series = no legend, 2px line, hover tooltip). Colors only via CSS tokens in `web/src/styles.css`, with light + dark + reduced-motion + phone layouts.
- Plain-language copy for non-experts; no jargon without explanation.
- Commit messages: imperative summary + bullet body. Work on `main` unless told otherwise (CI runs on every push to `main`); `features-addition` keeps the history of the initial build-out. Don't open PRs unless asked.

## Layout

```
src/cli.ts, commands.ts     CLI entry and subcommands
src/scan.ts                 scan pipeline (order matters; see comments)
src/scanners/               one module per AI tool (+ wider.ts, shell.ts); Windows paths included
src/checks/index.ts         rules (RULES) + OWASP mapping; findings get ATLAS tags via frameworks/atlas.ts
src/analysis/               tool code vs description, hooks/telemetry, reach & combos, context cost
src/frameworks/             MITRE ATLAS mapping, NIST AI RMF + ISO 42001 baselines
src/agentlogs.ts            Claude Code / Codex / Gemini CLI session logs → normalized calls
src/sessions.ts, activity.ts, incident.ts   usage audit, timeline, incident mode
src/add.ts, vet.ts, pkgfetch.ts, deps.ts, inspect.ts   safe add/upgrade, dependencies, sandbox
src/fix/, triage.ts, state.ts, score.ts     fixes+undo, muting, persistence, security score
src/server/                 local dashboard server (mutations require X-AI-BOM: 1 header)
web/src/                    React 19 dashboard (App.tsx, components/, styles.css)
extensions/vscode/          VS Code / Cursor extension (runs `ai-bom check`)
test/fixture.ts             synthetic macOS home used by tests and the demo
```
