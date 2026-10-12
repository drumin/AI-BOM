# Handoff: cloud session → local Claude

Written 2026-10-01 at the end of the Claude Code (cloud) session that built most of AI-BOM, and updated the same day after a local session on the user's Mac. Read with `CLAUDE.md`.

## Where things stand

Work happens on **`main`**. `features-addition` (formerly `claude/modest-ramanujan-d3i68v`) holds the same history up to the handoff. At handoff both included the user's latest commits (up to `50a99b8`); typecheck was clean and 150 tests passed (17 files). After the local session (`ab5ebc0`) there are 164 tests in 19 files. As of `5238a8a`: 304 unit tests (33 files) and 125 browser tests.

Built and pushed, roughly in order:

1. **Core scanner and dashboard.** Inventory across Claude Code/Desktop, Cursor, VS Code, Windsurf, Zed, Gemini CLI, Codex, Goose and more. Also covers the map, findings with OWASP LLM/Agentic Top 10 mapping, CVE checks (bundled advisories, OSV, NVD), CycloneDX/SARIF/HTML/Markdown reports, and doctor.
2. **Features 1–11.**
   - Fix-it-for-me with snapshots/undo.
   - Watch mode.
   - Pre-flight `check`.
   - Dangerous combinations / blast radius.
   - Trust signals.
   - Session-log usage and per-call audit.
   - Wider inventory: models, keys, apps, browser extensions.
   - Reports.
   - Signed advisory feed.
   - Triage.
   - Plain-language `explain` (opt-in).
3. **Tool behavior and hooks.** Each tool's code is compared with its description (the "weather tool that exfiltrates" case). Hooks are explained in plain words, and telemetry/OTEL export is detected.
4. **Persistence.** Everything lives in `~/.ai-bom`. `ai-bom state [export|import]`, preferences on the server, scan history.
5. **The second feature list** (the user's picks 2, 3, 4, 5, 9, 10, 12, 13):
   - safe add/upgrade (`ai-bom add|upgrade`);
   - activity timeline and incident mode;
   - context cost;
   - sandboxed live inspection;
   - dependency check;
   - menu bar plugin and VS Code/Cursor extension;
   - security score with trend and next best step;
   - Codex/Gemini logs and Windows paths.
6. **Baselines.**
   - MITRE ATLAS techniques on every finding, plus an ATLAS matrix view.
   - NIST AI RMF 1.0 and ISO/IEC 42001 Annex A controls, checked from scan evidence. Controls a scan can't see are answered by the user: `ai-bom baseline …`, the **Baselines** tab, stored in `attestations.json`.
7. **The user's own commits.**
   - `scripts/dummy-real.ts` (`npm run dummy`) plants removable dummy assets in the real home folder.
   - Dashboard accessibility/contrast/responsive fixes (`3716319`): a keyboard-navigable tab bar (now `TabBar.tsx`; the tab list and labels live in `nav.ts`), and the coarse-pointer sizes.
   - `c43dd56` … `50a99b8`:
     - fixes for two failing tests;
     - dialog focus/inert handling and an axe-clean browser test suite (`npm run test:e2e`);
     - CI on Linux and macOS (`.github/workflows/ci.yml`);
     - Baselines improvements: remembered view/filter, per-group progress, fix buttons, re-check after 90 days;
     - findings-over-time chart in History;
     - bulk triage;
     - command palette (Ctrl/Cmd+K);
     - **Safeguards** tab (protections, folder pre-flight, diagnostics);
     - first-run welcome.
   - These were written outside the cloud session; read them before changing those areas.

## Decisions already made

- **MCP gateway** (a proxy enforcing policy on every call): deferred. It would be a separate product, not part of this scanner.
- **Baselines framing.** NIST/ISO are organizational standards. We check what one machine can show and ask the user about the rest. It is never presented as compliance or certification. Control titles are paraphrases; ISO text is copyrighted, so don't paste it.
- **ATLAS mappings** must use IDs from the official ATLAS data. To regenerate `src/frameworks/atlas-data.ts`, download `dist/v6/ATLAS-<version>.yaml` from github.com/mitre-atlas/atlas-data and re-run the extraction (tactics via "achieves" relationships, subtechniques via "specializes").
- **Single user, local first.** No accounts, no telemetry, no uploads except explicit opt-ins.

## Verified locally on macOS (2026-10-01)

Everything below was run for real on the user's Mac, with scratch state (`AI_BOM_HOME`, a fake `$HOME`, fake keys) and cleaned up afterwards:

- **Online lookups** (`scan --online`): OSV.dev and NVD both answer. On 3 real MCP packages: 8 known CVEs plus 45 low `VULN-POSSIBLE` findings. That is noisy, so NVD keyword matching may deserve tightening.
- **`sandbox-exec` inspection**: `test/inspect.test.ts` runs (not skipped) and passes on macOS. The profile also blocks network, writes to `~` and reads of `~/Library/Keychains` against the real home.
- **Keychain**: the real `security` store round-trips awkward passwords, the `ai-bom-secrets` launcher works, and `fix` → `undo` restores the file and deletes the item. Cosmetic: undo restores the value but reformats the JSON whitespace, and a project `.mcp.json` secret is filed under `ai-bom/claude-code-<project>/…`.
- **Menu bar plugin**: install, run and uninstall work against a fake xbar folder (`HOME` override); the output format is right. Not seen rendering, because SwiftBar/xbar are not installed.
- **launchd watch service**: `watch --install` loads, runs once (exit 0), logs, and `--uninstall` removes it.
- **VS Code extension**: built, and activated in the real VS Code through `--extensionDevelopmentPath` plus an `--extensionTestsPath` runner (use short `--user-data-dir` paths; macOS socket paths are limited to about 103 characters). It registered all 3 commands and showed correct diagnostics on the right lines. Cursor is untested.

Still not verified:

- Windows: covered with a synthetic home only.
- The extension: `aiBom.command` is split on spaces (a path with a space breaks), and its fix command runs `ai-bom fix <id>` without the workspace folder.
- The newly added agent clients (below) follow vendor docs; none of those tools are installed on the user's Mac, so no real-install check yet.

## Claude Desktop and other agents (added 2026-10-01)

- **Claude Desktop account skills and plugins** (`src/scanners/claude-desktop.ts`): reads `local-agent-mode-sessions/skills-plugin/<account>/<org>/{manifest.json,skills/}` and `local-agent-mode-sessions/<account>/<org>/rpm/` (plugins). Skills merge with Claude Code's `~/.claude/skills/synced/…` copy (one asset, two occurrences); Desktop-only built-ins such as `schedule` and `setup-claude` are new. The manifest gives who made each skill (`creatorType` user/anthropic) and the enabled flag. A skills folder the manifest does not list is still shown, with a note.
- **Connectors cannot be read from Desktop.** Desktop's `claude_desktop_config.json` has no `mcpServers` here, and the claude.ai connector list is fetched from the server and not stored locally (the claude.ai web cache in `IndexedDB` is partial and may hold conversation data; do not mine it). The only complete source is the claude.ai API with the OAuth token in Desktop's `config.json`. That would be credential use, so it needs an explicit opt-in design. Today's connector sources are Claude Code's `claudeAiMcpEverConnected` and `mcp-needs-auth-cache.json`, plus the manual `ai-bom connectors add`.
- **New or extended clients** (paths from vendor docs): GitHub Copilot CLI (`~/.copilot/mcp-config.json`, `.github/mcp.json`; the shared project `.mcp.json` stays under Claude Code on purpose), Gemini CLI skills (`~/.gemini/skills`, `.gemini/skills`), Windsurf also at `~/.config/devin/mcp_config.json`, and opencode's plural `agents/ commands/ skills/ plugins/` folders in `~/.config/opencode` and `.opencode/` (plugin code files are listed as plugins).
- **Added 2026-10-02 (from current vendor docs, not real installs)**: Amp (`amp.mcpServers` is a literal dotted key, so it has its own reader), Factory Droid (`.factory/`), Qwen Code (`.qwen/`, `QWEN.md`), JetBrains Junie (`.junie/mcp/mcp.json`, `.junie/AGENTS.md`), Augment/Auggie (`~/.augment/settings.json`, rules), Trae (project `.trae/` only), and Aider (no MCP; plaintext keys in `.aider.conf.yml` become key assets, `read:` files are checked as instructions). Windsurf now also reads the Devin-era `.devin/{rules,workflows,skills,hooks.json}` and `~/.codeium/windsurf/{skills,hooks.json}`; Codex reads `hooks.json`; Copilot CLI reads `~/.copilot/skills`.
- **Still unconfirmed or skipped**: Kiro hooks (`.kiro/hooks/*.json`) and skills, Qwen extensions, Factory hooks and plugins, Codex inline `[hooks]` tables in `config.toml`, Trae user-level MCP (not a plain file), Amp user skills location, and Windows paths for the new clients. Skills/hooks/plugin locations for Cursor, Codex and Copilot CLI are now confirmed from docs except where listed. ChatGPT desktop shows up only as an installed app (its connectors are probably account-side), and Ollama has no MCP config (check whether an exposed `OLLAMA_HOST` is flagged).

## Skill checks and rough edges (added 2026-10-02)

- **`ai-bom check` takes more than a repo**: a skill folder (SKILL.md at its root), a single SKILL.md, a `.zip`/`.skill` download, or a repo that keeps skills outside the usual folders (`src/preflight.ts`, `extraSkillDirs` in `scan.ts`, `addSkillFolder` in `scanners/common.ts`). Symlinks are never followed. `extractZip` (`pkgfetch.ts`) counts bytes actually written, because a zip header's sizes are only claims (a test builds a bomb to prove it).
- **`CONTENT-NOT-INSPECTED`**: a file over 1 MB, or a skill with more than `SKILL_FILE_CAP` (200) files, is reported instead of silently skipped, and `check` says "review", never "safe", while anything is unread. It maps to no ATLAS technique on purpose (a coverage gap, not an attack).
- **`CONTENT-PERSISTENCE`** (`src/checks/persistence.ts`, ATLAS AML.T0081): writes to shell startup files, SSH keys, cron, launchd, systemd, git hooks and AI tool settings, in scripts and fenced code blocks only (prose is masked). Shell profiles and `.mcp.json` are medium (setup skills do this legitimately); the rest are high.
- **Undo is byte-exact** when the file is unchanged since the fix: the snapshot keeps only the changed region (`splices`), with Keychain secrets replaced by a placeholder. Otherwise it falls back to value-level undo.
- **`VULN-POSSIBLE`** needs the contiguous product phrase and is dropped when NVD ties the CVE to another product; several unconfirmed matches collapse into one finding per package.
- **Dashboard**: the Findings card's total, severity counts, "N muted by you" and the score all open the Findings tab (one-shot severity filter).

Verified against a recorded SkillSpector report (Apache-2.0; ideas only, no code copied). Built since (each has its own test file and was checked against the user's real home for false positives):

- **Settings** (`SETTINGS-ENV-INJECTION`, `SETTINGS-TRAFFIC-INTERCEPT`, `PERM-BROAD-DIRS` in `checks/index.ts`): `LD_PRELOAD`/`DYLD_*`/`BASH_ENV`/`PYTHONSTARTUP`, `NODE_OPTIONS` that loads code, remote proxies, certificate checks off or extra CAs, and `additionalDirectories` covering home, `/` or credential folders. `disableAllHooks` was left out: how it combines across scopes is unclear.
- **Hidden instructions** (`CONTENT-HIDDEN-INSTRUCTION`, `checks/hidden.ts`): directives in HTML comments, letter-spaced text, base64 that decodes to commands, and safety-off phrases addressed to the model. The bare word "jailbreak" is deliberately not flagged (it hit a real security skill).
- **Look-alike names** (`TRUST-TYPOSQUAT-SKILL`, `SKILL-DEP-TYPOSQUAT`, `SKILL-DEP-UNPINNED`, `checks/skillsupply.ts`): one slip from a well-known skill/plugin/package name (neighbouring-letter swaps count as one). Two slips on long names was tried and dropped: it matched three unrelated real skills. The known-name lists are short on purpose; extend them with names you are sure of.
- **Concealed binaries** (`SKILL-BINARY`, `checks/binaries.ts`): ELF/Mach-O/PE/WebAssembly, `.pyc`/`.class`, macro Office files, recognised by first bytes; a program with a harmless name is high. It looks inside `__pycache__`, which `walkFiles` skips. Only exercised on synthetic files; the user's real skills ship none.

Still to do from it: registry redirection (`.npmrc registry=`, `pip --index-url`, `NPM_CONFIG_REGISTRY`), skill-script code checks (dynamic `exec`/`eval`, `pickle.load`, whole-environment copies), and an optional LLM `--review` pass that may only annotate findings. New ATLAS IDs must be checked against the official data first. A known unrelated issue: the Map tab has colour-contrast failures (`.view-switch > .meta`, `.count-pill`) that no e2e audit covers.

## Dashboard UI rework (added 2026-10-03)

Desktop only. Mobile was dropped from the brief, but the e2e suite still checks 320px for horizontal scroll, so keep that passing. Design reviews used the `better-*` skills; the design-system pass is `262d538`, the UI rework is `5238a8a`.

- **Navigation lives in the URL** (`web/src/nav.ts`, `navigate()` in `App.tsx`). `#<tab>` plus optional `?a=<asset id>&k=<kind,kind>`. Opening a view or an asset pushes a history entry; filters replace the current one; `popstate` restores everything. `history.state.trail` is the chain of assets opened by following links inside the pane (it drives the pane's **Back to …** button). `siblings` (in memory, not the URL) is the list an asset was opened from, for ‹ › and the `[` / `]` keys.
- **Details pane replaces the drawer** (`components/AssetPane.tsx`, was `AssetDrawer.tsx`). Non-modal `<aside>` beside the page (sticky, `--pane-w`), floating over the page below 1100px. Sections: Overview, Findings, Details, Where (jump chips with scroll-spy). Focus moves to the title on open and returns to the opener on close; Escape works from inside the pane. Sheets (fix, explain, add…) still make the whole `.workspace` inert.
- **Tabs** (`components/TabBar.tsx`): every tab shows while it fits; the rest move into a **More** menu only when the bar is too narrow, and the open view always stays in the row. Widths come from a hidden copy (`.tabs-measure`, width 0). The bar is sticky under the top bar.
- **Findings are grouped by cause** (`FindingsList.tsx`): key = rule + advisory + title minus its "(used by …)" suffix. One row per issue with a count, collapsed by default; the group checkbox selects all its findings, so bulk triage still works per finding. A single-finding group shows its fix button inline.
- **Dashboard top** (`Summary.tsx`): score ring, findings card, "Fix these first" (top 3 of `score.next`), and a compact stat strip with a tint on categories holding critical or high findings. `.summary` is a container, so the layout reflows when the pane narrows the page.
- **Filters** (`FilterMenu.tsx`): Inventory type / AI tool / sort are popovers with counts (type and tool take several choices). The Name column shrinks with an ellipsis and Changed / Scope drop out (container queries on `.table-wrap`) so Risk stays in view beside the pane.
- **Maps**: connectors that end at critical or high assets are drawn warm, those cards get a soft ring, a caption says what is highlighted, column titles stay pinned, and the open asset is marked. `.flow { overflow: clip }` (not `hidden`) so the sticky titles work.
- **Tokens**: colors are declared once with `light-dark()`; the theme switch only sets `color-scheme` (`system`, or `data-theme`). `--control-border` (3:1) is for controls, `--axis` for meaningful lines. Type sizes are `--text-xs … --text-xl`; curves are `--ease`, `--ease-out`, `--ease-sheet`; press scale is `--press` / `--press-lg`.

Gotchas found the hard way: several short class names are global (`.ring`, `.more`) and silently collide with older rules, so prefix new ones. The e2e tests open findings groups with `showFindings()` and tick groups with `pickGroups()`; the inert container is `.workspace`, not `main`.

Known and left alone: dimmed map cards (`.ccard.faded`, opacity 0.42) fail color contrast while another card is hovered; toasts still use keyframes; `.expander` and `.finding-wrap` animate `grid-template-rows`. Not checked: motion at 10% speed, 200% zoom, the sticky map titles while scrolled, RTL.

## Open items and ideas

- The user asked "I do not see any Governance tab?". The tab is called **Baselines** (between Findings and Activity). Offer to rename it to "Governance" if they prefer.
- The user's Mac had uncommitted edits that blocked a `git pull` (advised: `git stash`, pull, `git stash pop`). Their later pushes suggest it was resolved. If `git stash list` still shows an entry, check with the user before dropping it.
- Possible next steps, none requested yet:
  - the not-yet-covered agents and the unconfirmed skills/hooks paths above;
  - tighten `VULN-POSSIBLE` noise from NVD keyword matches;
  - a baselines section in the HTML/Markdown reports;
  - an ATLAS Navigator layer export;
  - the NIST AI 600-1 (GenAI profile) mapping.

## Quick verification after pulling

```bash
git log --oneline -5           # should include "Read Claude Desktop account skills/plugins; fill agent config gaps"
npm install && npm run typecheck && npm test && npm run build
npm start                      # dashboard; check the Baselines tab
npx tsx src/cli.ts baseline    # same in the terminal
```
