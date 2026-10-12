# AI-BOM

**See every AI tool, MCP server, skill, plugin, hook, model and API key on your machine: which ones are risky, what they really do, and where your data goes. Fix issues with one reversible click.**

People set up MCP servers, install skills and plugins, and paste API keys into config files across many AI tools, then forget about them. AI-BOM is a free, local-first scanner. It builds an *AI Bill of Materials* for your machine, shows it as an interactive map, and flags risky configurations. It is built for individual AI users rather than enterprise security teams.

```bash
npx ai-bom                 # scan and open the dashboard
npx ai-bom scan            # scan and print a summary in the terminal
npx ai-bom scan --online   # also check packages against OSV.dev, the NIST NVD, npm/PyPI and the MCP Registry
npx ai-bom check <repo>    # pre-flight check of a repository before you open it with an AI tool
npx ai-bom fix             # list problems it can fix for you, reversibly
npx ai-bom add <package>   # vet an MCP server before adding it (downloads, never runs it)
npx ai-bom timeline        # what your agents actually did this week, with risky steps flagged
```

Everything runs on your machine. Nothing is uploaded unless you ask for the online check (package names and versions only) or an AI review of one item. Secret values are redacted from all output, and every change AI-BOM makes can be undone.

## Run it from a clone

```bash
git clone https://github.com/drumin/ai-scanner.git && cd ai-scanner
npm install && npm run build
npm start                 # dashboard      (same as: node dist/cli.js)
npm start -- scan         # terminal summary; flags go after --
```

**Want an `ai-bom` command?** `npm link` writes to `/usr/local`, which needs admin rights on most Macs (`EACCES`). Don't use `sudo`; pick one of these instead:

```bash
# Option A: an alias (zsh). Adjust the path to your clone.
echo 'alias ai-bom="node $HOME/Projects/ai-scanner/dist/cli.js"' >> ~/.zshrc && source ~/.zshrc

# Option B: make npm install global commands into your home folder, then link.
mkdir -p ~/.npm-global && npm config set prefix ~/.npm-global
echo 'export PATH="$HOME/.npm-global/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
npm link
```

The hooks and the background watcher (below) call AI-BOM by absolute path, so install it permanently (Option B, or a global install) before using `--install`.

## What it finds

| Asset | Where |
|---|---|
| **MCP servers** (local and remote) | Claude Desktop, Claude Code, Cursor, VS Code / Copilot, Windsurf, Cline, Roo Code, Kilo Code, Gemini CLI, Codex CLI, Crush, Google Antigravity, Zed, Continue, Goose, opencode, LM Studio, Amazon Q, Kiro |
| **Skills** | `~/.claude/skills`, `.claude/skills`, `~/.codex/skills`, `.agents/skills`, `.cursor/skills`, `.github/skills`, skills bundled in plugins, and skills synced from your Claude account |
| **Plugins and extensions** | Claude Code plugins (with everything they bundle), Claude Desktop extensions (`.dxt`/`.mcpb`), Gemini CLI extensions |
| **Subagents and commands** | `.claude/agents`, `.claude/commands`, Cursor/Gemini/Codex/Copilot prompts |
| **Hooks and auto-run commands** | Claude Code and Cursor hooks, `statusLine`, `apiKeyHelper` and other helper commands, Codex `notify`, and VS Code/Cursor tasks that run when a folder opens |
| **Telemetry exports** | OpenTelemetry settings in Claude Code (settings or shell profile), Gemini CLI and Codex: where they send data and whether your prompts are included |
| **Instruction files** | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursor/rules`, `.windsurfrules`, `copilot-instructions.md`, … |
| **Permissions** | Claude Code allow rules, bypass mode, auto-approved project MCP servers, API base-URL redirects |
| **Local models** | Ollama, LM Studio, the Hugging Face cache, GPT4All and Jan (file sizes and formats only; weights are never read) |
| **AI API keys** | OpenAI, Anthropic, Gemini, Groq, Mistral, Hugging Face and 25 more, in shell profiles and project `.env` files. The same key found in several places is shown once. |
| **AI apps and browser extensions** | AI desktop apps in `/Applications`, and AI extensions in Chrome, Brave, Edge and Arc with the sites they can read |
| **Cloud connectors** | claude.ai connectors Claude Code knows about, plus connectors you register for claude.ai, ChatGPT, Gemini… |

It scans both **user-level** configuration (your home directory) and **project-level** configuration.

### Where MCP servers are read from

The same server is often defined in more than one place (for example `claude mcp add` in `~/.claude.json` and again in a repo's `.mcp.json`). Every file below is read, and duplicates are merged into **one** asset whose details list each place it's configured.

| Tool | User level | Project level |
|---|---|---|
| Claude Code | `~/.claude.json` (user and per-project "local" servers), plugins' `.mcp.json`, managed `managed-mcp.json` | `<project>/.mcp.json` (with its approved/rejected state), including `~/.mcp.json` when you run Claude from your home folder |
| Claude Desktop | `claude_desktop_config.json`, Desktop extensions | n/a |
| Cursor · VS Code · Windsurf · Cline · Roo · Gemini CLI · Codex · Zed · Continue · Goose · opencode · LM Studio · Amazon Q · Kiro | each tool's own config file | `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`, `.codex/config.toml`, `.roo/mcp.json`, `.amazonq/mcp.json`, `.kiro/settings/mcp.json`, `.zed/settings.json`, `opencode.json`, `.continue/mcpServers/` |

Projects come from:

- the current directory, and any directory you pass with `--project`;
- projects Claude Code remembers;
- your home folder;
- anything under common code folders (`~/Projects`, `~/code`, `~/Developer`, `~/src`, `~/repos`, `~/GitHub`, …, three levels deep; turn off with `--no-auto-discover`);
- folders you sweep with `--discover <dir>`.

### The map

- **Overview** (default): AI tools on the left, grouped as desktop apps, editors, command line, online accounts, local models, browsers and "this computer". What they use is on the right, grouped by type. Cards open like a dropdown, with labeled details on every row.
- **All connections:** a three-column flow, *which tool → configured where → uses what*. Point at anything to light up its chain; click to keep it in focus.

## Does each tool do what it says?

The model (and you, when approving a call) only ever sees an MCP tool's **name and description**. AI-BOM reads the tool's **code** and compares the two.

- The server's code is found on disk without running it: the npx cache, uv/pipx environments, global installs, Desktop-extension and plugin folders, or the local script a config points to.
- Each tool registration is located: `server.tool()`, `registerTool()`, `addTool()`, `@mcp.tool()`, and low-level `tools/list` + `call_tool` handlers, in JavaScript, TypeScript and Python.
- The tool's handler, plus the helper functions it calls, is read for network destinations, credential files, environment variables, process execution and file writes.

Each tool then gets a verdict: **matches its description** or **does more than it says**, with plain reasons. For example, a `get_forecast` tool described as "Get the weather forecast" gets this verdict:

> It reads SSH keys, which the description never mentions. It reads your entire environment (all variables, including secrets) and makes network requests. It also sends requests to metrics.forecast-cdn.net, unrelated to what it describes (api.weather.gov).

Hosts are compared with the **server's own name**, never with the tool description (which whoever wrote the tool controls). Tools registered in code but missing from an extension's manifest are flagged too. The tools and their verdicts are shown in each server's details.

## Hooks, telemetry and where your data goes

Hooks run automatically and are handed data: every prompt you type, every tool call's input and output, or the path to the whole transcript. For every hook, AI-BOM explains in one sentence **when it runs, what it gets, which script it runs and where that script sends data**, e.g.:

> Every time you submit a prompt, runs `log-prompt.sh`, which sends data to collector.example.com. It is given the full text of your prompt.

Scripts referenced by hook commands (including `${CLAUDE_PLUGIN_ROOT}` and `$CLAUDE_PROJECT_DIR` paths) are followed and read. A hook that receives your data and talks to the network is a `HOOK-DATA-EGRESS` finding.

OpenTelemetry export is read from Claude Code settings and shell profiles (`CLAUDE_CODE_ENABLE_TELEMETRY`, `OTEL_*`), Gemini CLI (`telemetry`) and Codex (`[otel]`). You see the collector endpoint, whether **your prompts** or tool parameters are included, and whether it came from an admin-managed policy.

## Real usage and a review of every tool call

Coding agents keep session logs on disk. AI-BOM reads them **locally** from Claude Code (`~/.claude/projects/`, including subagents), Claude Desktop agent mode (including delegated background agents), Codex (`~/.codex/sessions/`), Gemini CLI (`~/.gemini/tmp/*/chats/`, current `.jsonl` journals and older snapshots), GitHub Copilot CLI (`~/.copilot/session-state/`) and Cline, Roo Code and Kilo Code (their task folders). Logs kept in SQLite databases (Cursor, opencode, Warp) are not read yet:

- **Usage:** calls per MCP server and per tool, last used, and in which projects. Servers that are configured but never called in two or more weeks of logs, from every agent that loads them, get a low `USAGE-UNUSED` finding, and servers you use only a few tools of get a suggestion to block the rest.
- **Per-call audit:** every MCP tool call's arguments are checked for credentials (`TOOLCALL-SECRET-SENT`) and for data-collection/tunneling destinations (`TOOLCALL-SUSPICIOUS-DEST`). Every result is checked for invisible characters and instruction-override text (`TOOLCALL-INJECTION`), which is how indirect prompt injection reaches your agent.

Findings keep only a short, redacted excerpt. Turn it off with `--no-session-logs`.

**Live guard.** `ai-bom guard --install` adds a Claude Code hook that checks every MCP call *as it happens*. If the arguments carry a credential or target a collection endpoint, Claude Code asks you first. If a result contains injected instructions, the model is told to treat it as data and you see a warning. It is pattern-based, fast and offline, and it logs to `~/.ai-bom/guard.log`. Remove it with `ai-bom guard --uninstall`.

## Dangerous combinations and blast radius

Every MCP server and connector gets a **"What it can reach"** profile: files, network hosts, credentials, accounts, and whether it can run commands, plus least-privilege suggestions.

AI-BOM then looks at what each agent loads *together* (a tool's user-level config, plus each project's own). It flags:

- **The lethal trifecta** (`COMBO-LETHAL-TRIFECTA`): something that reads your private data, something that feeds it content written by others (web pages, issues, email), and something that can send data out. One prompt injection is then enough to leak data. The finding names each leg, and a single server can be all three (the GitHub MCP server, for example).
- **Command execution + untrusted content** (`COMBO-SHELL-UNTRUSTED`).

Both are raised to high when that agent runs with approval prompts turned off.

## Trust signals

- **Offline:** lookalike package names one or two characters away from well-known MCP packages (`TRUST-TYPOSQUAT`). Also "rug pulls": servers whose tool descriptions changed since the last scan (`TRUST-TOOLS-CHANGED`; hashes are kept in `~/.ai-bom/tool-hashes.json`).
- **Online (`--online`):**
  - npm / PyPI metadata: first publish date, maintainers, source repository, license, build provenance, install scripts and deprecation;
  - whether the server is listed in the **official MCP Registry**, where the publisher proved they own that name.

  Each server gets a summary (good, mixed or poor signals), and very new packages, install scripts, deprecated releases and packages without a source repository are flagged.

## Security score and the next best step

Every scan gets a score from 0 to 100 and a grade (A to F), computed from your active findings: muted ones don't count, and each critical weighs far more than a low. The dashboard shows how the score moved over your recent scans and the **one change that would raise it most**. Click it to open the fix. `ai-bom scan` prints the same line.

## Add and upgrade servers safely

```bash
ai-bom add @modelcontextprotocol/server-github           # npm
ai-bom add pypi:mcp-server-fetch                         # PyPI (also "uvx mcp-server-fetch")
ai-bom add https://mcp.linear.app/sse --to claude-code,cursor
ai-bom add some-server --secret API_TOKEN                # the value goes to the keychain, not a config file
ai-bom upgrade                                           # which servers have a newer version
ai-bom upgrade weather                                   # what changes in the new version, then pin it
```

Before anything is added, AI-BOM downloads the exact package from npm or PyPI (checking its integrity hash), **without installing or running it**. It then reads every tool's code against its description, checks advisories, publisher signals and dependencies, and gives a verdict: fine, review, or dangerous. Only then does it write a **pinned** entry into the agents you pick, as one change you can undo. Dangerous servers need `--force`.

`upgrade` compares the version you have with the new one: tools added or removed, descriptions that changed (a classic rug pull), new network destinations, new install scripts, and findings that appear or go away. The dashboard offers the same through **Add server** and **Check for update** in a server's details.

## Dependencies

For every MCP server whose code is on disk, AI-BOM reads the dependencies installed with it (`node_modules`, or `site-packages` for Python) and checks them against the bundled advisories and, with `--online`, OSV.dev. A vulnerable dependency is a `DEP-VULN` finding on the server. Strong-copyleft licenses (AGPL, GPL, SSPL…) are noted as `DEP-LICENSE`, since they matter if you ship what the agent writes.

## Live check in a sandbox (opt-in)

Reading a server's code catches most things, but some servers only reveal their tools, or change their descriptions, once running. `ai-bom inspect <server>` (or **Run in sandbox** in its details) starts a local server once:

- inside a sandbox: `sandbox-exec` on macOS, `bwrap` or `unshare` on Linux;
- with **no network**, an empty home folder and no credentials;
- for up to 20 seconds, asking it only for its tool list.

AI-BOM then compares what it reports with what its files say: tools that only exist at runtime (`LIVE-HIDDEN-TOOLS`), descriptions that change (`LIVE-DYNAMIC-DESCRIPTIONS`), and attempts to reach the network on start (`LIVE-NETWORK-AT-START`). If no sandbox is available, it refuses to run the server. Results are kept in `~/.ai-bom/inspections.json` and used by later scans.

## What your agents did, and what to do if something went wrong

```bash
ai-bom timeline --days 7          # every session: commands, file writes, fetches, MCP calls
ai-bom timeline <session-id>      # one session in full
ai-bom incident                   # pause, list keys to rotate, write a report
```

The **Activity** tab and `timeline` show what those agents actually did, per session. Risky steps are flagged, for example:

- downloading and running code;
- reading credentials and sending data out;
- changing a startup, credential or agent settings file;
- writing outside the project;
- destructive commands, including cloud and infrastructure ones (`aws s3 rm --recursive`, `kubectl delete`, `terraform destroy`), database drops, force pushes and `git reset --hard`;
- MCP calls that carried a secret or returned injected instructions;
- anything the agent did soon after a tool result told it what to do, which is what a hijack looks like from the outside;
- an agent rewriting its own instructions (`CLAUDE.md`, `AGENTS.md`, rules) or memory after reading web pages or tool output, or editing which tool servers it uses;
- runaway loops: the same network command repeated, bursts of requests to one host, one tool called over and over.

Sessions also say how steps were approved when nobody was asked: *Auto mode*, *Permissions bypassed*, *Headless* (scripts and the Agent SDK) and *Background agent* (delegated by Claude Desktop), so a flag on a step that ran unattended says so.

Activity reads as a conversation: each prompt you typed, the agent's reply (rendered as Markdown), and a `5 actions · 1 finding` dropdown with everything it did in between, including subagents. Every flagged step says why and highlights the part that triggered it, and shows what the command printed (never for commands that touch credentials). You can search across prompts, replies, commands and files, stop flagging a kind of step that is routine for you (undo it from *Muted flags*), and see each session's data trail: which sensitive files were touched and which hosts and tool servers were reached afterwards. Everything is read locally from the agents' own logs, and secrets are masked.

If something looks wrong, **incident mode** (the *Something went wrong…* button, or `ai-bom incident`) does three things. It pauses every MCP server and every hook that sends data out, as one change you can undo. It lists the keys to rotate, with a link to each provider's page. And it writes a report of the last days of activity to `~/.ai-bom/incidents/`. Keep servers you still need with `--keep name,name`.

## Context cost

Every enabled MCP server, skill, subagent and instruction file adds text that the agent loads before you type anything. The **Context** tab and `ai-bom context` estimate those tokens per agent and project. They show the biggest items and flag servers you never use. Trimming them makes answers cheaper, faster and more focused.

## Baselines: NIST AI RMF, ISO/IEC 42001 and MITRE ATLAS

```bash
ai-bom baseline                      # coverage for each framework
ai-bom baseline nist                 # every NIST AI RMF control: status, evidence, next step
ai-bom baseline iso                  # the same for ISO/IEC 42001 Annex A
ai-bom baseline atlas                # open findings arranged by MITRE ATLAS tactic and technique
ai-bom baseline mark nist "GOVERN 6.1" --notes "New servers only via ai-bom add, pinned"
ai-bom baseline mark iso A.3.2 --na  # not applicable to you
```

The **Baselines** tab shows the same. Filter it to what **needs attention** or **needs your answer**, expand or collapse every control, and see how many controls are in place in each group. A gap whose finding has an automatic fix offers it right there. The framework and filter you pick are remembered with your other preferences. The Markdown and HTML reports include a Baselines section.

- **NIST AI RMF 1.0** and **ISO/IEC 42001** are risk-management standards written for organizations. AI-BOM picks the controls a personal AI setup can meet and checks each one against evidence from your scan. Each control is marked *in place*, *partly* or *gap*, with the evidence, the findings involved and what to do. For example, *GOVERN 1.6 Inventory of AI systems* is met by the inventory itself, and *MANAGE 1.3* has a gap while any critical or high finding has neither a fix nor a recorded decision.
- Controls a scan can't see, such as a personal AI-use policy or what you use each tool for, are questions for you. Mark them done with a note, or not applicable. Your answers are kept in `~/.ai-bom/attestations.json` and included in `ai-bom state export`. Controls checked from your scan can't be marked by hand. A "done" answer older than 90 days counts as unanswered again (with your note kept) until you confirm it, because policies drift.
- **MITRE ATLAS:** every finding is tagged with the ATLAS techniques it relates to. Examples: *AML.T0110 AI Agent Tool Poisoning* for a tool that does more than it says, *AML.T0083 Credentials from AI Agent Configuration* for a key in a config file, and *AML.T0086 Exfiltration via AI Agent Tool Invocation* for a lethal-trifecta setup. The ATLAS view arranges your open findings by tactic. Technique IDs and names come from the official ATLAS data (release 2026.09). The tags also appear in SARIF, CycloneDX and HTML reports.

This is a self-assessment aid, not a certification or an audit. Control titles are short paraphrases; check them against the standards themselves.

## Using the dashboard

- **Search and commands:** press <kbd>⌘K</kbd> (<kbd>Ctrl</kbd>+<kbd>K</kbd>) to jump to any tab, rescan, export, change theme, or open any asset or finding by name.
- **History** shows a stacked chart of findings per scan, so you can see whether you are getting better.
- **Keyboard and screen readers:** every control is reachable and named, dialogs trap focus and make the page behind them inert, and views are checked with axe in light and dark mode. It works from a 320px-wide window up.

## Menu bar and editor

- **macOS menu bar:** `ai-bom menubar --install` adds a [SwiftBar](https://github.com/swiftbar/SwiftBar) or [xbar](https://xbarapp.com) plugin. It shows your score and top risks, and rescans every 30 minutes. `--uninstall` removes it.
- **VS Code / Cursor:** [`extensions/vscode`](extensions/vscode) shows `ai-bom check` results for the open folder as problems in the editor. It also puts a verdict in the status bar and re-checks when you save an AI config file (`.mcp.json`, `CLAUDE.md`, skills…).

Both call the `ai-bom` command, so install AI-BOM permanently (see *Run it from a clone*) rather than using `npx`.

## Fix it for me (safely, reversibly)

```bash
ai-bom fix                 # list findings with an automatic fix
ai-bom fix a1b2c3          # preview the change as a diff, confirm, apply
ai-bom fix weather --kind remove-entry
ai-bom snapshots           # changes made by ai-bom
ai-bom undo                # undo the last one (or: ai-bom undo <snapshot>)
```

| Fix | What it does |
|---|---|
| **Pin a safe version** | Rewrites the server's arguments to the fixed/latest version (`mcp-remote` → `mcp-remote@0.1.16`) |
| **Move secret to Keychain** | Stores the value in the macOS Keychain (or Linux Secret Service) and starts the server through a tiny launcher that reads it back. `ANTHROPIC_API_KEY` in Claude Code settings becomes an `apiKeyHelper`. |
| **Remove from config** | Takes a server out of every JSON config that starts it |
| **Fix the setting** | Turns permission prompts back on, stops auto-approving project servers, removes a broad allow rule, an API redirect, or prompt export |
| **Remove the hook** | Removes a hook entry |
| **Quarantine** | Moves a skill, agent or command to `~/.ai-bom/quarantine/` |
| **Disable the plugin** | Sets `enabledPlugins[…]` to `false` in Claude Code |

How it stays safe:

- **Preview first.** You always see a redacted diff before anything changes.
- **Refuses stale previews.** Applying re-reads each file and refuses if it changed since the preview.
- **Minimal, validated edits.** Edits are JSONC-aware, so comments, key order and formatting elsewhere are kept. The result is re-parsed before it is written atomically with the file's original permissions.
- **Snapshots, without copying secrets.** Every change is saved as a snapshot in `~/.ai-bom/snapshots/` and listed in the dashboard's History tab. Only the changed entries are stored, never whole config files (which often hold secrets). Undo refuses if you edited the same spot since, unless you pass `--force`.
- **Audit log.** `~/.ai-bom/audit.log` records file names only.
- **Claude Code rewrites `~/.claude.json` while it runs,** so quit it before fixing entries in that file (the preview reminds you).
- **TOML/YAML configs** (Codex, Continue, Goose) get step-by-step manual instructions instead of edits.

## Triage: accept, snooze, dismiss

Not every finding needs fixing. In the dashboard, or from the terminal:

```bash
ai-bom triage accept <id> --reason "Needed for work; token is read-only"
ai-bom triage snooze <id> 30d --reason "Revisit after the migration"   # 30d, 2w, 3m or a date
ai-bom triage fp <id> --reason "Test fixture, not a real key"
ai-bom triage                 # list decisions
ai-bom triage clear <id>
```

- In the dashboard you can tick several findings and accept, snooze or dismiss them together with one shared reason (or unmute several from **Muted**). One toast offers one Undo for the whole batch.
- Muted findings stay visible under **Muted**, but they don't count toward risk, `--fail-on`, notifications or the headline numbers.
- Snoozes come back when they expire.
- A decision is tied to the exact evidence, so a new version or a different token brings the finding back.
- Decisions live in `~/.ai-bom/triage.json`.

## Pre-flight check for repositories you didn't write

```bash
ai-bom check ~/Downloads/some-repo
ai-bom check https://github.com/someone/project       # shallow clone to a temp folder
ai-bom check . --sarif results.sarif                  # for CI
ai-bom check --install-hook                           # check every project when a Claude Code session starts
```

It scans only the repository's own files, never your user-level config, and runs nothing in it. Remote repositories are cloned shallowly with git hooks, LFS and submodules disabled. You get:

- **What it sets up:** hooks, MCP servers, tasks that run on folder open;
- **Findings,** such as a project settings file that redirects `ANTHROPIC_BASE_URL` to steal your key;
- **A verdict:** safe (exit 0), review (1) or dangerous (2).

With `--install-hook`, Claude Code shows a warning at session start in risky projects and tells the model to treat repository instructions as untrusted.

The dashboard's **Safeguards** tab does the same without a terminal: it checks a folder on this computer, turns the pre-flight hook, the MCP call guard (`ai-bom guard`) and the background watch on or off, and runs diagnostics (`ai-bom doctor`). The two hooks edit Claude Code's `settings.json` through the same undoable snapshots as `fix`. To check a URL, use `ai-bom check <url>` in a terminal.

## Watch mode and notifications

```bash
ai-bom watch                    # rescan when AI config changes (and every 30 min)
ai-bom watch --install          # run in the background: launchd on macOS, a systemd user timer on Linux
ai-bom watch --uninstall
```

You get a desktop notification when a new MCP server, skill or hook appears, or a new high or critical finding shows up. The first run only records the current state; muted findings never notify.

## Plain-language review (opt-in)

```bash
ai-bom explain helper            # review one skill / agent / command / hook / MCP server with Claude
ai-bom explain helper --local    # use a local Ollama model instead: nothing leaves your machine
```

A model reads the item's files (or a server's tool list and code) and answers in plain words:

- what it does;
- what data it touches;
- where data goes;
- anything it does that its description doesn't say;
- a verdict: looks fine, review, or avoid.

How it handles your data:

- You see exactly which files and how many characters would be sent, and must confirm.
- Secrets are masked first, and content over 60,000 characters is cut (the review says so).
- Results are cached by content hash in `~/.ai-bom/reviews.json`.
- The Claude API uses `ANTHROPIC_API_KEY` or an `ant auth login` profile. The dashboard's **Explain in plain words** button does the same, with a consent step.

## Known vulnerabilities, per call

AI-BOM checks the *call* each MCP server is started with, not just the package name. That means first working out which version that call actually runs:

| The call… | Version checked |
|---|---|
| pins a version (`npx -y mcp-remote@0.1.10`, `uvx pkg==1.2`) | that version |
| is unpinned, and a copy sits in the npx / uv / pipx cache | each cached version: `npx` can keep reusing an old copy instead of updating |
| is unpinned (online mode) | the latest release, which is what a fresh `npx` / `uvx` fetches |

That version is then checked against these sources, and the results are merged into one finding per CVE:

- **Bundled advisories (offline, always)**, such as `mcp-remote` [CVE-2025-6514](https://nvd.nist.gov/vuln/detail/CVE-2025-6514), MCP Inspector CVE-2025-49596, the filesystem server's path escapes, and the malicious `postmark-mcp`.
- **The signed advisory feed**, which ships new advisories between releases (see below).
- **NIST NVD (online).** A CVE is **confirmed** only when the package name appears in its description or affected-product data. Otherwise it is a low-severity **possible** finding to verify. The NVD allows 5 requests per 30 s, so AI-BOM paces itself and caches for 24 h. Set `NVD_API_KEY` ([free](https://nvd.nist.gov/developers/request-an-api-key)) for faster checks.
- **OSV.dev (online):** GitHub/npm/PyPI advisories and OpenSSF malicious-package reports.

Each finding explains why *your* call is affected and gives the **corrected call to copy** (or a one-click **Pin a safe version** fix).

### Self-updating advisory feed

The maintainers publish `advisories.json` with a detached **Ed25519 signature** on a rolling GitHub release. `ai-bom update` (and `--online` scans, at most once a day) downloads it and handles it strictly:

- the signature is verified against the public key built into the package;
- a feed older than the installed one (rollback) or dated in the future is refused;
- a verified copy is kept in `~/.ai-bom/feed/` and re-verified on every load;
- anything that fails verification is ignored, and the bundled advisories are used.

Maintainers: run `npm run feed:keygen`, which keeps the private key outside the repository. Paste the public key into `src/feed/index.ts` and add the printed secret as `AI_BOM_FEED_KEY`. The `advisory-feed` workflow then signs and publishes `feed/advisories.json` on every change. Forks can point clients at their own feed with `AI_BOM_FEED_URL` and `AI_BOM_FEED_PUBKEY`.

## Security checks

Each rule maps to the [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/), the OWASP Top 10 for Agentic Applications and [MITRE ATLAS](https://atlas.mitre.org) techniques:

| Rule | What it catches |
|---|---|
| `MCP-SECRET`, `SETTINGS-SECRET`, `CONTENT-SECRET` | API keys and tokens pasted into config, extension settings or skill files |
| `MCP-UNPINNED` | `npx -y pkg`, `@latest`, `uvx pkg`, `image:latest` |
| `MCP-INSECURE-TRANSPORT`, `MCP-BROAD-FS`, `MCP-CONTAINER-PRIVILEGED`, `MCP-SHELL-COMMAND` | Plain-http remotes, whole-disk access, privileged containers, `sh -c` launchers |
| `MCP-TOOL-POISONING`, `TOOL-BEHAVIOR-MISMATCH`, `TOOL-UNDECLARED`, `MCP-TOOL-SHADOWING` | Hidden instructions in tool descriptions; tools whose code does more than they say; tools missing from the manifest; a server reusing a trusted server's tool names ("tool shadowing") |
| `PERM-BYPASS`, `PERM-BROAD-ALLOW`, `PERM-AUTO-PROJECT-MCP`, `SETTINGS-API-REDIRECT` | Prompts disabled, `Bash(*)`, auto-trusting every repo's servers, API traffic redirected to another host |
| `HOOK-DATA-EGRESS`, `HOOK-NETWORK`, `HOOK-EXEC`, `AUTORUN-TASK` | Hooks that send your data out; hooks in general; tasks that run when a folder opens |
| `TELEMETRY-PROMPTS`, `TELEMETRY-EXPORT`, `TELEMETRY-INSECURE` | Prompt text exported to a collector; where telemetry goes; plain-http export |
| `CONTENT-HIDDEN-UNICODE`, `CONTENT-PROMPT-INJECTION`, `CONTENT-DOWNLOAD-EXEC`, `CONTENT-SENSITIVE-PATHS` | Smuggled characters (text hidden in invisible Unicode tag characters is decoded and shown; emoji joiners and Thai/Persian spacing are not flagged), "ignore previous instructions", `curl … \| sh`, `~/.ssh` in skills and rules |
| `SKILL-UNRESTRICTED-TOOLS`, `SKILL-EXFIL-PATTERN`, `SKILL-SUSPICIOUS-ENDPOINT` | Unrestricted `Bash`, credential-reading scripts that talk to the network, webhook.site/ngrok/raw IPs |
| `TOOLCALL-SECRET-SENT`, `TOOLCALL-SUSPICIOUS-DEST`, `TOOLCALL-INJECTION`, `USAGE-UNUSED` | From your session logs (see above) |
| `MODEL-SERVER-EXPOSED`, `MCP-UNLISTED-RUNNING` | From the running processes and open ports: a model server (Ollama, llama.cpp, LM Studio…) reachable from other computers; a program that looks like an MCP server but is in no config. Read with `ps` and `lsof`, only when scanning this computer's own home folder |
| `COMBO-LETHAL-TRIFECTA`, `COMBO-SHELL-UNTRUSTED` | Dangerous combinations |
| `TRUST-*` | Typosquats, rug pulls, install scripts, very new/deprecated packages, no source repository |
| `VULN-KNOWN`, `VULN-POSSIBLE`, `VULN-MALICIOUS` | Known CVEs / malware in the package an MCP server runs |
| `DEP-VULN`, `DEP-LICENSE` | Vulnerable or strong-copyleft dependencies installed with an MCP server |
| `LIVE-HIDDEN-TOOLS`, `LIVE-DYNAMIC-DESCRIPTIONS`, `LIVE-NETWORK-AT-START` | What a sandboxed live check found that its files didn’t show |
| `MODEL-PICKLE`, `APIKEY-PLAINTEXT`, `APIKEY-NOT-GITIGNORED`, `EXT-ALL-SITES` | Pickle model weights, keys in dotfiles or committable `.env` files, AI extensions that read every site |
| `CONNECTOR-REVIEW` | A cloud connector you haven't confirmed in 90+ days |

### Cloud connectors

No AI platform offers an API to list the connectors you enabled in your account. So AI-BOM:

- detects the claude.ai connectors Claude Code knows about;
- keeps a user-maintained registry in `~/.ai-bom/connectors.json` for the rest;
- reminds you when a connector hasn't been reviewed for 90 days.

```bash
ai-bom connectors add claude.ai Gmail --access read-write
ai-bom connectors                 # list, with ids
ai-bom connectors review <id>     # "still in use"
ai-bom connectors remove <id>
```

## Reports

```bash
ai-bom report                               # ai-bom-report.html: self-contained, prints cleanly to PDF
ai-bom report --sarif ai-bom.sarif --markdown ai-bom.md
ai-bom scan --json ai-bom.json              # full inventory (ai-bom schema)
ai-bom scan --cyclonedx ai-bom.cdx.json     # CycloneDX 1.6
ai-bom scan --fail-on high                  # exit 1 if an active high/critical finding exists
```

The dashboard's **Export** menu offers the same reports. Muted findings appear in SARIF as suppressions, with your reason.

**GitHub Action.** Check pull requests for risky AI configuration and see results in code scanning:

```yaml
- uses: actions/checkout@v4
- uses: drumin/ai-scanner@main
  with:
    fail-on: dangerous      # or: review, never
```

See [`action.yml`](action.yml) and [`docs/example-workflow.yml`](docs/example-workflow.yml).

Each scan is compared with the previous one, stored in `~/.ai-bom/last-scan.json` (asset IDs and names only). New and removed assets are highlighted, which is how forgotten "shadow AI" shows up over time. Use `--no-history` to turn this off.

## Where AI-BOM keeps its data

Everything you decide or change is saved in **`~/.ai-bom/`** (or `$AI_BOM_HOME`) with owner-only permissions, so it survives restarts, rescans and a different dashboard port:

| File | What |
|---|---|
| `triage.json` | Muted findings (accepted, snoozed, false positives) with your reasons |
| `snapshots/`, `audit.log` | Every change `fix` made, how to undo it, and a log of fixes/undos (file names only) |
| `connectors.json` | Cloud connectors you registered |
| `attestations.json` | Your answers for NIST AI RMF / ISO 42001 controls a scan can't check |
| `preferences.json` | Dashboard preferences (theme, map view, active/muted findings, baseline framework and filter, whether you dismissed the welcome) |
| `history/scans.jsonl` | One line per scan with counts only (assets, active findings by severity, muted, score), shown under **History → Scans** and as the score trend |
| `inspections.json` | Results of sandboxed live checks (tool names and descriptions only) |
| `incidents/` | Reports written by incident mode |
| `last-scan.json`, `tool-hashes.json`, `reviews.json` | Previous scan, tool descriptions for rug-pull detection, cached reviews |
| `quarantine/`, `feed/`, `cache/`, `bin/` | Quarantined items, the verified advisory feed, NVD cache, the keychain launcher |

```bash
ai-bom state                          # what is stored, how big, and your recent scans
ai-bom state export ai-bom-state.json # back up triage decisions, connectors and preferences
ai-bom state import ai-bom-state.json # restore on another Mac (merges; --force replaces)
```

`npm run demo` keeps its fake home folder and its own state in `~/.ai-bom/demo/`, separate from your real data; `npm run demo -- --reset` starts it over.

## Nothing found? Run the doctor

```bash
npm start -- doctor          # or: ai-bom doctor   (add --all to list every missing location)
```

It prints:

- the AI tools detected;
- every config file and folder that was found, with its top-level **key names** or item counts;
- files that couldn't be read;
- the folder listing of your Claude config directories.

It never prints values, so it's safe to paste into an issue. If you use a custom Claude config folder, set `CLAUDE_CONFIG_DIR`.

## Options

```
-p, --project <dir>    Also scan this project directory (repeatable)
-d, --discover <dir>   Find projects with AI config under <dir> (repeatable)
    --online           Query OSV.dev, the NVD, npm/PyPI and the MCP Registry
    --no-auto-discover Don't sweep ~/Projects, ~/code, ~/Developer… for projects
    --no-known         Skip projects remembered by Claude Code
    --no-cwd           Don't treat the current directory as a project
    --no-history       Don't save/compare with the previous scan
    --no-session-logs  Don't read Claude Code session logs
    --no-tool-analysis Don't read MCP server code
    --full-paths       Keep absolute home paths instead of "~"
    --port <n>         Dashboard port (default 7654)
    --no-open          Don't open the browser
```

Run `ai-bom --help` for every command.

## Privacy and safety

- **Scanning only reads.** The scanner never runs the MCP servers, skills, hooks or repositories it inspects. Model weights and browser data are only listed, never read.
- **What leaves your machine:** only what you ask for.
  - `--online` sends package names and versions to OSV.dev, the NVD, npm/PyPI and the MCP Registry.
  - `explain` sends one item's redacted text to the Claude API, or to nothing with `--local`.
- **Secrets are masked** in env vars, headers, URLs, arguments, diffs, reports and session-log excerpts before anything is serialized. References like `${env:TOKEN}` are kept.
- **Paths are shortened.** Home paths are rewritten to `~` by default, so exports are safer to share.
- **The dashboard is local only.** Its server listens on `127.0.0.1` only and rejects foreign `Host` headers, which blocks DNS rebinding. Every state-changing request needs a custom header (a CSRF defense), and request bodies are capped at 16 KB.
- **AI-BOM's own state stays private.** Everything it writes lives in `~/.ai-bom/` with owner-only permissions.
  - Snapshots store only the entries a fix changed. Removed entries can contain the secrets they held, so treat that folder like your configs.
  - Secrets moved to the keychain are not kept anywhere else.

## Development

```bash
npm install
npm test            # vitest: unit tests and full scans of a synthetic macOS home
npm run demo        # dashboard on http://127.0.0.1:7655 against the test fixture (kept in ~/.ai-bom/demo)
npm run build       # dist/cli.js and dist/web
npm run typecheck
npm run e2e:install # once: downloads the Chromium the browser tests use
npm run test:e2e    # dashboard in a real browser: keyboard, dialogs, responsive layout, axe audit
```

Layout:

```
src/
  scanners/     one module per AI tool, plus wider.ts (models, keys, apps, browser extensions)
  analysis/     tool code vs. description, hook explanations and telemetry, reach and combinations
  checks/       rules and OWASP mapping
  vulns/        bundled advisories, OSV, NVD, installed versions
  trust/        typosquats, rug pulls, registry metadata
  feed/         signed advisory feed
  fix/          reversible fixes: JSONC edits, keychain, snapshots, undo
  review/       opt-in plain-language review (Claude API / Ollama)
  reports/      HTML, SARIF, Markdown;  bom/ CycloneDX
  agentlogs.ts  Claude Code, Claude Desktop, Codex, Gemini CLI, Copilot CLI and Cline session logs, normalized
  sessions.ts   usage and per-call audit;  activity.ts  timeline;  incident.ts  incident mode
  add.ts, vet.ts, pkgfetch.ts   safe add and upgrade (download, verify, analyze, pin)
  deps.ts       dependency vulnerabilities and licenses
  inspect.ts    sandboxed live inspection
  score.ts      security score;  analysis/context.ts  context cost
  frameworks/   MITRE ATLAS mapping (generated technique table), NIST AI RMF and ISO/IEC 42001 baselines
  menubar.ts    SwiftBar / xbar plugin
  guard.ts      live MCP call guard (Claude Code hook)
  preflight.ts  repository pre-flight check
  watch.ts      watch mode, notifications, launchd/systemd
  triage.ts     accept / snooze / false positive
  state.ts      scan history, preferences, state export/import
  server/       local dashboard server and actions
web/            React dashboard
extensions/vscode  VS Code / Cursor extension
test/           fixture home dir and tests
```

## Roadmap

- **Container images:** image vulnerability checks via Grype or Trivy when installed.
- **Cloud connector import:** automatic, as soon as a platform exposes a connector list.
- **An MCP gateway** that sits between agents and servers and enforces policy on every call. It is a different kind of tool (always running, in the data path), so it would be a separate product rather than part of this scanner.
- **Windows:** config, browser, app and PowerShell profile paths are covered and tested with a synthetic home, but not yet on a real Windows machine. The live sandbox and menu bar are macOS/Linux only.
