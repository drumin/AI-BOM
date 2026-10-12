# AI-BOM for VS Code and Cursor

Shows risky AI configuration where it lives: MCP servers in `.mcp.json` / `.vscode/mcp.json` / `.cursor/mcp.json`, hooks and permissions in `.claude/settings.json`, tasks that run when the folder opens, prompt injection in `CLAUDE.md` / `AGENTS.md` / skills.

- Problems appear in the editor and the Problems panel; the status bar shows **safe / review / dangerous**.
- Re-checks when you save an AI config file.
- **AI-BOM: Fix a finding…** previews and applies a reversible fix (`ai-bom fix`) in the terminal.

It runs the local `ai-bom check` (a pre-flight scan of this folder only); nothing leaves your machine.

## Setup

1. Install AI-BOM so `ai-bom` is on your PATH (see the main README), or set **aiBom.command** to e.g. `node /path/to/ai-scanner/dist/cli.js`.
2. Build and install the extension:

```bash
cd extensions/vscode
npm install && npm run build
npx @vscode/vsce package          # creates ai-bom-vscode-0.1.0.vsix
code --install-extension ai-bom-vscode-0.1.0.vsix     # or: cursor --install-extension …
```
