import * as vscode from 'vscode';
import * as path from 'node:path';
import { execFile } from 'node:child_process';
import { fixLine, splitCommand } from './command';

/**
 * AI-BOM for VS Code / Cursor: runs `ai-bom check <workspace> --json` (the
 * local scanner; nothing is uploaded) and turns its findings into problems
 * in the files that caused them, with a status-bar verdict.
 */

interface Finding {
  id: string;
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  remediation: string;
  location?: string;
  evidence?: string;
  muted?: unknown;
  fixes?: string[];
}

interface CheckResult {
  verdict: 'safe' | 'review' | 'dangerous';
  findings: Finding[];
  autorun: string[];
}

const AI_FILES = /(^|[\\/])(\.mcp\.json|mcp\.json|mcp_config\.json|settings(\.local)?\.json|tasks\.json|CLAUDE(\.local)?\.md|AGENTS\.md|GEMINI\.md|SKILL\.md|\.cursorrules|\.windsurfrules|copilot-instructions\.md)$|[\\/](\.claude|\.cursor|\.gemini|\.codex|\.agents)[\\/]/;

const SEVERITY: Record<Finding['severity'], vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};

function run(folder: string): Promise<CheckResult> {
  const cmd = splitCommand(vscode.workspace.getConfiguration('aiBom').get<string>('command', 'ai-bom'));
  if (!cmd.length) return Promise.reject(new Error('aiBom.command is empty.'));
  return new Promise((resolve, reject) => {
    execFile(cmd[0], [...cmd.slice(1), 'check', folder, '--json'], { maxBuffer: 50 * 1024 * 1024, timeout: 120_000 }, (err, stdout, stderr) => {
      // Exit codes 1 and 2 mean "review" / "dangerous", not failure.
      if (err && !stdout) return reject(new Error(stderr.trim() || err.message));
      try {
        resolve(JSON.parse(stdout) as CheckResult);
      } catch {
        reject(new Error('Could not read ai-bom output. Is aiBom.command set correctly?'));
      }
    });
  });
}

/** Best line for a finding: an explicit :line, else where its evidence or asset name appears. */
function rangeFor(doc: vscode.TextDocument, f: Finding, line?: number): vscode.Range {
  if (line && line <= doc.lineCount) return doc.lineAt(line - 1).range;
  const text = doc.getText();
  const needles = [f.evidence?.split(/[=:]/)[0], ...(f.evidence?.match(/"([^"]{3,})"/g) ?? []).map((s) => s.slice(1, -1)), f.title.split(' ').find((w) => w.length > 5)].filter((x): x is string => !!x && x.length > 2);
  for (const n of needles) {
    const i = text.indexOf(n);
    if (i >= 0) {
      const p = doc.positionAt(i);
      return doc.lineAt(p.line).range;
    }
  }
  return doc.lineAt(0).range;
}

export function activate(ctx: vscode.ExtensionContext) {
  const diagnostics = vscode.languages.createDiagnosticCollection('ai-bom');
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.command = 'aiBom.check';
  ctx.subscriptions.push(diagnostics, status);
  let last: CheckResult | undefined;

  const check = async (quiet = false) => {
    const folder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!folder) return;
    status.text = '$(sync~spin) AI-BOM';
    status.show();
    try {
      const r = await run(folder);
      last = r;
      diagnostics.clear();
      const byFile = new Map<string, vscode.Diagnostic[]>();
      for (const f of r.findings.filter((x) => !x.muted)) {
        const m = f.location?.match(/^(.*?)(?::(\d+))?$/);
        if (!m?.[1]) continue;
        const file: string = path.isAbsolute(m[1]) ? m[1] : path.join(folder, m[1]);
        if (!file.startsWith(folder)) continue;
        let doc: vscode.TextDocument;
        try {
          doc = await vscode.workspace.openTextDocument(file);
        } catch {
          continue;
        }
        const d = new vscode.Diagnostic(rangeFor(doc, f, m[2] ? Number(m[2]) : undefined), `${f.title}${f.evidence ? ` — ${f.evidence}` : ''}\n${f.remediation}`, SEVERITY[f.severity]);
        d.source = 'ai-bom';
        d.code = f.ruleId;
        byFile.set(file, [...(byFile.get(file) ?? []), d]);
      }
      for (const [file, list] of byFile) diagnostics.set(vscode.Uri.file(file), list);
      const icon = r.verdict === 'dangerous' ? '$(error)' : r.verdict === 'review' ? '$(warning)' : '$(shield)';
      status.text = `${icon} AI-BOM: ${r.verdict}`;
      status.tooltip = r.autorun.length ? `This workspace sets up:\n${r.autorun.slice(0, 8).join('\n')}` : 'No AI hooks, MCP servers or auto-run tasks configured here.';
      if (!quiet && r.verdict === 'dangerous') {
        const pick = await vscode.window.showWarningMessage(`AI-BOM: this workspace's AI configuration looks dangerous (${r.findings.filter((x) => !x.muted && (x.severity === 'critical' || x.severity === 'high')).length} critical/high).`, 'Show problems');
        if (pick) vscode.commands.executeCommand('workbench.actions.view.problems');
      }
    } catch (e) {
      status.text = '$(circle-slash) AI-BOM';
      status.tooltip = (e as Error).message;
      if (!quiet) vscode.window.showErrorMessage(`AI-BOM: ${(e as Error).message}`);
    }
  };

  ctx.subscriptions.push(
    vscode.commands.registerCommand('aiBom.check', () => check(false)),
    vscode.commands.registerCommand('aiBom.dashboard', () => {
      const t = vscode.window.createTerminal('AI-BOM');
      t.sendText(vscode.workspace.getConfiguration('aiBom').get<string>('command', 'ai-bom'));
      t.show();
    }),
    vscode.commands.registerCommand('aiBom.fix', async () => {
      const items = (last?.findings ?? []).filter((f) => !f.muted && f.fixes?.length).map((f) => ({ label: f.title, description: f.fixes!.join(', '), id: f.id }));
      if (!items.length) return vscode.window.showInformationMessage('AI-BOM: nothing here can be fixed automatically.');
      const pick = await vscode.window.showQuickPick(items, { placeHolder: 'Preview and apply a reversible fix in the terminal' });
      if (!pick) return;
      const t = vscode.window.createTerminal('AI-BOM fix');
      // Ids from a workspace check only resolve when that workspace is part of the scan, so pass it explicitly.
      t.sendText(fixLine(vscode.workspace.getConfiguration('aiBom').get<string>('command', 'ai-bom'), pick.id, vscode.workspace.workspaceFolders?.[0]?.uri.fsPath));
      t.show();
    }),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (vscode.workspace.getConfiguration('aiBom').get<boolean>('checkOnSave', true) && AI_FILES.test(doc.fileName)) check(true);
    }),
  );
  check(true);
}

export function deactivate() {}
