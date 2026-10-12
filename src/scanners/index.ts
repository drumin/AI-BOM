import type { Collector } from '../collector.js';
import type { ClientId } from '../types.js';
import { claudeCode } from './claude-code.js';
import { claudeDesktop } from './claude-desktop.js';
import { otherScanners } from './others.js';
import { widerScanners } from './wider.js';

/**
 * A scanner knows where one AI client keeps its configuration.
 * `scanUser` looks at user-level (home directory) config; `scanProject`
 * is called once per project root.
 */
export interface Scanner {
  id: ClientId;
  scanUser?(col: Collector): Promise<void>;
  scanProject?(col: Collector, dir: string): Promise<void>;
}

export const scanners: Scanner[] = [claudeCode, claudeDesktop, ...otherScanners, ...widerScanners];

/** Files/dirs whose presence marks a directory as a project with AI config (for --discover). */
export const PROJECT_MARKERS = [
  '.mcp.json',
  '.claude',
  '.cursor',
  '.cursorrules',
  '.vscode/mcp.json',
  '.gemini',
  '.codex',
  '.roo',
  '.kiro',
  '.amazonq',
  '.continue',
  '.windsurfrules',
  '.windsurf',
  '.clinerules',
  '.agents',
  '.github/copilot-instructions.md',
  'AGENTS.md',
  'CLAUDE.md',
  'GEMINI.md',
  'opencode.json',
  '.opencode',
  '.devin',
  '.factory',
  '.qwen',
  '.junie',
  '.augment',
  '.trae',
  '.amp',
  '.aider.conf.yml',
  '.github/mcp.json',
];
