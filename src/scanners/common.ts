import path from 'node:path';
import YAML from 'yaml';
import type { Collector } from '../collector.js';
import type { AssetKind, ClientId, Scope } from '../types.js';
import { normalizeMcpEntry } from '../mcp.js';
import { asString, asStringArray, isDir, isObject, listDir, ParseError, readStructured, readSmallText, SKILL_FILE_CAP, TooLargeError, walkFiles } from '../util/fs.js';

export interface Where {
  client: ClientId;
  scope: Scope;
  project?: string;
  /** Parent asset id (plugin/extension) that bundles what's found. */
  via?: string;
}

/** Read a config file, recording parse errors. Returns undefined if missing. */
export async function readConfig(col: Collector, file: string): Promise<Record<string, unknown> | undefined> {
  try {
    const data = await readStructured(file);
    if (data === undefined) {
      col.note(file, 'missing');
      return undefined;
    }
    if (!isObject(data)) {
      col.error(file, 'Unexpected top-level structure');
      col.note(file, 'error', 'not an object');
      return undefined;
    }
    // Key names only (never values) so `ai-bom doctor` can show what the file contains.
    const keys = Object.keys(data);
    col.note(file, 'found', `keys: ${keys.slice(0, 12).join(', ')}${keys.length > 12 ? `, … (${keys.length})` : ''}`);
    return data;
  } catch (e) {
    const msg = e instanceof ParseError || e instanceof TooLargeError ? e.message : `Could not read: ${(e as Error).message}`;
    col.error(file, msg);
    col.note(file, 'error', msg);
    return undefined;
  }
}

/** JSON/JSONC files can be edited in place by `ai-bom fix`; TOML/YAML get manual instructions. */
export const isJsonFile = (file: string) => /\.(json|jsonc)$/i.test(file);

/** Walk a dotted key path (`mcp.servers`) inside a config object. */
export function dig(obj: Record<string, unknown>, keyPath: string): unknown {
  let cur: unknown = obj;
  for (const k of keyPath.split('.')) {
    if (!isObject(cur)) return undefined;
    cur = cur[k];
  }
  return cur;
}

/** Add every entry of a `{ name: serverEntry }` map as an MCP server. */
export function addMcpMap(
  col: Collector,
  map: unknown,
  file: string,
  where: Where,
  status?: (name: string) => { enabled?: boolean; note?: string },
  /** Key path of `map` inside the file (JSON configs only), recorded so fixes can edit the entry. */
  basePath?: string[],
): number {
  if (!isObject(map)) return 0;
  let n = 0;
  const skipped: string[] = [];
  for (const [name, entry] of Object.entries(map)) {
    const norm = normalizeMcpEntry(entry);
    if (!norm) {
      skipped.push(name);
      continue;
    }
    const st = norm.enabled ? status?.(name) ?? { enabled: true } : { enabled: false };
    col.add({
      kind: 'mcp-server',
      name,
      mcp: norm.details,
      occurrence: {
        client: where.client,
        scope: where.scope,
        source: file,
        name,
        project: where.project,
        via: where.via,
        enabled: st.enabled,
        note: st.note,
        jsonPath: basePath && isJsonFile(file) ? [...basePath, name] : undefined,
      },
    });
    n++;
  }
  col.note(file, 'found', `${n} MCP server(s)${where.project ? ` for ${where.project}` : ''}${skipped.length ? `; ${skipped.length} entr(y/ies) without command or url` : ''}`);
  return n;
}

/**
 * The most common case: a JSON/YAML/TOML file holding an MCP server map at `key`.
 * Registers the client when the file exists.
 */
export async function scanMcpFile(
  col: Collector,
  file: string,
  keys: string[],
  where: Where,
  clientName: string,
): Promise<Record<string, unknown> | undefined> {
  const data = await readConfig(col, file);
  if (!data) return undefined;
  col.client(where.client, clientName, file);
  for (const key of keys) addMcpMap(col, dig(data, key), file, where, undefined, key.split('.'));
  return data;
}

export interface Frontmatter {
  data: Record<string, unknown>;
  body: string;
}

export function parseFrontmatter(text: string): Frontmatter {
  const m = text.match(/^﻿?---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!m) return { data: {}, body: text };
  try {
    const data = YAML.parse(m[1]);
    return { data: isObject(data) ? data : {}, body: m[2] };
  } catch {
    return { data: {}, body: m[2] };
  }
}

function toolsList(v: unknown): string[] | undefined {
  if (typeof v === 'string') return v.split(/,\s*/).map((s) => s.trim()).filter(Boolean);
  return asStringArray(v);
}

/**
 * Scan a skills directory. Each folder holding a SKILL.md is one skill; they
 * may be nested (e.g. skills/synced/<account>/<skill>/SKILL.md for skills
 * synced from a claude.ai account). A skill's own subfolders are not searched.
 */
export interface SkillsDirHooks {
  /** Identity to merge with an asset found elsewhere (default: the skill folder). */
  key?(skillName: string, skillDir: string): string | undefined;
  /** Extra detail for this occurrence (replaces the synced-from-account note). */
  note?(skillName: string): string | undefined;
  enabled?(skillName: string): boolean | undefined;
}

/** Register the skill in `skillDir` (a folder holding SKILL.md). Returns false when there is no SKILL.md. */
export async function addSkillFolder(col: Collector, skillDir: string, where: Where, hooks: SkillsDirHooks = {}): Promise<boolean> {
  const skillFile = (await listDir(skillDir)).find((f) => f.toLowerCase() === 'skill.md');
  if (!skillFile) return false;
  const text = (await readSmallText(path.join(skillDir, skillFile))) ?? '';
  const fm = parseFrontmatter(text);
  const skillName = asString(fm.data.name) ?? path.basename(skillDir);
  const walked = await walkFiles(skillDir, 4, SKILL_FILE_CAP + 1);
  const files = walked.slice(0, SKILL_FILE_CAP);
  col.add({
    kind: 'skill',
    name: skillName,
    key: hooks.key?.(skillName, skillDir) ?? skillDir,
    path: skillDir,
    skill: {
      description: asString(fm.data.description),
      allowedTools: toolsList(fm.data['allowed-tools'] ?? fm.data.allowedTools),
      version: asString(fm.data.version) ?? asString(dig(fm.data, 'metadata.version')),
      author: asString(fm.data.author),
      files,
      truncated: walked.length > SKILL_FILE_CAP || undefined,
    },
    occurrence: {
      client: where.client,
      scope: where.scope,
      source: skillDir,
      name: skillName,
      project: where.project,
      via: where.via,
      enabled: hooks.enabled?.(skillName),
      note: hooks.note?.(skillName) ?? (/[\\/]synced[\\/]/.test(skillDir) ? 'Synced from your Claude account' : undefined),
    },
  });
  return true;
}

export async function scanSkillsDir(col: Collector, dir: string, where: Where, maxDepth = 3, hooks: SkillsDirHooks = {}): Promise<void> {
  if (!(await isDir(dir))) return col.note(dir, 'missing');
  const before = col.assets.size;
  const visit = async (d: string, depth: number) => {
    for (const name of await listDir(d)) {
      if (name.startsWith('.')) continue;
      const skillDir = path.join(d, name);
      if (!(await isDir(skillDir))) continue;
      if (!(await addSkillFolder(col, skillDir, where, hooks)) && depth < maxDepth) await visit(skillDir, depth + 1);
    }
  };
  await visit(dir, 0);
  col.note(dir, 'found', `${col.assets.size - before} skill(s)`);
}

/** Scan a directory of markdown definitions (subagents, slash commands, rules). */
export async function scanMarkdownDir(
  col: Collector,
  dir: string,
  kind: AssetKind,
  where: Where,
  exts = ['.md'],
): Promise<void> {
  if (!(await isDir(dir))) return col.note(dir, 'missing');
  col.note(dir, 'found', `${kind} folder`);
  const files = await walkFiles(dir, 3, 300);
  for (const rel of files) {
    if (!exts.includes(path.extname(rel).toLowerCase())) continue;
    const file = path.join(dir, rel);
    const text = (await readSmallText(file)) ?? '';
    const fm = parseFrontmatter(text);
    const base = rel.slice(0, -path.extname(rel).length).split(path.sep).join(':');
    // Rules files are named by location (their frontmatter rarely has a name).
    const name =
      kind === 'instructions'
        ? where.project
          ? `${path.basename(where.project)}/${path.relative(where.project, file)}`
          : file.replace(col.ctx.home, '~')
        : asString(fm.data.name) ?? base;
    col.add({
      kind,
      name,
      key: file,
      path: file,
      skill: {
        description: asString(fm.data.description),
        allowedTools: toolsList(fm.data['allowed-tools'] ?? fm.data.tools),
        files: [path.basename(file)],
      },
      occurrence: { client: where.client, scope: where.scope, source: file, name, project: where.project, via: where.via },
    });
  }
}

/** Add a single instructions file (CLAUDE.md, AGENTS.md, .cursorrules...) if present. */
export async function addInstructionsFile(col: Collector, file: string, where: Where): Promise<boolean> {
  const text = await readSmallText(file);
  if (text === undefined) return false;
  col.add({
    kind: 'instructions',
    name: where.project ? `${path.basename(where.project)}/${path.relative(where.project, file)}` : file.replace(col.ctx.home, '~'),
    key: file,
    path: file,
    skill: { files: [path.basename(file)] },
    occurrence: { client: where.client, scope: where.scope, source: file, name: path.basename(file), project: where.project, via: where.via },
  });
  return true;
}

/**
 * Hooks. Two shapes are supported:
 *   Claude Code: { Event: [ { matcher, hooks: [ { type: "command", command } ] } ] }
 *   Cursor:      { event: [ { command } ] }
 */
export function addHooks(col: Collector, hooks: unknown, file: string, where: Where, basePath?: string[]): void {
  if (!isObject(hooks)) return;
  for (const [event, groups] of Object.entries(hooks)) {
    if (!Array.isArray(groups)) continue;
    groups.forEach((g, gi) => {
      if (!isObject(g)) return;
      const matcher = asString(g.matcher);
      const nested = Array.isArray(g.hooks);
      const inner = nested ? (g.hooks as unknown[]) : [g];
      inner.forEach((h, hi) => {
        if (!isObject(h)) return;
        const command = asString(h.command) ?? asString(h.prompt);
        if (!command) return;
        const name = `${event}${matcher ? ` [${matcher}]` : ''}`;
        col.add({
          kind: 'hook',
          name,
          key: `${file}|${event}|${matcher ?? ''}|${command}`,
          hook: { event, matcher, command },
          path: file,
          occurrence: {
            client: where.client,
            scope: where.scope,
            source: file,
            name,
            project: where.project,
            via: where.via,
            jsonPath: basePath && isJsonFile(file) ? [...basePath, event, gi, ...(nested ? ['hooks', hi] : [])] : undefined,
          },
        });
      });
    });
  }
}
