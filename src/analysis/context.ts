import path from 'node:path';
import { promises as fs } from 'node:fs';
import type { Collector } from '../collector.js';
import type { Asset, ClientId, ContextCost } from '../types.js';

/**
 * Context cost: how much of every conversation your setup uses up before you
 * type anything. Each enabled MCP server adds its tool names, descriptions
 * and input schemas; skills, subagents and commands add their name and
 * description; instruction files (CLAUDE.md, AGENTS.md…) are included in
 * full. Estimates use ~4 characters per token.
 */

const tok = (chars: number) => Math.ceil(chars / 4);
/** Per-tool overhead for the name, input schema and JSON framing when only the description is known. */
const TOOL_OVERHEAD = 90;
/** A remote or unread server whose tools we can't see: a typical small server. */
const UNKNOWN_SERVER = 1200;

async function fileSize(p?: string): Promise<number | undefined> {
  if (!p) return undefined;
  try {
    const st = await fs.stat(p);
    return st.isFile() ? st.size : undefined;
  } catch {
    return undefined;
  }
}

async function tokensFor(a: Asset): Promise<{ tokens: number; estimated: boolean } | undefined> {
  if (a.kind === 'mcp-server' && a.mcp) {
    const tools = a.mcp.tools;
    if (!tools?.length) return { tokens: UNKNOWN_SERVER, estimated: true };
    return { tokens: tools.reduce((n, t) => n + TOOL_OVERHEAD + tok(t.name.length + (t.description?.length ?? 0)), 0), estimated: false };
  }
  if (a.kind === 'skill' || a.kind === 'agent' || a.kind === 'command') {
    return { tokens: 15 + tok(a.name.length + (a.skill?.description?.length ?? 0)), estimated: false };
  }
  if (a.kind === 'instructions') {
    const size = await fileSize(a.path);
    return size === undefined ? undefined : { tokens: tok(size), estimated: false };
  }
  return undefined;
}

const LOADED = new Set(['mcp-server', 'skill', 'agent', 'command', 'instructions']);

/** `unusedIds`: servers the session logs show as never called (see USAGE-UNUSED). */
export async function contextCost(col: Collector, unusedIds: Set<string> = new Set()): Promise<ContextCost[]> {
  const perAsset = new Map<string, { tokens: number; estimated: boolean }>();
  for (const a of col.assets.values()) {
    if (!LOADED.has(a.kind)) continue;
    const t = await tokensFor(a);
    if (t) perAsset.set(a.id, t);
  }
  // What loads together: a client's user-level assets, plus each project's own.
  const groups = new Map<string, { client: ClientId; project?: string; ids: Set<string> }>();
  for (const a of col.assets.values()) {
    if (!perAsset.has(a.id)) continue;
    for (const o of a.occurrences) {
      if (o.enabled === false || o.note?.startsWith('Not approved') || o.note?.startsWith('Rejected') || o.client.startsWith('cloud:')) continue;
      const project = o.scope === 'project' || o.scope === 'local' ? o.project : undefined;
      const key = `${o.client}|${project ?? ''}`;
      if (!groups.has(key)) groups.set(key, { client: o.client, project, ids: new Set() });
      groups.get(key)!.ids.add(a.id);
    }
  }
  const out: ContextCost[] = [];
  for (const g of groups.values()) {
    const ids = new Set(g.ids);
    if (g.project) for (const id of groups.get(`${g.client}|`)?.ids ?? []) ids.add(id);
    const items = [...ids]
      .map((id) => {
        const a = col.assets.get(id)!;
        const t = perAsset.get(id)!;
        const unused = unusedIds.has(id) || undefined;
        return { assetId: id, name: a.name, kind: a.kind, tokens: t.tokens, estimated: t.estimated || undefined, unused };
      })
      .sort((x, y) => y.tokens - x.tokens);
    const total = items.reduce((n, i) => n + i.tokens, 0);
    const suggestions: string[] = [];
    const idle = items.filter((i) => i.unused && i.tokens >= 300);
    if (idle.length) {
      const saved = idle.reduce((n, i) => n + i.tokens, 0);
      suggestions.push(`${idle.map((i) => i.name).slice(0, 4).join(', ')} ${idle.length === 1 ? 'is' : 'are'} never called in your session logs; disabling ${idle.length === 1 ? 'it' : 'them'} saves ~${saved.toLocaleString()} tokens per conversation.`);
    }
    const big = items.find((i) => i.kind === 'instructions' && i.tokens > 3000);
    if (big) suggestions.push(`${big.name} alone is ~${big.tokens.toLocaleString()} tokens and is sent with every message; move rarely-needed parts into a skill.`);
    const heavy = items.find((i) => i.kind === 'mcp-server' && i.tokens > 5000);
    if (heavy) suggestions.push(`${heavy.name} exposes ~${heavy.tokens.toLocaleString()} tokens of tool descriptions; if you only use a few of its tools, disable the rest.`);
    out.push({ client: g.client, project: g.project ? path.resolve(g.project) : undefined, total, items, suggestions });
  }
  return out.sort((x, y) => y.total - x.total);
}
