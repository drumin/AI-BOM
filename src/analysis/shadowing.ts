import type { Collector } from '../collector.js';
import type { Asset } from '../types.js';
import type { Findings } from '../checks/index.js';

/**
 * Tool shadowing: two MCP servers expose a tool with the same name, so when the agent asks for that
 * tool by name it can end up calling the wrong server. An attacker's server only has to reuse a
 * trusted tool's name ("read_file", "create_issue") to be called in its place.
 *
 * A server is treated as trusted when it is listed in the official MCP Registry or is one of the
 * reference servers (`@modelcontextprotocol/*`). Needs tool lists, so it only covers servers whose
 * tools are known (a manifest, readable source, or a live inspection).
 */
const isTrusted = (a: Asset) => !!a.trust?.officialRegistry || /^@modelcontextprotocol\//.test(a.mcp?.package?.name ?? '');

export function checkShadowing(col: Collector, f: Findings): void {
  const servers = [...col.assets.values()].filter((a) => a.kind === 'mcp-server' && a.mcp?.tools?.length);
  const owners = new Map<string, Asset[]>();
  for (const a of servers) {
    for (const name of new Set(a.mcp!.tools!.map((t) => t.name.toLowerCase()))) owners.set(name, [...(owners.get(name) ?? []), a]);
  }
  const perAsset = new Map<string, { asset: Asset; names: { name: string; others: Asset[]; trusted: Asset[] }[] }>();
  for (const [name, list] of owners) {
    if (list.length < 2) continue;
    for (const a of list) {
      if (isTrusted(a)) continue; // the trusted one is the one being imitated, not the imitator
      const others = list.filter((x) => x !== a);
      const entry = perAsset.get(a.id) ?? { asset: a, names: [] };
      entry.names.push({ name, others, trusted: others.filter(isTrusted) });
      perAsset.set(a.id, entry);
    }
  }
  for (const { asset: a, names } of perAsset.values()) {
    const imitates = names.filter((n) => n.trusted.length);
    const shown = (imitates.length ? imitates : names).slice(0, 4);
    const label = (n: (typeof names)[number]) => `${n.name} (also in ${(n.trusted.length ? n.trusted : n.others).slice(0, 2).map((x) => x.name).join(', ')})`;
    f.add('MCP-TOOL-SHADOWING', imitates.length ? 'high' : 'low', {
      asset: a,
      location: a.occurrences[0]?.source,
      title: imitates.length ? `${a.name} reuses tool names from a trusted server` : `${a.name} shares tool names with another server`,
      evidence: shown.map(label).join('; '),
      detail: imitates.length
        ? `When the agent asks for ${imitates[0].name} it can end up calling ${a.name} instead of ${imitates[0].trusted[0].name}. That is how a look-alike server intercepts calls meant for a trusted one.`
        : 'Both servers answer to the same tool name, so the agent may pick either one.',
      related: [...new Set(shown.flatMap((n) => n.others.map((o) => o.id)))],
    });
  }
}
