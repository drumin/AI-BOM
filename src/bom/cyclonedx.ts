import { randomUUID } from 'node:crypto';
import type { Asset, Inventory, PackageRef } from '../types.js';

/**
 * Export an Inventory as a CycloneDX 1.6 JSON BOM so it can be consumed by
 * standard SBOM/AI-BOM tooling (Dependency-Track, OWASP tools, etc.).
 *
 * - local assets -> components (MCP packages carry a purl)
 * - remote MCP servers -> services (with endpoints)
 * - plugin/extension bundling -> dependencies
 * - findings -> vulnerabilities (source "ai-bom", one per rule hit)
 */

function purl(p: PackageRef): string | undefined {
  const v = p.version ? `@${encodeURIComponent(p.version)}` : '';
  if (p.ecosystem === 'npm') {
    const name = p.name.startsWith('@') ? `%40${p.name.slice(1)}` : p.name;
    return `pkg:npm/${name}${v}`;
  }
  if (p.ecosystem === 'pypi') {
    if (/^(git\+|https?:)/.test(p.name)) return undefined;
    return `pkg:pypi/${p.name.toLowerCase().replace(/_/g, '-')}${v}`;
  }
  if (p.ecosystem === 'docker') {
    const [ns, ...rest] = p.name.split('/');
    const hasRegistry = rest.length > 0 && (ns.includes('.') || ns.includes(':'));
    const name = hasRegistry ? rest.join('/') : p.name;
    const q = hasRegistry ? `?repository_url=${encodeURIComponent(ns)}` : '';
    return `pkg:docker/${name}${v}${q}`;
  }
  return undefined;
}

function props(a: Asset): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = [
    { name: 'ai-bom:kind', value: a.kind },
    { name: 'ai-bom:origin', value: a.origin },
  ];
  const clients = [...new Set(a.occurrences.map((o) => o.client))];
  for (const c of clients) out.push({ name: 'ai-bom:client', value: c });
  for (const o of a.occurrences) out.push({ name: 'ai-bom:source', value: `${o.scope}:${o.source}` });
  if (a.mcp) {
    out.push({ name: 'ai-bom:mcp:transport', value: a.mcp.transport });
    if (a.mcp.command) out.push({ name: 'ai-bom:mcp:command', value: [a.mcp.command, ...(a.mcp.args ?? [])].join(' ') });
    if (a.mcp.env) out.push({ name: 'ai-bom:mcp:env', value: Object.keys(a.mcp.env).join(',') });
  }
  if (a.hook) {
    out.push({ name: 'ai-bom:hook:event', value: a.hook.event });
    out.push({ name: 'ai-bom:hook:command', value: a.hook.command });
  }
  if (a.risk) out.push({ name: 'ai-bom:risk', value: a.risk });
  return out;
}

const isRemote = (a: Asset) => (a.kind === 'mcp-server' && !!a.mcp?.url && !a.mcp.command) || a.kind === 'connector';

export function toCycloneDX(inv: Inventory): Record<string, unknown> {
  const components = inv.assets
    .filter((a) => !isRemote(a))
    .map((a) => {
      const pkg = a.mcp?.package;
      const type = pkg?.ecosystem === 'docker' ? 'container' : ['mcp-server', 'plugin', 'extension'].includes(a.kind) ? 'application' : 'file';
      const c: Record<string, unknown> = {
        type,
        'bom-ref': a.id,
        name: pkg && pkg.ecosystem !== 'binary' && pkg.ecosystem !== 'local' ? pkg.name : a.name,
        properties: props(a),
      };
      const version = pkg?.version ?? a.skill?.version;
      if (version) c.version = version;
      const p = pkg && purl(pkg);
      if (p) c.purl = p;
      if (a.skill?.description) c.description = a.skill.description;
      if (a.skill?.author) c.author = a.skill.author;
      if (pkg && c.name !== a.name) c.properties = [...(c.properties as object[]), { name: 'ai-bom:configured-name', value: a.name }];
      return c;
    });

  const services = inv.assets.filter(isRemote).map((a) =>
    a.connector
      ? {
          'bom-ref': a.id,
          name: a.name,
          provider: { name: a.connector.platform },
          authenticated: true,
          'x-trust-boundary': true,
          properties: [
            ...props(a),
            { name: 'ai-bom:connector:access', value: a.connector.access },
            ...(a.connector.reviewedAt ? [{ name: 'ai-bom:connector:reviewed', value: a.connector.reviewedAt }] : []),
          ],
        }
      : {
          'bom-ref': a.id,
          name: a.name,
          endpoints: [a.mcp!.url!],
          authenticated: !!a.mcp!.headers && Object.keys(a.mcp!.headers).length > 0 ? true : undefined,
          'x-trust-boundary': true,
          properties: props(a),
        },
  );

  const dependencies = inv.assets.filter((a) => a.children?.length).map((a) => ({ ref: a.id, dependsOn: a.children }));

  const vulnerabilities = inv.findings
    .filter((f) => f.assetId)
    .map((f) => ({
      'bom-ref': `finding:${f.id}`,
      // Advisory findings carry the real CVE/OSV id; configuration findings use the rule id.
      id: f.advisory ?? f.ruleId,
      source: { name: f.ruleId.startsWith('VULN-') && f.references?.some((u) => u.includes('osv.dev/vulnerability')) ? 'OSV' : 'ai-bom' },
      advisories: f.references?.map((url) => ({ url })),
      ratings: [{ source: { name: 'ai-bom' }, severity: f.severity, method: 'other' }],
      description: `${f.title}. ${f.description}`,
      recommendation: f.remediation,
      detail: [f.location, f.evidence].filter(Boolean).join(' — ') || undefined,
      properties: [...(f.owasp ?? []).map((o) => ({ name: 'ai-bom:owasp', value: o })), ...(f.atlas ?? []).map((a) => ({ name: 'ai-bom:mitre-atlas', value: a }))],
      affects: [{ ref: f.assetId }],
    }));

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: inv.scannedAt,
      tools: { components: [{ type: 'application', name: inv.tool.name, version: inv.tool.version }] },
      component: { type: 'device', 'bom-ref': 'host', name: inv.host.hostname },
      properties: inv.clients.map((c) => ({ name: 'ai-bom:client-detected', value: c.name })),
    },
    components,
    services,
    dependencies,
    vulnerabilities,
  };
}
