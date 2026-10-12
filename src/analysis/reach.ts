import path from 'node:path';
import type { Collector } from '../collector.js';
import type { Asset, ClientId, Reach } from '../types.js';
import type { Findings } from '../checks/index.js';
import { isObject } from '../util/fs.js';
import { classifySecret } from '../util/secrets.js';

/**
 * Blast radius and dangerous combinations.
 *
 * Each MCP server / connector gets a "what it can reach" profile. Then every
 * agent (a client, plus each project's extra config) is checked for the
 * "lethal trifecta": something that reads your private data, something that
 * feeds it content written by others, and something that can send data out.
 * Any one alone is fine; together, a single prompt injection can leak data.
 */

type Trait = Reach['traits'][number];

const ACCOUNTS: [RegExp, string][] = [
  [/github/, 'GitHub'], [/gitlab/, 'GitLab'], [/slack/, 'Slack'], [/gmail|google[-_ ]?mail/, 'Gmail'], [/drive|gdrive/, 'Google Drive'],
  [/calendar/, 'Calendar'], [/notion/, 'Notion'], [/linear/, 'Linear'], [/jira|atlassian|confluence/, 'Atlassian'], [/stripe/, 'Stripe'],
  [/supabase/, 'Supabase'], [/postgres|pg\b/, 'PostgreSQL'], [/mysql|mariadb/, 'MySQL'], [/mongo/, 'MongoDB'], [/sqlite/, 'SQLite'], [/redis/, 'Redis'],
  [/aws|bedrock|s3\b/, 'AWS'], [/cloudflare/, 'Cloudflare'], [/sentry/, 'Sentry'], [/figma/, 'Figma'], [/vercel/, 'Vercel'], [/outlook|office|microsoft|onedrive|sharepoint|teams/, 'Microsoft 365'],
  [/dropbox/, 'Dropbox'], [/discord/, 'Discord'], [/telegram/, 'Telegram'], [/whatsapp/, 'WhatsApp'], [/hubspot/, 'HubSpot'], [/salesforce/, 'Salesforce'], [/asana/, 'Asana'], [/trello/, 'Trello'],
];
const PRIVATE_ACCOUNT = new Set(['GitHub', 'GitLab', 'Slack', 'Gmail', 'Google Drive', 'Calendar', 'Notion', 'Linear', 'Atlassian', 'Stripe', 'Supabase', 'PostgreSQL', 'MySQL', 'MongoDB', 'SQLite', 'Redis', 'AWS', 'Microsoft 365', 'Dropbox', 'Discord', 'Telegram', 'WhatsApp', 'HubSpot', 'Salesforce', 'Asana', 'Trello', 'Sentry', 'Figma']);
/** Services where content is written by other people (issues, emails, messages). */
const UNTRUSTED_ACCOUNT = new Set(['GitHub', 'GitLab', 'Slack', 'Gmail', 'Linear', 'Atlassian', 'Discord', 'Telegram', 'WhatsApp', 'Microsoft 365', 'Notion', 'Sentry']);
/** Local data stores: private data, but not a way to send anything off the machine. */
const LOCAL_STORE = new Set(['SQLite', 'PostgreSQL', 'MySQL', 'MongoDB', 'Redis']);
const WEB = /fetch|browser|puppeteer|playwright|firecrawl|exa\b|brave|search|tavily|scrape|crawl|\bweb\b|reddit|twitter|youtube|rss|perplexity|context7|docs|mcp-remote/;
const SHELL = /shell|terminal|desktop-commander|iterm|\bexec\b|command|bash|docker|kubectl|ssh|code-runner|sandbox/;
const FS = /filesystem|file-?system|\bfs\b|files/;

function textOf(a: Asset): string {
  return [a.name, a.mcp?.package?.name, a.mcp?.command && path.basename(a.mcp.command), a.connector?.platform, ...(a.mcp?.tools ?? []).map((t) => t.name)].filter(Boolean).join(' ').toLowerCase();
}

function hostOf(u?: string): string | undefined {
  try {
    return u ? new URL(u).host : undefined;
  } catch {
    return undefined;
  }
}

export function reachOf(a: Asset, home: string): Reach | undefined {
  if (a.kind !== 'mcp-server' && a.kind !== 'connector' && a.kind !== 'browser-extension') return undefined;
  const text = textOf(a);
  const r: Reach = { files: [], network: [], credentials: [], commands: false, accounts: [], traits: [], suggestions: [] };
  const traits = new Set<Trait>();
  for (const [re, name] of ACCOUNTS) if (re.test(text)) r.accounts.push(name);
  if (a.kind === 'connector') {
    // Your account's data is private; mail, chat, issues and shared docs also carry text written by others,
    // and the same services can send it on (a message, an email, a public issue).
    const service = r.accounts.find((x) => UNTRUSTED_ACCOUNT.has(x) || x === 'Google Drive' || x === 'Calendar');
    r.accounts = [a.name];
    traits.add('private-data');
    if (service) traits.add('untrusted-input');
    if (service && a.connector?.access !== 'read') traits.add('exfiltration');
  }
  if (a.kind === 'browser-extension' && a.browserExtension) {
    if (a.browserExtension.allSites) r.files.push('every page you visit');
    r.network.push('its own AI service');
    traits.add('private-data');
    traits.add('untrusted-input');
    traits.add('exfiltration');
  }
  const m = a.mcp;
  if (m) {
    // Paths handed to the server on the command line.
    for (const arg of m.args ?? []) {
      const p = arg.replace(/^~(?=\/|$)/, home);
      if (p === '/' || p === home || p === '/Users' || p === '/home') r.files.push(p === '/' ? 'the whole disk' : 'your whole home folder');
      else if (path.isAbsolute(p) && !/node_modules|\.npm|\.cache|\.(js|mjs|py|ts)$/.test(p) && !p.includes('ai-bom-secrets')) r.files.push(arg);
    }
    for (const u of [m.url, m.remoteUrl]) {
      const h = hostOf(u);
      if (h) r.network.push(h);
    }
    for (const t of m.tools ?? []) for (const h of t.behavior?.hosts ?? []) if (!r.network.includes(h)) r.network.push(h);
    const envs = { ...m.env };
    for (const [k, v] of Object.entries(envs)) if (classifySecret(k, v) || /KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL/i.test(k)) r.credentials.push(k);
    for (const k of m.keychainEnv ?? []) r.credentials.push(`${k} (keychain)`);
    r.commands = SHELL.test(text) || (m.tools ?? []).some((t) => t.behavior?.capabilities.includes('subprocess'));
    if (r.files.length || FS.test(text)) traits.add('private-data');
    if (r.accounts.some((x) => PRIVATE_ACCOUNT.has(x))) traits.add('private-data');
    if ((m.tools ?? []).some((t) => t.behavior?.credentialPaths.length)) traits.add('private-data');
    if (WEB.test(text) || r.accounts.some((x) => UNTRUSTED_ACCOUNT.has(x))) traits.add('untrusted-input');
    if (m.url || m.remoteUrl || r.network.length || WEB.test(text) || r.accounts.some((x) => !LOCAL_STORE.has(x))) traits.add('exfiltration');
    if (r.commands) traits.add('shell');
  }
  r.traits = [...traits];
  r.files = [...new Set(r.files)].slice(0, 10);
  r.network = r.network.slice(0, 12);

  // Least-privilege suggestions.
  if (r.files.some((f) => f.startsWith('the whole') || f.startsWith('your whole'))) r.suggestions.push('Give it only the project folders it needs instead of your whole disk or home folder.');
  if (m?.env && Object.entries(m.env).some(([k, v]) => classifySecret(k, v))) r.suggestions.push('Move its secrets into the keychain (ai-bom fix → Move secret to Keychain).');
  if (m?.package && !m.package.pinned && (m.package.ecosystem === 'npm' || m.package.ecosystem === 'pypi')) r.suggestions.push('Pin an exact version so an update can\'t change what runs.');
  if (r.commands) r.suggestions.push('Keep approval prompts on for its tools: it can run commands.');
  const used = a.usage?.tools ? Object.keys(a.usage.tools) : undefined;
  const all = m?.tools?.map((t) => t.name) ?? [];
  if (used && all.length > used.length + 1 && a.occurrences.some((o) => o.client === 'claude-code')) {
    const unused = all.filter((t) => !used.includes(t));
    r.suggestions.push(`You used ${used.length} of its ${all.length} tools. Block the rest in Claude Code with permissions.deny, e.g. "mcp__${a.occurrences.find((o) => o.client === 'claude-code')!.name}__${unused[0]}".`);
  }
  if (a.kind === 'connector' && a.connector?.access === 'read-write') r.suggestions.push('If you only need to read, reconnect it with read-only access.');
  if (a.kind === 'browser-extension' && a.browserExtension?.allSites) r.suggestions.push('Set site access to "On click" in the browser\'s extension settings.');
  return r;
}

const LEG: Record<Trait, string> = { 'private-data': 'reads private data', 'untrusted-input': 'reads content others wrote', exfiltration: 'can send data out', shell: 'runs commands' };

export function analyzeReach(col: Collector, f: Findings): void {
  const home = col.ctx.home;
  for (const a of col.assets.values()) {
    const r = reachOf(a, home);
    if (r) a.reach = r;
  }

  // Agents that run without approval prompts make every combination worse.
  const bypass = new Set<ClientId>();
  for (const d of col.settings) {
    const perms = isObject(d.data.permissions) ? d.data.permissions : undefined;
    if (perms?.defaultMode === 'bypassPermissions' || d.data.skipDangerousModePermissionPrompt === true) bypass.add(d.client);
  }

  // Group what loads together: a client's user-level assets, plus each project's extra ones.
  const groups = new Map<string, { client: ClientId; project?: string; assets: Set<Asset> }>();
  const group = (client: ClientId, project?: string) => {
    const key = `${client}|${project ?? ''}`;
    if (!groups.has(key)) groups.set(key, { client, project, assets: new Set() });
    return groups.get(key)!;
  };
  for (const a of col.assets.values()) {
    if (!a.reach?.traits.length || a.kind === 'browser-extension') continue;
    for (const o of a.occurrences) {
      if (o.enabled === false || o.note?.startsWith('Not approved') || o.note?.startsWith('Rejected')) continue;
      const client: ClientId = a.kind === 'connector' && a.connector?.detectedIn === 'Claude Code' ? 'claude-code' : o.client;
      if (client.startsWith('cloud:')) continue;
      const g = group(client, o.scope === 'project' || o.scope === 'local' ? o.project : undefined);
      g.assets.add(a);
    }
  }
  const clientName = (id: ClientId) => col.clients.get(id)?.name ?? id;
  const flagged = new Set<string>();
  for (const g of [...groups.values()].sort((x, y) => (x.project ? 1 : 0) - (y.project ? 1 : 0))) {
    const members = new Set(g.assets);
    if (g.project) for (const a of groups.get(`${g.client}|`)?.assets ?? []) members.add(a);
    const by = (t: Trait) => [...members].filter((a) => a.reach!.traits.includes(t));
    const priv = by('private-data');
    const untrusted = by('untrusted-input');
    const out = by('exfiltration');
    const shell = by('shell');
    const where = `${clientName(g.client)}${g.project ? ` (${path.basename(g.project)})` : ''}`;
    const names = (xs: Asset[]) => [...new Set(xs.map((x) => x.name))].slice(0, 4).join(', ');
    const noPrompts = bypass.has(g.client);
    if (priv.length && untrusted.length && out.length) {
      const legs = new Set([...priv, ...untrusted, ...out].map((a) => a.id));
      const sig = [...legs].sort().join(',');
      if (!flagged.has(`trifecta|${g.client}|${sig}`)) {
        flagged.add(`trifecta|${g.client}|${sig}`);
        f.add('COMBO-LETHAL-TRIFECTA', noPrompts ? 'high' : 'medium', {
          title: `Lethal trifecta in ${where}`,
          location: [...members][0]?.occurrences[0]?.source,
          evidence: `${LEG['private-data']}: ${names(priv)} · ${LEG['untrusted-input']}: ${names(untrusted)} · ${LEG.exfiltration}: ${names(out)}`,
          detail: noPrompts ? 'Approval prompts are turned off for this agent, so nothing stops the chain.' : undefined,
          related: [...legs],
        });
      }
    }
    if ((shell.length || noPrompts) && untrusted.length) {
      const legs = [...new Set([...shell, ...untrusted].map((a) => a.id))];
      const sig = `shell|${g.client}|${legs.sort().join(',')}`;
      if (!flagged.has(sig)) {
        flagged.add(sig);
        f.add('COMBO-SHELL-UNTRUSTED', noPrompts ? 'high' : 'medium', {
          title: `Command execution + untrusted content in ${where}`,
          location: [...members][0]?.occurrences[0]?.source,
          evidence: `${LEG.shell}: ${shell.length ? names(shell) : 'built-in shell with prompts off'} · ${LEG['untrusted-input']}: ${names(untrusted)}`,
          related: legs,
        });
      }
    }
  }
}
