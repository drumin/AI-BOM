import path from 'node:path';
import type { Inventory } from './types.js';
import { applyChanges, type Op, type Snapshot } from './fix/index.js';
import { getAt, hasAt, readJsonDoc } from './fix/jsonedit.js';
import { activityMarkdown, readActivity } from './activity.js';
import { dataDir, writeAtomic } from './util/store.js';

/**
 * "I think something went wrong." One step that:
 *  1. pauses every MCP server (and every hook that sends data out) in the
 *     JSON configs it can edit, as ONE snapshot, so `ai-bom undo` restores all;
 *  2. lists the keys those agents could reach, with where to rotate each;
 *  3. writes a report with the recent activity timeline to ~/.ai-bom/incidents/.
 */

export const ROTATE: [RegExp, string, string][] = [
  [/openai|sk-proj/i, 'OpenAI', 'https://platform.openai.com/api-keys'],
  [/anthropic|claude|sk-ant/i, 'Anthropic', 'https://console.anthropic.com/settings/keys'],
  [/github|ghp_|github_pat/i, 'GitHub', 'https://github.com/settings/tokens'],
  [/gitlab|glpat/i, 'GitLab', 'https://gitlab.com/-/user_settings/personal_access_tokens'],
  [/slack|xox/i, 'Slack', 'https://api.slack.com/apps'],
  [/gemini|google_generative/i, 'Google Gemini', 'https://aistudio.google.com/app/apikey'],
  [/google|gcp|AIza/i, 'Google Cloud', 'https://console.cloud.google.com/apis/credentials'],
  [/aws|AKIA|ASIA/i, 'AWS', 'https://console.aws.amazon.com/iam/home#/security_credentials'],
  [/hugging|hf_/i, 'Hugging Face', 'https://huggingface.co/settings/tokens'],
  [/stripe|sk_live|rk_live/i, 'Stripe', 'https://dashboard.stripe.com/apikeys'],
  [/notion|ntn_|secret_/i, 'Notion', 'https://www.notion.so/my-integrations'],
  [/linear|lin_api/i, 'Linear', 'https://linear.app/settings/account/security'],
  [/groq/i, 'Groq', 'https://console.groq.com/keys'],
  [/mistral/i, 'Mistral', 'https://console.mistral.ai/api-keys'],
  [/openrouter/i, 'OpenRouter', 'https://openrouter.ai/settings/keys'],
  [/exa/i, 'Exa', 'https://dashboard.exa.ai/api-keys'],
  [/brave/i, 'Brave Search', 'https://api-dashboard.search.brave.com/app/keys'],
];

export interface KeyToRotate {
  label: string;
  provider?: string;
  url?: string;
  where: string[];
  why: string;
}

export interface IncidentPlan {
  paused: { assetId: string; name: string; kind: string; files: string[] }[];
  keys: KeyToRotate[];
  manual: string[];
  ops: Extract<Op, { type: 'json' }>[];
}

const expand = (home: string, p: string) => (p === '~' || p.startsWith('~/') ? path.join(home, p.slice(1)) : p);

function provider(text: string): { provider?: string; url?: string } {
  const hit = ROTATE.find(([re]) => re.test(text));
  return hit ? { provider: hit[1], url: hit[2] } : {};
}

export async function planIncident(inv: Inventory, home: string, keep: string[] = []): Promise<IncidentPlan> {
  const plan: IncidentPlan = { paused: [], keys: [], manual: [], ops: [] };
  const egress = new Set(inv.findings.filter((f) => f.ruleId === 'HOOK-DATA-EGRESS' && !f.muted).map((f) => f.assetId));
  const docs = new Map<string, unknown>();
  const doc = async (file: string) => {
    if (!docs.has(file)) docs.set(file, (await readJsonDoc(file)).data);
    return docs.get(file);
  };
  for (const a of inv.assets) {
    const target = a.kind === 'mcp-server' || (a.kind === 'hook' && egress.has(a.id));
    if (!target || keep.includes(a.name)) continue;
    const files: string[] = [];
    for (const o of a.occurrences) {
      if (!o.jsonPath || o.via || !/\.(json|jsonc)$/i.test(o.source)) {
        if (o.enabled !== false) plan.manual.push(o.via ? `${a.name}: comes with a plugin/extension (${o.source}); disable that plugin in its app.` : `${a.name}: remove it from ${o.source} by hand.`);
        continue;
      }
      const file = expand(home, o.source);
      let data: unknown;
      try {
        data = await doc(file);
      } catch {
        plan.manual.push(`${a.name}: could not read ${o.source}.`);
        continue;
      }
      if (!hasAt(data, o.jsonPath)) continue;
      plan.ops.push({ type: 'json', file, path: o.jsonPath, before: { present: true, value: getAt(data, o.jsonPath) }, after: { present: false }, array: typeof o.jsonPath[o.jsonPath.length - 1] === 'number' });
      files.push(o.source);
    }
    if (files.length) plan.paused.push({ assetId: a.id, name: a.name, kind: a.kind, files });
  }

  // Keys: in dotfiles/.env, in MCP/agent configs, and any seen leaving in a tool call.
  const add = (label: string, where: string, why: string, hint: string) => {
    const cur = plan.keys.find((k) => k.label === label);
    if (cur) {
      if (!cur.where.includes(where)) cur.where.push(where);
      return;
    }
    plan.keys.push({ label, ...provider(hint), where: [where], why });
  };
  for (const a of inv.assets.filter((x) => x.kind === 'api-key' && x.apiKey)) {
    for (const o of a.occurrences) add(`${a.apiKey!.provider} key (${a.apiKey!.masked})`, o.source, 'Readable by every program and agent you run.', `${a.apiKey!.provider} ${a.apiKey!.variable}`);
  }
  for (const f of inv.findings.filter((x) => !x.muted && ['MCP-SECRET', 'SETTINGS-SECRET', 'CONTENT-SECRET', 'TOOLCALL-SECRET-SENT'].includes(x.ruleId))) {
    const name = f.evidence?.split(/[=:]/)[0].trim() ?? f.title;
    const why = f.ruleId === 'TOOLCALL-SECRET-SENT' ? 'Was sent to an MCP tool.' : 'Stored in plain text where agents and tools can read it.';
    add(f.ruleId === 'TOOLCALL-SECRET-SENT' ? f.evidence ?? f.title : name, f.location ?? '', why, `${name} ${f.evidence ?? ''} ${f.description}`);
  }
  plan.keys.sort((x, y) => Number(y.why.startsWith('Was sent')) - Number(x.why.startsWith('Was sent')));
  return plan;
}

export async function applyIncident(inv: Inventory, home: string, dirs: { claudeDir: string }, opts: { keep?: string[]; days?: number; pause?: boolean }): Promise<{ snapshot?: Snapshot; report: string; plan: IncidentPlan }> {
  const plan = await planIncident(inv, home, opts.keep);
  const snapshot = opts.pause !== false && plan.ops.length ? await applyChanges(`Incident: paused ${plan.paused.length} server(s)/hook(s)`, 'remove-entry', plan.ops) : undefined;
  const activity = await readActivity({ claudeDir: dirs.claudeDir, home }, { days: opts.days ?? 7, sessions: 20 });
  const high = inv.findings.filter((f) => !f.muted && (f.severity === 'critical' || f.severity === 'high'));
  const md = [
    `# AI-BOM incident report`,
    '',
    `Created ${new Date().toISOString()} on ${inv.host.hostname}.`,
    '',
    '## What was paused',
    '',
    snapshot ? `Undo everything with: \`ai-bom undo ${snapshot.id}\`` : 'Nothing was paused.',
    '',
    ...plan.paused.map((p) => `- ${p.kind === 'hook' ? 'Hook' : 'MCP server'} **${p.name}** (${p.files.join(', ')})`),
    ...(plan.manual.length ? ['', '**Still to do by hand:**', '', ...plan.manual.map((m) => `- ${m}`)] : []),
    '',
    '## Keys to rotate',
    '',
    ...(plan.keys.length ? plan.keys.map((k) => `- **${k.label}** — ${k.why} Where: ${k.where.filter(Boolean).join(', ') || 'n/a'}.${k.url ? ` Rotate: ${k.url}` : ''}`) : ['No stored keys were found.']),
    '',
    `## High-risk findings (${high.length})`,
    '',
    ...high.map((f) => `- ${f.severity.toUpperCase()}: ${f.title}${f.evidence ? ` — \`${f.evidence.replace(/`/g, "'")}\`` : ''}`),
    '',
    `## Agent activity (last ${opts.days ?? 7} days)`,
    '',
    activity.length ? activityMarkdown(activity) : 'No session logs found.',
  ].join('\n');
  const report = path.join(dataDir(), 'incidents', `incident-${new Date().toISOString().replace(/[:.]/g, '-')}.md`);
  await writeAtomic(report, md);
  return { snapshot, report, plan };
}
