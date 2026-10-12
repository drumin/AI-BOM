import { beforeAll, describe, expect, it } from 'vitest';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync } from 'node:fs';
import { scan } from '../src/scan.js';
import { RULES } from '../src/checks/index.js';
import { ATLAS_TACTICS, ATLAS_TECHNIQUES, RULE_ATLAS, atlasView } from '../src/frameworks/atlas.js';
import { ATTEST_MAX_AGE_DAYS, attest, baselines, evaluate, FRAMEWORKS, gatherEvidence, type FrameworkId } from '../src/frameworks/baselines.js';
import { toHtml } from '../src/reports/html.js';
import { toMarkdown } from '../src/reports/markdown.js';
import { exportState, importState } from '../src/state.js';
import type { Inventory } from '../src/types.js';
import { buildFixture, type Fixture } from './fixture.js';

let fx: Fixture;
let inv: Inventory;
beforeAll(async () => {
  process.env.AI_BOM_HOME = mkdtempSync(path.join(os.tmpdir(), 'ai-bom-base-'));
  fx = buildFixture();
  inv = await scan({ home: fx.home, platform: 'darwin', systemRoot: fx.systemRoot, projects: [fx.project, fx.scratch], connectorsFile: fx.connectorsFile });
});

describe('MITRE ATLAS mapping', () => {
  it('maps every rule, only to techniques and tactics that exist in the bundled ATLAS data', () => {
    for (const id of Object.keys(RULES)) expect(RULE_ATLAS, id).toHaveProperty(id);
    const tactics = new Set(ATLAS_TACTICS.map((t) => t.id));
    for (const [rule, list] of Object.entries(RULE_ATLAS)) {
      for (const t of list) {
        expect(ATLAS_TECHNIQUES[t], `${rule} → ${t}`).toBeDefined();
        for (const ta of ATLAS_TECHNIQUES[t].tactics) expect(tactics.has(ta)).toBe(true);
      }
    }
  });

  it('labels findings and arranges active ones on the matrix', () => {
    const poison = inv.findings.find((f) => f.ruleId === 'TOOL-BEHAVIOR-MISMATCH')!;
    expect(poison.atlas).toContain('AML.T0110 AI Agent Tool Poisoning');
    const view = atlasView(inv);
    const persistence = view.tactics.find((t) => t.name === 'Persistence')!;
    const tech = persistence.techniques.find((t) => t.id === 'AML.T0110')!;
    expect(tech.findings).toContain(poison.id);
    expect(tech.worst).toBeDefined();
    expect(view.seen).toBeGreaterThan(5);
    expect(view.checked).toBe(new Set(Object.values(RULE_ATLAS).flat()).size);
    // Muted findings drop out.
    const muted = atlasView({ findings: inv.findings.map((f) => ({ ...f, muted: { status: 'accepted' as const, at: '' } })) });
    expect(muted.seen).toBe(0);
  });
});

describe('NIST AI RMF and ISO/IEC 42001', () => {
  it('derives control status from scan evidence', async () => {
    const r = await baselines(inv);
    const nist = (id: string) => r['nist-ai-rmf'].controls.find((c) => c.id === id)!;
    const iso = (id: string) => r['iso-42001'].controls.find((c) => c.id === id)!;
    expect(nist('GOVERN 1.6').status).toBe('met');
    expect(nist('MANAGE 1.3').status).toBe('gap');
    expect(nist('MANAGE 1.3').findings.length).toBeGreaterThan(0);
    expect(nist('MEASURE 2.10').status).toBe('gap');
    expect(nist('MANAGE 3.2').status).toBe('partial');
    expect(nist('MANAGE 3.2').findings.length).toBe(1);
    expect(nist('MEASURE 2.7').status).toBe('partial');
    expect(nist('MANAGE 4.3').status).toBe('na');
    expect(nist('GOVERN 6.1').status).toBe('manual');
    expect(iso('A.9.4').status).toBe('gap');
    expect(iso('A.6.2.8').status).toBe('met');
    for (const rep of Object.values(r)) {
      const sum = Object.values(rep.counts).reduce((a, b) => a + b, 0);
      expect(sum).toBe(rep.controls.length);
      expect(rep.coverage).toBeGreaterThanOrEqual(0);
      expect(rep.coverage).toBeLessThanOrEqual(100);
    }
  });

  it('meets a control once its findings are dealt with', async () => {
    const e = await gatherEvidence(inv);
    const clean = { ...e, inv: { ...inv, findings: inv.findings.map((f) => ({ ...f, muted: { status: 'accepted' as const, reason: 'reviewed', at: '' } })) } };
    expect(evaluate('nist-ai-rmf', clean).controls.find((c) => c.id === 'MANAGE 1.3')!.status).toBe('met');
    expect(evaluate('nist-ai-rmf', clean).controls.find((c) => c.id === 'MANAGE 1.4')!.status).toBe('met');
  });

  it('records your answers for controls a scan cannot check, and keeps them in state backups', async () => {
    const { id } = await attest('nist-ai-rmf', 'govern 6.1', 'done', 'New servers only via ai-bom add, pinned');
    expect(id).toBe('GOVERN 6.1');
    await attest('iso-42001', 'A.3.2', 'na');
    await expect(attest('nist-ai-rmf', 'MAP 4.1', 'done')).rejects.toThrow(/checked from your scan/);
    await expect(attest('iso-42001', 'Z.9', 'done')).rejects.toThrow(/Unknown control/);
    const r = await baselines(inv);
    const g61 = r['nist-ai-rmf'].controls.find((c) => c.id === 'GOVERN 6.1')!;
    expect(g61.status).toBe('attested');
    expect(g61.evidence).toEqual(['New servers only via ai-bom add, pinned']);
    expect(r['iso-42001'].controls.find((c) => c.id === 'A.3.2')!.status).toBe('na');

    const file = path.join(process.env.AI_BOM_HOME!, 'backup.json');
    expect(await exportState(file)).toContain('attestations.json');
    await attest('nist-ai-rmf', 'GOVERN 6.1', undefined);
    expect((await baselines(inv))['nist-ai-rmf'].controls.find((c) => c.id === 'GOVERN 6.1')!.status).toBe('manual');
    await importState(file);
    expect((await baselines(inv))['nist-ai-rmf'].controls.find((c) => c.id === 'GOVERN 6.1')!.status).toBe('attested');
  });

  it('treats a confirmation older than 90 days as unanswered, keeping the note, until you re-confirm', async () => {
    await attest('nist-ai-rmf', 'GOVERN 6.2', 'done', 'Runbook in the wiki');
    const e = await gatherEvidence(inv);
    const find = (now: Date) => evaluate('nist-ai-rmf', { ...e, now }).controls.find((c) => c.id === 'GOVERN 6.2')!;
    expect(find(e.now).status).toBe('attested');
    const later = new Date(e.now.getTime() + (ATTEST_MAX_AGE_DAYS + 1) * 86_400_000);
    const stale = find(later);
    expect(stale.status).toBe('manual');
    expect(stale.stale).toBe(true);
    expect(stale.evidence).toEqual(['Runbook in the wiki']);
    expect(evaluate('nist-ai-rmf', { ...e, now: later }).coverage).toBeLessThan(evaluate('nist-ai-rmf', e).coverage);
    await attest('nist-ai-rmf', 'GOVERN 6.2', undefined);
  });

  it('puts a Baselines section in the Markdown and HTML reports when given the results', async () => {
    const r = await baselines(inv);
    expect(toMarkdown(inv)).not.toContain('## Baselines');
    const md = toMarkdown(inv, undefined, r);
    expect(md).toContain('## Baselines');
    expect(md).toContain('NIST AI RMF');
    expect(md).toContain('what to work on');
    const html = toHtml(inv, undefined, r);
    expect(html).toContain('<h2>Baselines</h2>');
    expect(html).toContain('not a certification');
  });

  it('only checks controls with evidence; the rest are questions for you', () => {
    for (const fw of Object.keys(FRAMEWORKS) as FrameworkId[]) {
      for (const c of FRAMEWORKS[fw].controls) expect(Boolean(c.check) || Boolean(c.hint), `${fw} ${c.id}`).toBe(true);
    }
  });
});
