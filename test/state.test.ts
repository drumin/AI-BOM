import { beforeEach, describe, expect, it } from 'vitest';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { scan } from '../src/scan.js';
import { setTriage, loadTriage, defaultTriageFile } from '../src/triage.js';
import { describeState, exportState, importState, loadPreferences, readScans, savePreferences, scanLogFile } from '../src/state.js';
import { tilde, untildeDeep } from '../src/util/paths.js';
import { buildFixture } from './fixture.js';

beforeEach(() => {
  process.env.AI_BOM_HOME = mkdtempSync(path.join(os.tmpdir(), 'ai-bom-st-'));
});

describe('persistent state in the .ai-bom folder', () => {
  it('records a counts-only summary of every scan', async () => {
    const fx = buildFixture();
    const opts = { home: fx.home, platform: 'darwin' as const, systemRoot: fx.systemRoot, projects: [fx.project], triageFile: defaultTriageFile() };
    const first = await scan({ ...opts, recordAs: 'scan' });
    const f = first.findings.find((x) => x.ruleId === 'MODEL-PICKLE')!;
    await setTriage(defaultTriageFile(), f.id, { status: 'accepted', reason: 'fine' });
    await scan({ ...opts, recordAs: 'dashboard' });
    const scans = await readScans();
    expect(scans.map((s) => s.source)).toEqual(['dashboard', 'scan']);
    expect(scans[0].muted).toBe(1);
    expect(scans[1].assets).toBe(first.assets.length);
    const raw = readFileSync(scanLogFile(), 'utf8');
    expect(raw).not.toContain(fx.home);
    expect(raw).not.toContain('bert-base');
    expect(statSync(scanLogFile()).mode & 0o077).toBe(0);
  });

  it('keeps validated dashboard preferences', async () => {
    await savePreferences({ theme: 'dark', mapView: 'network', evil: 'x', findingsView: 'nope' });
    expect(await loadPreferences()).toEqual({ theme: 'dark', mapView: 'network' });
    await savePreferences({ baselineView: 'atlas', baselineFilter: 'answer' });
    expect(await loadPreferences()).toMatchObject({ baselineView: 'atlas', baselineFilter: 'answer' });
    await savePreferences({ welcomed: 'yes' });
    expect((await loadPreferences()).welcomed).toBe('yes');
    await savePreferences({ welcomed: 'maybe' });
    expect((await loadPreferences()).welcomed).toBe('yes');
    await savePreferences({ baselineView: 'tarot', baselineFilter: 'x' });
    expect(await loadPreferences()).toMatchObject({ baselineView: 'atlas', baselineFilter: 'answer' });
  });

  it('exports and merges triage decisions, connectors and preferences', async () => {
    await setTriage(defaultTriageFile(), 'aaaaaaaaaaaa', { status: 'false-positive', reason: 'test key' });
    await savePreferences({ theme: 'light' });
    const backup = path.join(mkdtempSync(path.join(os.tmpdir(), 'ai-bom-bk-')), 'state.json');
    expect(await exportState(backup)).toEqual(['triage.json', 'preferences.json']);

    process.env.AI_BOM_HOME = mkdtempSync(path.join(os.tmpdir(), 'ai-bom-st2-'));
    await setTriage(defaultTriageFile(), 'bbbbbbbbbbbb', { status: 'accepted' });
    expect(await importState(backup)).toEqual(['triage.json', 'preferences.json']);
    expect(Object.keys(await loadTriage()).sort()).toEqual(['aaaaaaaaaaaa', 'bbbbbbbbbbbb']);
    expect((await describeState()).entries.map((e) => e.name)).toEqual(expect.arrayContaining(['triage.json', 'preferences.json']));
  });

  it('drops malformed triage entries from an imported backup', async () => {
    const backup = path.join(process.env.AI_BOM_HOME!, 'bad.json');
    const good = { status: 'accepted', at: '2026-01-01T00:00:00.000Z' };
    writeFileSync(backup, JSON.stringify({ kind: 'ai-bom-state', version: 1, exportedAt: '', files: { 'triage.json': { version: 1, entries: { cccccccccccc: good, 'not-an-id': good, dddddddddddd: { status: 'whatever' }, eeeeeeeeeeee: { status: 'snoozed', until: 'soon' } } } } }));
    await importState(backup, true);
    expect(Object.keys(await loadTriage())).toEqual(['cccccccccccc']);
  });
});

describe('home paths', () => {
  it('shortens on a folder boundary only, and expands both separators', () => {
    expect(tilde('/Users/dru/x', '/Users/dru')).toBe('~/x');
    expect(tilde('/Users/drumin/x', '/Users/dru')).toBe('/Users/drumin/x');
    expect(tilde('/Users/dru', '/Users/dru')).toBe('~');
    expect(untildeDeep({ a: ['~/x', '~\\y', 'a~/b'] }, 'C:\\Users\\me')).toEqual({ a: ['C:\\Users\\me/x', 'C:\\Users\\me\\y', 'a~/b'] });
  });
});
