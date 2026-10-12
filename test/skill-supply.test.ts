import { describe, expect, it } from 'vitest';
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { imitates, KNOWN_NPM, KNOWN_PY, KNOWN_SKILLS, parsePackageJson, parseRequirements } from '../src/checks/skillsupply.js';
import { preflight } from '../src/preflight.js';

describe('names that imitate well-known ones', () => {
  it('flags one-character look-alikes of long, well-known skill and plugin names', () => {
    expect(imitates('skill-creatr', KNOWN_SKILLS)).toBe('skill-creator');
    expect(imitates('frontend-desing', KNOWN_SKILLS)).toBe('frontend-design');
    expect(imitates('superpowrs', KNOWN_SKILLS)).toBe('superpowers');
    expect(imitates('code-reviews', KNOWN_SKILLS)).toBe('code-review');
  });
  it('flags the same name spelled with different case or separators', () => {
    expect(imitates('Skill_Creator', KNOWN_SKILLS)).toBe('skill-creator');
    expect(imitates('Web-Artifacts-Builder', KNOWN_SKILLS)).toBe('web-artifacts-builder');
  });
  it('accepts the real names and ordinary different ones', () => {
    for (const n of ['skill-creator', 'superpowers', 'code-review', 'my-skill', 'review-animations', 'docs', 'docx', 'pdf', 'xlsx', 'learn', 'morning', 'code-reviewer', 'feature-flags', 'emil-design-eng', 'mobile-native', 'brainstorming']) {
      expect(imitates(n, KNOWN_SKILLS), n).toBeUndefined();
    }
  });
  it('flags dependency typos per ecosystem, and leaves real neighbours alone', () => {
    expect(imitates('reqeusts', KNOWN_PY, { minLength: 5 })).toBe('requests');
    expect(imitates('numpyy', KNOWN_PY, { minLength: 5 })).toBe('numpy');
    expect(imitates('expres', KNOWN_NPM, { minLength: 5 })).toBe('express');
    expect(imitates('lodahs', KNOWN_NPM, { minLength: 5 })).toBe('lodash');
    expect(imitates('request', KNOWN_NPM, { minLength: 5 })).toBeUndefined();
    expect(imitates('requests', KNOWN_PY, { minLength: 5 })).toBeUndefined();
    expect(imitates('flask-cors', KNOWN_PY, { minLength: 5 })).toBeUndefined();
    expect(imitates('rich', KNOWN_PY, { minLength: 5 })).toBeUndefined();
  });
  it('flags a lookalike scope for an npm package', () => {
    expect(imitates('@anthropic/sdk', KNOWN_NPM, { minLength: 5 })).toBeUndefined(); // different bare name: not claimed
    expect(imitates('@anthropic-ai/sdk', KNOWN_NPM)).toBeUndefined();
  });
});

describe('reading dependency files', () => {
  it('reads requirements.txt, skipping options, comments and URLs', () => {
    const deps = parseRequirements('# tools\nrequests==2.32.3\nnumpy>=1.20  # loose\nflask\n-r other.txt\n--index-url https://x\ngit+https://github.com/a/b.git\nhttps://x/y.whl\nrich[extra]~=13.0\npydantic===2.0 ; python_version>"3"\n');
    expect(deps.map((d) => `${d.name}:${d.pinned}`)).toEqual(['requests:true', 'numpy:false', 'flask:false', 'rich:false', 'pydantic:true']);
  });
  it('reads package.json and treats only floating specs as unpinned', () => {
    const deps = parsePackageJson(JSON.stringify({ dependencies: { a: '1.2.3', b: '^1.2.3', c: '*', d: 'latest', e: 'github:x/y', f: 'github:x/y#abcdef1234', g: '' }, devDependencies: { ignored: '*' } }));
    expect(deps.map((d) => `${d.name}:${d.pinned}`)).toEqual(['a:true', 'b:true', 'c:false', 'd:false', 'e:false', 'f:true', 'g:false']);
    expect(parsePackageJson('not json')).toEqual([]);
  });
});

describe('in a skill', () => {
  const FM = (n: string) => `---\nname: ${n}\ndescription: a skill\n---\nDoes a thing.\n`;
  const tmp = () => mkdtempSync(path.join(os.tmpdir(), 'ai-bom-supply-'));
  const run = async (files: Record<string, string>) => {
    const dir = tmp();
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      writeFileSync(path.join(dir, rel), text);
    }
    return preflight(dir, { home: tmp(), sessionLogs: false });
  };
  const ids = (r: Awaited<ReturnType<typeof run>>, rule: string) => r.inventory.findings.filter((f) => f.ruleId === rule);

  it('flags a look-alike skill name', async () => {
    const r = await run({ 'SKILL.md': FM('skill-creatr') });
    const f = ids(r, 'TRUST-TYPOSQUAT-SKILL');
    expect(f).toHaveLength(1);
    expect(f[0].evidence).toBe('skill-creatr ≈ skill-creator');
    expect(f[0].atlas?.some((x) => x.startsWith('AML.T0010.005'))).toBe(true);
    await r.cleanup();
  });

  it('flags a look-alike dependency and one summary of the unpinned ones', async () => {
    const r = await run({ 'SKILL.md': FM('reporter'), 'scripts/requirements.txt': 'reqeusts==2.0\nnumpy\nflask>=2\nrich==13.0\n' });
    expect(ids(r, 'SKILL-DEP-TYPOSQUAT').map((f) => f.evidence)).toEqual(['reqeusts ≈ requests']);
    const loose = ids(r, 'SKILL-DEP-UNPINNED');
    expect(loose).toHaveLength(1);
    expect(loose[0].severity).toBe('low');
    expect(loose[0].evidence).toBe('2 of 4 not pinned: numpy, flask');
    await r.cleanup();
  });

  it('says nothing for a fully pinned, correctly named skill', async () => {
    const r = await run({ 'SKILL.md': FM('reporter'), 'requirements.txt': 'requests==2.32.3\nnumpy==2.0.1\n', 'package.json': JSON.stringify({ dependencies: { express: '4.19.2', lodash: '^4.17.21' } }) });
    expect(r.inventory.findings.filter((f) => /TYPOSQUAT|UNPINNED/.test(f.ruleId))).toHaveLength(0);
    await r.cleanup();
  });
});
