import { useEffect, useState } from 'react';
import { post, type Finding, type Inventory } from '../lib';
import { ErrorNote } from './ui';
import { Sheet } from './Sheet';
import { Sev } from './Severity';

interface Vetted {
  token: string;
  name: string;
  spec: { kind: string; name: string; url?: string };
  version?: string;
  entry: { command?: string; args?: string[]; url?: string };
  verdict: 'safe' | 'review' | 'dangerous';
  findings: Finding[];
  tools: { name: string; description?: string; behavior?: { verdict: string; reasons: string[] } }[];
  trust?: { level: string; notes: string[] };
  deps?: { total: number; scope: string; licenseNotes: string[]; error?: string };
}

const VERDICT = { safe: ['Looks safe', 'ok'], review: ['Worth a look', 'warn'], dangerous: ['Dangerous', 'bad'] } as const;

/** Vet first (download, never run), then add pinned to the tools you pick. */
export function AddSheet({ onClose, onAdded }: { onClose: () => void; onAdded: (r: { snapshot?: { id: string; title: string }; inventory: Inventory }) => void }) {
  const [spec, setSpec] = useState('');
  const [busy, setBusy] = useState<null | 'vet' | 'add'>(null);
  const [error, setError] = useState<string | null>(null);
  const [v, setV] = useState<Vetted | null>(null);
  const [name, setName] = useState('');
  const [targets, setTargets] = useState<{ id: string; name: string; installed: boolean }[]>([]);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [force, setForce] = useState(false);

  useEffect(() => {
    fetch('/api/add/targets').then((r) => r.json()).then((t: typeof targets) => {
      setTargets(t);
      setChosen(new Set(t.filter((x) => x.installed).map((x) => x.id)));
    }).catch(() => {});
  }, []);

  const check = async () => {
    setBusy('vet');
    setError(null);
    setV(null);
    try {
      const r = await post<Vetted>('/api/add/vet', { spec });
      setV(r);
      setName(r.name);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };
  const add = async () => {
    if (!v) return;
    setBusy('add');
    setError(null);
    try {
      onAdded(await post('/api/add/apply', { token: v.token, name, targets: [...chosen], force }));
    } catch (e) {
      setError((e as Error).message);
      setBusy(null);
    }
  };

  return (
    <Sheet
      title="Add an MCP server"
      wide
      onClose={onClose}
      footer={
        <>
          <span className="meta">Added pinned to one version. Undo from History.</span>
          <span className="spacer" />
          <button className="btn" onClick={onClose}>Cancel</button>
          {v ? (
            <button className="btn primary" onClick={add} disabled={!!busy || !chosen.size || (v.verdict === 'dangerous' && !force)}>{busy === 'add' ? 'Adding…' : 'Add'}</button>
          ) : (
            <button className="btn primary" onClick={check} disabled={!!busy || !spec.trim()}>{busy === 'vet' ? <><span className="spinner light" aria-hidden /> Checking</> : 'Check it'}</button>
          )}
        </>
      }
    >
      <form className="add-form" onSubmit={(e) => { e.preventDefault(); if (!v) check(); }}>
        <input
          className="input grow"
          data-autofocus
          value={spec}
          onChange={(e) => { setSpec(e.target.value); setV(null); }}
          placeholder="@modelcontextprotocol/server-github · pypi:mcp-server-fetch · https://mcp.linear.app/sse"
          aria-label="Package or URL"
        />
      </form>
      <p className="meta">AI-BOM downloads the exact package (it never installs or runs it), reads its tools’ code, and checks advisories, publisher signals and dependencies before anything is added. Secrets: add them with <code>ai-bom add … --secret NAME</code> so they go to the keychain.</p>
      {error && <ErrorNote message={error} />}
      {v && (
        <>
          <div className={`verdict ${VERDICT[v.verdict][1]}`}>
            <strong>{VERDICT[v.verdict][0]}</strong> — {v.spec.url ?? `${v.spec.name}@${v.version}`}
            {v.trust?.notes.length ? <div className="meta">{v.trust.notes.slice(0, 4).join(' · ')}</div> : null}
          </div>
          {v.findings.length > 0 && (
            <ul className="plain">
              {v.findings.slice(0, 8).map((f) => <li key={f.id}><Sev severity={f.severity} /> {f.title}{f.evidence && <span className="meta"> — {f.evidence.slice(0, 120)}</span>}</li>)}
            </ul>
          )}
          {v.tools.length > 0 && (
            <>
              <h4>Tools ({v.tools.length}), read from its code</h4>
              <ul className="plain">
                {v.tools.slice(0, 20).map((t) => (
                  <li key={t.name}>
                    <span className="mono">{t.name}</span> {t.behavior?.verdict === 'mismatch' ? <span className="pill bad">does more than it says</span> : t.behavior?.verdict === 'matches' ? <span className="pill ok">matches</span> : null}
                    {t.behavior?.reasons.length ? <div className="meta">{t.behavior.reasons.join('; ')}</div> : null}
                  </li>
                ))}
              </ul>
            </>
          )}
          {v.deps && <p className="meta">Dependencies: {v.deps.total} ({v.deps.scope}){v.deps.error ? ` · ${v.deps.error}` : ''}{v.deps.licenseNotes.length ? ` · ${v.deps.licenseNotes.join('; ')}` : ''}</p>}
          <h4>Add to</h4>
          <div className="target-grid">
            {targets.map((t) => (
              <label key={t.id} className={`check${t.installed ? '' : ' dim'}`}>
                <input
                  type="checkbox"
                  checked={chosen.has(t.id)}
                  onChange={(e) => setChosen((cur) => { const n = new Set(cur); if (e.target.checked) n.add(t.id); else n.delete(t.id); return n; })}
                />
                {t.name}{!t.installed && <span className="meta"> (not found)</span>}
              </label>
            ))}
          </div>
          <label className="field">Name in config <input className="input" value={name} onChange={(e) => setName(e.target.value)} /></label>
          {v.verdict === 'dangerous' && (
            <label className="check"><input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} /> I understand the risks; add it anyway</label>
          )}
        </>
      )}
    </Sheet>
  );
}
