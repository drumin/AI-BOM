import { useEffect, useState } from 'react';
import { post, type Inventory } from '../lib';
import { ErrorNote } from './ui';

interface State {
  guard: boolean;
  preflight: boolean;
  watch: { supported: boolean; installed: boolean };
  settingsFile: string;
  ephemeral: boolean;
}
interface Check {
  folder: string;
  verdict: 'safe' | 'review' | 'dangerous';
  autorun: string[];
  findings: { id: string; severity: string; title: string; location?: string; evidence?: string; remediation: string }[];
  reads: number;
}
interface Doctor {
  version: string;
  node: string;
  platform: string;
  claudeDir: string;
  tools: string[];
  assets: number;
  projects: number;
  found: { path: string; note?: string }[];
  errors: { path: string; note?: string }[];
  missing: number;
}

const VERDICT = { safe: ['Safe', 'ok', 'Nothing in this folder acts on its own.'], review: ['Review', 'warn', 'Worth a look before you open it in an AI tool.'], dangerous: ['Dangerous', 'bad', 'Do not open it in an AI tool until you have read what it sets up.'] } as const;

/** What protects you while you work, a pre-flight check for folders you did not write, and what the scanner saw. */
export function SafeguardsView({ onChanged }: { onChanged: (r: { snapshot?: { id: string; title: string }; inventory: Inventory }, text?: string) => void }) {
  const [state, setState] = useState<State | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  useEffect(() => {
    fetch('/api/safeguards')
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then(setState)
      .catch((e) => setError((e as Error).message));
  }, []);

  const toggle = async (name: 'preflight' | 'guard' | 'watch', on: boolean) => {
    setBusy(name);
    setError(null);
    try {
      const r = await post<{ snapshot?: { id: string; title: string }; state: State; inventory?: Inventory; note?: string }>('/api/safeguards', { name, on });
      setState(r.state);
      if (r.inventory) onChanged({ snapshot: r.snapshot ?? undefined, inventory: r.inventory }, r.snapshot ? undefined : `${on ? 'Already on' : 'Already off'}.`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const rows: { id: 'preflight' | 'guard' | 'watch'; title: string; body: string; on: boolean; disabled?: string }[] = state
    ? [
        { id: 'preflight', title: 'Check each project when a session starts', body: `Claude Code runs a pre-flight check on the folder it opens and warns you if the project sets up hooks or servers that act on their own. Added to ${state.settingsFile}.`, on: state.preflight },
        { id: 'guard', title: 'Check every MCP tool call', body: `Looks at each MCP tool call before it runs and its result after, and stops the ones that look like they leak secrets or follow hidden instructions. Added to ${state.settingsFile}.`, on: state.guard },
        { id: 'watch', title: 'Watch for changes in the background', body: 'Rescans your AI setup on a schedule (every 30 minutes) and notifies you when something is added or changes.', on: state.watch.installed, disabled: state.watch.supported ? undefined : 'Background watch is available on macOS and Linux.' },
      ]
    : [];

  return (
    <div className="safeguards">
      <div className="panel pad">
        <h3 className="section-title">Protections</h3>
        <p className="meta">Each one can be turned off again. The two that edit Claude Code’s settings can be undone from History.</p>
        {error && <ErrorNote message={error} />}
        {!state && !error && <div className="meta"><span className="spinner" aria-hidden /> Checking…</div>}
        {state?.ephemeral && <p className="callout warn">AI-BOM is running from a temporary cache (npx). A hook added now can stop working when that cache is cleared. Install it with <code>npm i -g</code> first.</p>}
        <ul className="safeguard-list">
          {rows.map((r) => (
            <li key={r.id}>
              <div className="safeguard-text">
                <div className="safeguard-title">
                  <strong>{r.title}</strong>
                  <span className={`pill ${r.on ? 'ok' : ''}`}>{r.on ? 'On' : 'Off'}</span>
                </div>
                <p className="meta">{r.body}</p>
                {r.disabled && <p className="meta">{r.disabled}</p>}
              </div>
              <button className={`btn small${r.on ? '' : ' primary'}`} disabled={!!busy || !!r.disabled} onClick={() => toggle(r.id, !r.on)} aria-label={`${r.on ? 'Turn off' : 'Turn on'}: ${r.title}`}>
                {busy === r.id ? <><span className="spinner" aria-hidden /> Working</> : r.on ? 'Turn off' : 'Turn on'}
              </button>
            </li>
          ))}
        </ul>
      </div>
      <FolderCheck />
      <Diagnostics />
    </div>
  );
}

function FolderCheck() {
  const [path, setPath] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Check | null>(null);
  const run = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await post<Check>('/api/preflight', { path }));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const v = result && VERDICT[result.verdict];
  return (
    <section className="panel pad" aria-labelledby="folder-check-title">
      <h3 className="section-title" id="folder-check-title">Check a folder before you open it</h3>
      <p className="meta">For a repository you did not write. Only that folder’s own AI config is read; nothing in it is run.</p>
      <form className="form-row" onSubmit={run}>
        <label className="grow">
          Folder
          <input className="input" value={path} onChange={(e) => setPath(e.target.value)} placeholder="~/Downloads/some-repo" autoComplete="off" spellCheck={false} />
        </label>
        <button className="btn primary" type="submit" disabled={busy || !path.trim()}>{busy ? <><span className="spinner light" aria-hidden /> Checking</> : 'Check folder'}</button>
      </form>
      {error && <ErrorNote message={error} hint={false} />}
      {result && v && (
        <div className="check-result" role="region" aria-label={`Result for ${result.folder}`}>
          <p>
            <span className={`pill ${v[1]}`}>{v[0]}</span> <span className="mono">{result.folder}</span>
          </p>
          <p className="meta">{v[2]}</p>
          {result.autorun.length > 0 && (
            <>
              <h4>What it sets up for your AI tools</h4>
              <ul className="plain">{result.autorun.map((x) => <li key={x}>{x}</li>)}</ul>
            </>
          )}
          {result.findings.length > 0 && (
            <>
              <h4>Findings</h4>
              <ul className="check-findings">
                {result.findings.map((f) => (
                  <li key={f.id}>
                    <strong>{f.title}</strong> <span className="meta">{f.severity}{f.location ? ` · ${f.location}` : ''}</span>
                    {f.evidence && <code className="evidence">{f.evidence}</code>}
                    <span className="meta">{f.remediation}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
          {result.reads > 0 && <p className="meta">It also brings {result.reads} skill, agent, command or instruction file{result.reads === 1 ? '' : 's'} your agent would read.</p>}
          {!result.autorun.length && !result.findings.length && <p className="meta">It does not configure any hooks, MCP servers or auto-run tasks.</p>}
        </div>
      )}
    </section>
  );
}

function Diagnostics() {
  const [data, setData] = useState<Doctor | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await fetch('/api/doctor');
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setData(await r.json());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const text = data
    ? [
        `ai-bom ${data.version} · node ${data.node} · ${data.platform}`,
        `Claude config: ${data.claudeDir}`,
        `Tools: ${data.tools.join(', ') || 'none'} · ${data.assets} assets · ${data.projects} projects`,
        `Found (${data.found.length}):`,
        ...data.found.map((f) => `  ${f.path}${f.note ? ` — ${f.note}` : ''}`),
        ...(data.errors.length ? [`Could not read (${data.errors.length}):`, ...data.errors.map((f) => `  ${f.path} — ${f.note ?? ''}`)] : []),
        `Checked but not present: ${data.missing}`,
      ].join('\n')
    : '';
  return (
    <section className="panel pad" aria-labelledby="diag-title">
      <h3 className="section-title" id="diag-title">What was scanned</h3>
      <p className="meta">If something you expected is missing, this lists every place AI-BOM looked. It shows names and counts, never values, so it is safe to share.</p>
      <div className="actions">
        <button className="btn small" onClick={run} disabled={busy}>{busy ? <><span className="spinner" aria-hidden /> Looking</> : data ? 'Run again' : 'Run diagnostics'}</button>
        {data && (
          <button className="btn small" onClick={() => navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); })}>
            {copied ? 'Copied' : 'Copy as text'}
          </button>
        )}
      </div>
      {error && <ErrorNote message={`Couldn’t run diagnostics: ${error}`} />}
      {data && (
        <div className="diag">
          <p>
            <strong>{data.tools.length}</strong> AI tool{data.tools.length === 1 ? '' : 's'} found ({data.tools.join(', ') || 'none'}), <strong>{data.assets}</strong> assets, <strong>{data.projects}</strong> project{data.projects === 1 ? '' : 's'} with AI config.
          </p>
          <p className="meta">ai-bom {data.version} · node {data.node} · {data.platform} · Claude config {data.claudeDir}</p>
          {data.errors.length > 0 && (
            <>
              <h4>Could not read ({data.errors.length})</h4>
              <ul className="plain">{data.errors.map((f) => <li key={f.path}><span className="mono">{f.path}</span> — {f.note}</li>)}</ul>
            </>
          )}
          <details>
            <summary>Found ({data.found.length})</summary>
            <ul className="plain diag-list" tabIndex={0} aria-label="Places AI-BOM found something">{data.found.map((f) => <li key={f.path + (f.note ?? '')}><span className="mono">{f.path}</span>{f.note ? ` — ${f.note}` : ''}</li>)}</ul>
          </details>
          <p className="meta">Checked but not present: {data.missing} location{data.missing === 1 ? '' : 's'}.</p>
        </div>
      )}
    </section>
  );
}
