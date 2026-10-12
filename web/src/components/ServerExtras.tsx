import { useEffect, useState } from 'react';
import { post, relativeTime, SEV_VAR, type Asset, type Inventory } from '../lib';

/** Dependencies installed with an MCP server: vulnerable ones first, then licenses. */
export function DepsSection({ asset }: { asset: Asset }) {
  const d = asset.deps;
  if (!d) return null;
  const licenses = Object.entries(d.licenses).sort((a, b) => b[1] - a[1]);
  return (
    <>
      <h3>
        Dependencies ({d.total})
        <span className="h3-note">{d.scope === 'installed' ? 'everything installed with it' : 'direct dependencies, from the registry'}</span>
      </h3>
      {d.vulnerable.length === 0 ? (
        <p className="meta">No known vulnerabilities in its dependencies.</p>
      ) : (
        <ul className="dep-list">
          {d.vulnerable.map((v) => (
            <li key={`${v.name}@${v.version}-${v.id}`}>
              <span className="dot" style={{ background: `var(${SEV_VAR[v.severity]})` }} aria-hidden />
              <span className="mono">{v.name}@{v.version}</span> <span className="tag">{v.id}</span>
              <div className="meta">{v.summary}</div>
            </li>
          ))}
        </ul>
      )}
      {licenses.length > 0 && (
        <p className="meta">Licenses: {licenses.slice(0, 6).map(([l, n]) => `${l} ${n}`).join(' · ')}{licenses.length > 6 ? ' · …' : ''}</p>
      )}
      {d.licenseNotes.length > 0 && <ul className="suggestions">{d.licenseNotes.map((n) => <li key={n}>{n}</li>)}</ul>}
    </>
  );
}

interface LiveResult {
  ok: boolean;
  error?: string;
  sandbox: string;
  tools: { name: string }[];
  liveOnly: string[];
  staticOnly: string[];
  changedDescriptions: string[];
  poisoned: string[];
  networkAttempts: string[];
}

/** Start the server in a sandbox (no network, empty home) and compare what it reports with what its files say. */
export function LiveInspect({ asset, onInventory }: { asset: Asset; onInventory: (inv: Inventory) => void }) {
  const m = asset.mcp;
  const [sandbox, setSandbox] = useState<string | null | undefined>(undefined);
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<LiveResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    fetch('/api/sandbox').then((r) => r.json()).then((r: { sandbox: string | null }) => setSandbox(r.sandbox)).catch(() => setSandbox(null));
  }, []);
  if (!m || m.transport !== 'stdio' || !m.command) return null;
  const last = m.live;

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await post<{ result: LiveResult; inventory: Inventory }>('/api/inspect', { assetId: asset.id });
      setResult(r.result);
      setConfirm(false);
      onInventory(r.inventory);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const shown = result
    ? { ok: result.ok, error: result.error, tools: result.tools.length, liveOnly: result.liveOnly, changed: result.changedDescriptions, net: result.networkAttempts, at: undefined as string | undefined }
    : last
      ? { ok: last.ok, error: last.error, tools: last.tools, liveOnly: last.liveOnly, changed: last.changedDescriptions, net: last.networkAttempts, at: last.at }
      : null;

  return (
    <>
      <h3>
        Live check
        <span className="h3-note">{shown?.at ? `last run ${relativeTime(shown.at)}` : 'not run yet'}</span>
      </h3>
      {shown && (
        <div className={`live-card${shown.liveOnly.length || shown.changed.length || shown.net.length ? ' warn' : ''}`}>
          {!shown.ok ? (
            <p>It didn’t start in the sandbox{shown.error ? `: ${shown.error}` : '.'}</p>
          ) : (
            <>
              <p>
                It reported {shown.tools} tool{shown.tools === 1 ? '' : 's'}.
                {!shown.liveOnly.length && !shown.changed.length && !shown.net.length && ' Nothing differed from what its files say.'}
              </p>
              {shown.liveOnly.length > 0 && <p>Tools only visible when running: <span className="mono">{shown.liveOnly.join(', ')}</span></p>}
              {shown.changed.length > 0 && <p>Descriptions that change at runtime: <span className="mono">{shown.changed.join(', ')}</span></p>}
              {shown.net.length > 0 && <p>Tried to reach the network on start: <span className="mono">{shown.net.join(', ')}</span></p>}
            </>
          )}
        </div>
      )}
      {sandbox === null ? (
        <p className="meta">No sandbox available on this computer (needs macOS sandbox-exec, or bubblewrap/unshare on Linux), so AI-BOM won’t start it.</p>
      ) : confirm ? (
        <div className="confirm-box">
          <p>
            AI-BOM will start <span className="mono">{m.command}</span> inside {sandbox ?? 'a sandbox'} with <strong>no network</strong>, an empty home folder
            and no credentials, ask it for its tools, then stop it after 20 seconds.
          </p>
          <div className="actions">
            <button className="btn primary small" onClick={run} disabled={busy}>{busy ? <><span className="spinner light" aria-hidden /> Running…</> : 'Run it'}</button>
            <button className="btn small" onClick={() => setConfirm(false)} disabled={busy}>Cancel</button>
          </div>
        </div>
      ) : (
        <button className="btn small" onClick={() => setConfirm(true)} disabled={sandbox === undefined}>{shown ? 'Run again in sandbox…' : 'Run in sandbox…'}</button>
      )}
      {error && <p className="meta error">{error}</p>}
    </>
  );
}
