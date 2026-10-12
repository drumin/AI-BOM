import { useEffect, useState } from 'react';
import { post, type Inventory } from '../lib';
import { ErrorNote } from './ui';
import { Sheet } from './Sheet';

interface Preview {
  paused: { assetId: string; name: string; kind: string; files: string[] }[];
  keys: { label: string; provider?: string; url?: string; where: string[]; why: string }[];
  manual: string[];
}

/** One calm, reversible step for "I think something went wrong". */
export function IncidentSheet({ onClose, onDone }: { onClose: () => void; onDone: (r: { snapshot?: { id: string; title: string }; report: string; inventory: Inventory }) => void }) {
  const [p, setP] = useState<Preview | null>(null);
  const [keep, setKeep] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    post<Preview>('/api/incident/preview', {}).then(setP).catch((e) => setError((e as Error).message));
  }, []);
  return (
    <Sheet
      title="Respond to an incident"
      wide
      onClose={onClose}
      footer={
        <>
          <span className="meta">Pausing is one change: undo it from History.</span>
          <span className="spacer" />
          <button className="btn" onClick={onClose}>Cancel</button>
          <button
            className="btn danger"
            disabled={!p || busy}
            onClick={async () => {
              setBusy(true);
              try {
                onDone(await post('/api/incident/apply', { keep: [...keep] }));
              } catch (e) {
                setError((e as Error).message);
                setBusy(false);
              }
            }}
          >
            {busy ? 'Working…' : `Pause ${p ? p.paused.length - keep.size : ''} and write report`}
          </button>
        </>
      }
    >
      <p>This pauses your MCP servers and any hook that sends data out, so nothing can act while you look. It then writes a report with the keys to rotate and what your agents did this week, saved in <code>~/.ai-bom/incidents/</code>.</p>
      {error && <ErrorNote message={error} />}
      {!p && !error && <div className="meta"><span className="spinner" aria-hidden /> Preparing…</div>}
      {p && (
        <>
          <h4>Pause ({p.paused.length}) — untick what you need to keep</h4>
          <div className="target-grid">
            {p.paused.map((x) => (
              <label key={x.assetId} className="check">
                <input type="checkbox" checked={!keep.has(x.name)} onChange={(e) => setKeep((cur) => { const n = new Set(cur); if (e.target.checked) n.delete(x.name); else n.add(x.name); return n; })} />
                {x.name}<span className="meta"> {x.kind === 'hook' ? 'hook' : ''}</span>
              </label>
            ))}
          </div>
          {p.manual.length > 0 && <ul className="plain">{p.manual.map((m) => <li key={m} className="meta">{m}</li>)}</ul>}
          <h4>Keys to rotate ({p.keys.length})</h4>
          {p.keys.length === 0 ? <p className="meta">No stored keys found.</p> : (
            <ul className="keys">
              {p.keys.map((k) => (
                <li key={k.label}>
                  <strong>{k.label}</strong>
                  <div className="meta">{k.why} {k.where.filter(Boolean).slice(0, 2).join(', ')}</div>
                  {k.url && <a href={k.url} target="_blank" rel="noopener noreferrer">Rotate at {k.provider}</a>}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </Sheet>
  );
}
