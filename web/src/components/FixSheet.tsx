import { useEffect, useState } from 'react';
import { FIX_LABEL, post, type FixKind, type Inventory } from '../lib';
import { ErrorNote } from './ui';
import { Sheet } from './Sheet';

export interface FixTarget {
  findingId?: string;
  assetId?: string;
  kinds: FixKind[];
}

interface Plan {
  key: string;
  kind: FixKind;
  label: string;
  title: string;
  summary: string;
  warnings: string[];
  changes: { file: string; description: string; diff?: string }[];
  manual: string[];
}

export interface Applied {
  snapshot: { id: string; title: string };
  inventory: Inventory;
}

/** Preview → confirm → apply. Nothing is written until "Apply"; everything can be undone. */
export function FixSheet({ target, onClose, onApplied }: { target: FixTarget; onClose: () => void; onApplied: (r: Applied) => void }) {
  const [kind, setKind] = useState<FixKind>(target.kinds[0]);
  const [plan, setPlan] = useState<Plan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setPlan(null);
    setError(null);
    post<Plan>('/api/fix/preview', { findingId: target.findingId, assetId: target.assetId, kind })
      .then(setPlan)
      .catch((e) => setError((e as Error).message));
  }, [kind, target.findingId, target.assetId]);

  const apply = async () => {
    if (!plan) return;
    setBusy(true);
    try {
      onApplied(await post<Applied>('/api/fix/apply', { findingId: target.findingId, assetId: target.assetId, kind, key: plan.key }));
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };

  return (
    <Sheet
      title={plan?.title ?? FIX_LABEL[kind]}
      onClose={onClose}
      wide
      footer={
        <>
          <span className="meta">Saved as a snapshot: you can undo it from History at any time.</span>
          <span className="spacer" />
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" onClick={apply} disabled={!plan || busy || !plan.changes.length} data-autofocus>
            {busy ? <><span className="spinner light" aria-hidden /> Applying</> : 'Apply'}
          </button>
        </>
      }
    >
      {target.kinds.length > 1 && (
        <div className="segmented fix-kinds" role="radiogroup" aria-label="Kind of fix">
          {target.kinds.map((k) => (
            <label key={k} className={k === kind ? 'on' : ''}>
              <input type="radio" name="fixkind" checked={k === kind} onChange={() => setKind(k)} />
              {FIX_LABEL[k]}
            </label>
          ))}
        </div>
      )}
      {error && <ErrorNote message={error} />}
      {!plan && !error && <div className="meta"><span className="spinner" aria-hidden /> Preparing a preview…</div>}
      {plan && (
        <>
          <p>{plan.summary}</p>
          {plan.warnings.map((w) => (
            <div key={w} className="callout warn">{w}</div>
          ))}
          {plan.changes.map((c) => (
            <section key={c.file} className="diff-block">
              <div className="diff-file"><span className="mono">{c.file}</span><span className="meta">{c.description}</span></div>
              {c.diff && (
                <pre className="diff" aria-label={`Changes to ${c.file}`}>
                  {c.diff.split('\n').map((l, i) => (
                    <span key={i} className={l.startsWith('+ ') ? 'add' : l.startsWith('- ') ? 'del' : l.startsWith('@@') ? 'hunk' : ''}>{l}{'\n'}</span>
                  ))}
                </pre>
              )}
            </section>
          ))}
          {plan.manual.length > 0 && (
            <>
              <h4>Change these by hand</h4>
              <ul className="plain">{plan.manual.map((m) => <li key={m}>{m}</li>)}</ul>
            </>
          )}
        </>
      )}
    </Sheet>
  );
}
