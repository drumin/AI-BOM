import { useState } from 'react';
import { FIX_LABEL, SEV_VAR, type Asset, type Finding } from '../lib';
import { Sev } from './Severity';
import { VulnDetail } from './VulnDetail';

export type TriageAction = { status: 'accepted' | 'snoozed' | 'false-positive'; until?: string; reason?: string } | { status: 'clear' };

const SNOOZE = [['7d', '1 week'], ['30d', '1 month'], ['90d', '3 months']] as const;

/** One finding, with its evidence, fix and triage actions. */
export function FindingCard({
  f,
  asset,
  related,
  showAsset,
  onSelect,
  onFix,
  onTriage,
  as: Heading = 'h3',
  onAtlas,
  picked,
  onPick,
  titleless,
}: {
  f: Finding;
  asset?: Asset;
  related?: Asset[];
  showAsset?: boolean;
  onSelect: (id: string) => void;
  onFix: (f: Finding) => void;
  onTriage: (f: Finding, a: TriageAction) => void | Promise<void>;
  /** Heading level for the title: h3 on the Findings tab, h4 where it sits under a section heading. */
  as?: 'h3' | 'h4';
  /** Open this MITRE ATLAS technique in the Baselines view. */
  onAtlas?: (techniqueId: string) => void;
  /** Selection for bulk actions (Findings tab only). */
  picked?: boolean;
  onPick?: (picked: boolean) => void;
  /** Inside a group the title is already on the group row: show only which asset this one is about. */
  titleless?: boolean;
}) {
  const [mode, setMode] = useState<null | 'accepted' | 'snoozed' | 'false-positive'>(null);
  const [reason, setReason] = useState('');
  const [until, setUntil] = useState<string>('30d');
  const m = f.muted;
  const [leaving, setLeaving] = useState(false);
  /** Fold the card away, then apply; if it is still here afterwards (the change failed), unfold it. */
  const triage = async (a: TriageAction) => {
    const still = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (still) {
      setLeaving(true);
      await new Promise((r) => setTimeout(r, 200));
    }
    try {
      await onTriage(f, a);
    } finally {
      setLeaving(false);
    }
  };

  return (
    <div className="finding-wrap" data-leaving={leaving ? 'true' : 'false'}>
    <article className={`finding${m ? ' is-muted' : ''}${picked ? ' picked' : ''}`} style={{ borderLeftColor: m ? 'var(--border-strong)' : `var(${SEV_VAR[f.severity]})` }}>
      {onPick && (
        <label className="pick">
          <input type="checkbox" checked={!!picked} onChange={(e) => onPick(e.target.checked)} />
          <span className="sr-only">Select: {f.title}</span>
        </label>
      )}
      {titleless ? (
        showAsset && asset && (
          <Heading className="finding-asset">
            <button className="asset-link" onClick={() => onSelect(asset.id)}>{asset.name}</button>
          </Heading>
        )
      ) : (
        <Heading>
          <Sev severity={f.severity} />
          {f.title}
          {showAsset && asset && (
            <button className="asset-link" onClick={() => onSelect(asset.id)}>{asset.name}</button>
          )}
        </Heading>
      )}
      {m && (
        <div className="muted-line">
          {m.status === 'accepted' ? 'Accepted risk' : m.status === 'snoozed' ? `Snoozed until ${new Date(m.until!).toLocaleDateString()}` : 'Marked as false positive'}
          {m.reason && <> · “{m.reason}”</>}
        </div>
      )}
      <p>{f.description}</p>
      {f.evidence && <code className="evidence">{f.vuln ? `Your call: ${f.evidence}` : f.evidence}</code>}
      {related && related.length > 0 && (
        <div className="related">
          {related.map((r) => (
            <button key={r.id} className="chip" onClick={() => onSelect(r.id)}>{r.name}</button>
          ))}
        </div>
      )}
      {f.location && <div className="loc mono">{f.location}</div>}
      <VulnDetail f={f} />
      {!f.vuln?.fixCommand && (
        <p className="fix"><strong>Fix: </strong>{f.remediation}</p>
      )}
      {f.references && f.references.length > 0 && (
        <div className="refs">
          {f.references.map((u) => (
            <a key={u} href={u} target="_blank" rel="noopener noreferrer">{u.replace(/^https?:\/\//, '')}</a>
          ))}
        </div>
      )}
      {((f.owasp?.length ?? 0) > 0 || (f.atlas?.length ?? 0) > 0) && (
        <div className="tags">
          {f.owasp?.map((o) => <span className="tag" key={o}>{o}</span>)}
          {f.atlas?.map((a) =>
            onAtlas ? (
              <button className="tag atlas" key={a} onClick={() => onAtlas(a.split(' ')[0])} title="Show in the MITRE ATLAS view">{a}</button>
            ) : (
              <a className="tag atlas" key={a} href={`https://atlas.mitre.org/techniques/${a.split(' ')[0]}`} target="_blank" rel="noopener" title="MITRE ATLAS technique">{a}</a>
            ),
          )}
        </div>
      )}

      <div className="finding-actions">
        {!m && f.fixes && f.fixes.length > 0 && (
          <button className="btn primary small" onClick={() => onFix(f)} title={f.fixes.map((k) => FIX_LABEL[k]).join(' · ')}>
            {FIX_LABEL[f.fixes[0]]}…
          </button>
        )}
        {m ? (
          <button className="btn small" onClick={() => triage({ status: 'clear' })}>Unmute</button>
        ) : mode === null ? (
          <>
            <button className="btn small" onClick={() => setMode('accepted')}>Accept risk</button>
            <button className="btn small" onClick={() => setMode('snoozed')}>Snooze</button>
            <button className="btn small quiet" onClick={() => setMode('false-positive')}>Not an issue</button>
          </>
        ) : (
          <form
            className="triage-form"
            onSubmit={(e) => {
              e.preventDefault();
              const a: TriageAction = { status: mode, reason: reason.trim() || undefined, until: mode === 'snoozed' ? until : undefined };
              setMode(null);
              void triage(a);
            }}
          >
            {mode === 'snoozed' && (
              <select value={until} onChange={(e) => setUntil(e.target.value)} aria-label="Snooze for">
                {SNOOZE.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
              </select>
            )}
            <input
              autoFocus
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder={mode === 'accepted' ? 'Why is this OK? (optional)' : mode === 'snoozed' ? 'Note to self (optional)' : 'What did the check get wrong? (optional)'}
              maxLength={300}
              aria-label="Reason"
            />
            <button className="btn primary small" type="submit">{mode === 'accepted' ? 'Accept' : mode === 'snoozed' ? 'Snooze' : 'Mark'}</button>
            <button className="btn small quiet" type="button" onClick={() => setMode(null)}>Cancel</button>
          </form>
        )}
      </div>
    </article>
    </div>
  );
}
