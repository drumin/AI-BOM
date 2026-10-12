import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { FIX_LABEL, SEV_VAR, SEVERITIES, sevRank, type Asset, type Finding, type Inventory, type Severity } from '../lib';
import { Chevron } from './ui';
import { Sev } from './Severity';
import { FindingCard, type TriageAction } from './FindingCard';

/** One issue that shows up in several places: same rule, same advisory, same wording once the asset is taken out. */
const groupKey = (f: Finding) => `${f.ruleId}|${f.advisory ?? ''}|${f.title.replace(/\s*\((used by|in|for|on)\b[^)]*\)\s*$/i, '')}`;
const stripAsset = (t: string) => t.replace(/\s*\((used by|in|for|on)\b[^)]*\)\s*$/i, '');
const firstSentence = (t: string) => (t.match(/^.*?[.!?](?=\s|$)/)?.[0] ?? t).trim();

interface Group {
  key: string;
  title: string;
  severity: Severity;
  items: Finding[];
}

function FindingGroup({
  g,
  open,
  onToggle,
  assets,
  sel,
  onPick,
  children,
  onFix,
}: {
  g: Group;
  open: boolean;
  onToggle: () => void;
  assets: Map<string, Asset>;
  sel: Set<string>;
  onPick: (ids: string[], on: boolean) => void;
  children: React.ReactNode;
  onFix: (f: Finding) => void;
}) {
  const first = g.items[0];
  const names = [...new Set(g.items.map((f) => (f.assetId ? assets.get(f.assetId)?.name : undefined)).filter((n): n is string => !!n))];
  const ids = g.items.map((f) => f.id);
  const nPicked = ids.filter((id) => sel.has(id)).length;
  const box = useRef<HTMLInputElement>(null);
  // Once opened, keep the cards mounted so closing can animate.
  const [seen, setSeen] = useState(open);
  useEffect(() => {
    if (open) setSeen(true);
  }, [open]);
  useEffect(() => {
    if (box.current) box.current.indeterminate = nPicked > 0 && nPicked < ids.length;
  });
  const bodyId = useId();
  const muted = g.items.every((f) => f.muted);
  const quickFix = !muted && g.items.length === 1 && first.fixes?.length ? first : undefined;
  return (
    <article className={`fgroup${open ? ' open' : ''}${nPicked ? ' picked' : ''}`} style={{ ['--sev' as string]: muted ? 'var(--border-strong)' : `var(${SEV_VAR[g.severity]})` }}>
      <div className="fgroup-row">
        <label className="pick">
          <input ref={box} type="checkbox" checked={nPicked === ids.length} onChange={(e) => onPick(ids, e.target.checked)} />
          <span className="sr-only">Select: {g.title}{ids.length > 1 ? ` (${ids.length} places)` : ''}</span>
        </label>
        <button className="fgroup-head" aria-expanded={open} aria-controls={bodyId} onClick={onToggle}>
          <span className="fgroup-line">
            <Sev severity={g.severity} />
            <span className="fgroup-title">{g.title}</span>
            {g.items.length > 1 && <span className="count-pill" aria-label={`${g.items.length} places`}>{g.items.length}</span>}
            <span className="spacer" />
            <Chevron open={open} />
          </span>
          <span className="fgroup-sub">{firstSentence(first.description)}</span>
          {names.length > 0 && (
            <span className="fgroup-assets">
              {names.slice(0, 4).map((n) => <span className="tag" key={n}>{n}</span>)}
              {names.length > 4 && <span className="meta">+{names.length - 4} more</span>}
            </span>
          )}
        </button>
        {quickFix && (
          <button className="btn primary small fgroup-fix" onClick={() => onFix(quickFix)}>
            {FIX_LABEL[quickFix.fixes![0]]}…
          </button>
        )}
      </div>
      <div className="fgroup-expander" data-open={open} id={bodyId} inert={!open}>
        <div className="fgroup-inner">{(open || seen) && <div className="fgroup-body">{children}</div>}</div>
      </div>
    </article>
  );
}

export function FindingsList({
  inv,
  onSelect,
  onFix,
  onTriage,
  onTriageMany,
  onAtlas,
  view,
  onView,
  onlySeverity,
  onFocusUsed,
}: {
  inv: Inventory;
  onSelect: (id: string, ids?: string[]) => void;
  onFix: (f: Finding) => void;
  onTriage: (f: Finding, a: TriageAction) => void;
  onTriageMany: (list: Finding[], a: TriageAction) => void | Promise<void>;
  onAtlas?: (id: string) => void;
  view: 'active' | 'muted';
  onView: (v: 'active' | 'muted') => void;
  /** Start with just this severity showing (set by clicking a count in the summary). */
  onlySeverity?: Severity;
  onFocusUsed?: () => void;
}) {
  const showMuted = view === 'muted';
  const setShowMuted = (m: boolean) => onView(m ? 'muted' : 'active');
  // Track what the user hid (not what is shown) so severities appearing after a rescan are visible by default.
  const [hiddenSev, setHiddenSev] = useState<Set<Severity>>(() => new Set(onlySeverity ? SEVERITIES.filter((s) => s !== onlySeverity) : []));
  // The request is one-shot: coming back to this tab later should not re-apply it.
  useEffect(() => onFocusUsed?.(), []); // eslint-disable-line react-hooks/exhaustive-deps
  const assets = useMemo(() => new Map(inv.assets.map((a) => [a.id, a])), [inv]);
  const active = inv.findings.filter((f) => !f.muted);
  const muted = inv.findings.filter((f) => f.muted);
  const pool = showMuted ? muted : active;
  const present = SEVERITIES.filter((s) => pool.some((f) => f.severity === s));
  const list = pool.filter((f) => !hiddenSev.has(f.severity));

  const groups = useMemo<Group[]>(() => {
    const m = new Map<string, Group>();
    for (const f of list) {
      const k = groupKey(f);
      const g = m.get(k);
      if (g) {
        g.items.push(f);
        if (sevRank(f.severity) < sevRank(g.severity)) g.severity = f.severity;
      } else m.set(k, { key: k, title: stripAsset(f.title), severity: f.severity, items: [f] });
    }
    return [...m.values()].sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || b.items.length - a.items.length || a.title.localeCompare(b.title));
  }, [list]);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const allOpen = groups.length > 0 && groups.every((g) => open.has(g.key));
  const toggleGroup = (key: string) =>
    setOpen((cur) => {
      const n = new Set(cur);
      if (n.has(key)) n.delete(key);
      else n.add(key);
      return n;
    });
  const contextIds = useMemo(() => [...new Set(groups.flatMap((g) => g.items.map((f) => f.assetId)).filter((x): x is string => !!x))], [groups]);

  // Bulk selection. What you can't see can't be selected: ids no longer in the list drop out.
  const [sel, setSel] = useState<Set<string>>(new Set());
  const picked = list.filter((f) => sel.has(f.id));
  const [mode, setMode] = useState<null | 'accepted' | 'snoozed' | 'false-positive'>(null);
  const [reason, setReason] = useState('');
  const [until, setUntil] = useState('30d');
  const [working, setWorking] = useState(false);
  const pick = (ids: string[], on: boolean) =>
    setSel((cur) => {
      const n = new Set(cur);
      for (const id of ids) {
        if (on) n.add(id);
        else n.delete(id);
      }
      return n;
    });
  const clearSel = () => {
    setSel(new Set());
    setMode(null);
    setReason('');
  };
  const applyBulk = async (a: TriageAction) => {
    setWorking(true);
    try {
      await onTriageMany(picked, a);
    } finally {
      setWorking(false);
      clearSel();
    }
  };

  if (!inv.findings.length) return <div className="panel empty">No findings. Nice and tidy.</div>;

  return (
    <div className="panel">
      <div className="toolbar">
        <div className="segmented" role="radiogroup" aria-label="Which findings">
          <label className={!showMuted ? 'on' : ''}><input type="radio" name="muted" checked={!showMuted} onChange={() => setShowMuted(false)} />Active {active.length}</label>
          <label className={showMuted ? 'on' : ''}><input type="radio" name="muted" checked={showMuted} onChange={() => setShowMuted(true)} />Muted {muted.length}</label>
        </div>
        <div className="chips" role="group" aria-label="Filter by severity">
          {present.map((s) => (
            <button
              key={s}
              className="chip"
              aria-pressed={!hiddenSev.has(s)}
              onClick={() =>
                setHiddenSev((cur) => {
                  const n = new Set(cur);
                  if (n.has(s)) n.delete(s);
                  else n.add(s);
                  return n;
                })
              }
            >
              <Sev severity={s} /> {pool.filter((f) => f.severity === s).length}
            </button>
          ))}
        </div>
        <span className="spacer" />
        <span className="meta">{groups.length === list.length ? `${list.length} finding${list.length === 1 ? '' : 's'}` : `${groups.length} issues · ${list.length} findings`}</span>
        {groups.length > 0 && (
          <button className="linklike" onClick={() => setOpen(allOpen ? new Set() : new Set(groups.map((g) => g.key)))}>{allOpen ? 'Collapse all' : 'Expand all'}</button>
        )}
      </div>
      {picked.length > 0 && (
        <div className="bulk" role="region" aria-label="Actions for the selected findings">
          <span className="bulk-count" role="status">{picked.length} selected</span>
          {picked.length < list.length && <button className="linklike" onClick={() => setSel(new Set(list.map((f) => f.id)))}>Select all {list.length}</button>}
          <button className="linklike" onClick={clearSel}>Clear selection</button>
          <span className="spacer" />
          {showMuted ? (
            <button className="btn small" disabled={working} onClick={() => applyBulk({ status: 'clear' })}>Unmute {picked.length}</button>
          ) : mode === null ? (
            <>
              <button className="btn small" onClick={() => setMode('accepted')}>Accept risk</button>
              <button className="btn small" onClick={() => setMode('snoozed')}>Snooze</button>
              <button className="btn small" onClick={() => setMode('false-positive')}>Not an issue</button>
            </>
          ) : (
            <form
              className="triage-form"
              onSubmit={(e) => {
                e.preventDefault();
                void applyBulk({ status: mode, reason: reason.trim() || undefined, until: mode === 'snoozed' ? until : undefined });
              }}
            >
              {mode === 'snoozed' && (
                <select value={until} onChange={(e) => setUntil(e.target.value)} aria-label="Snooze for">
                  <option value="7d">1 week</option>
                  <option value="30d">1 month</option>
                  <option value="90d">3 months</option>
                </select>
              )}
              <input autoFocus value={reason} onChange={(e) => setReason(e.target.value)} maxLength={300} aria-label="Reason for all selected" placeholder={mode === 'accepted' ? 'Why is this OK? (optional)' : mode === 'snoozed' ? 'Note to self (optional)' : 'What did the check get wrong? (optional)'} />
              <button className="btn primary small" type="submit" disabled={working}>{working ? 'Working…' : `${mode === 'accepted' ? 'Accept' : mode === 'snoozed' ? 'Snooze' : 'Mark'} ${picked.length}`}</button>
              <button className="btn small quiet" type="button" onClick={() => setMode(null)}>Back</button>
            </form>
          )}
        </div>
      )}
      {!list.length && <div className="empty">{showMuted ? 'Nothing muted. Accepted, snoozed and dismissed findings appear here.' : 'No active findings.'}</div>}
      <div className="findings">
        {groups.map((g) => (
          <FindingGroup key={g.key} g={g} open={open.has(g.key)} onToggle={() => toggleGroup(g.key)} assets={assets} sel={sel} onPick={pick} onFix={onFix}>
            {g.items.map((f) => (
              <FindingCard
                key={f.id}
                f={f}
                asset={f.assetId ? assets.get(f.assetId) : undefined}
                related={f.related?.map((id) => assets.get(id)).filter((a): a is NonNullable<typeof a> => !!a)}
                showAsset
                titleless
                onSelect={(id) => onSelect(id, contextIds)}
                onFix={onFix}
                onTriage={onTriage}
                onAtlas={onAtlas}
              />
            ))}
          </FindingGroup>
        ))}
      </div>
    </div>
  );
}
