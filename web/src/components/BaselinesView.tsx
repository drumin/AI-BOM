import { useEffect, useMemo, useRef, useState } from 'react';
import { FIX_LABEL, post, sevRank, SEV_VAR, type Finding, type Inventory } from '../lib';
import { ErrorNote } from './ui';
import type { BaselineReport, ControlResult, ControlStatus, FrameworkId } from '../../../src/frameworks/baselines';
import type { AtlasView } from '../../../src/frameworks/atlas';

type Data = Record<FrameworkId, BaselineReport> & { atlas: AtlasView };
export type BaselineView = FrameworkId | 'atlas';
export type BaselineFilter = 'all' | 'attention' | 'answer';

const STATUS: Record<ControlStatus, { label: string; tone: string }> = {
  met: { label: 'In place', tone: 'ok' },
  attested: { label: 'You confirmed', tone: 'ok' },
  partial: { label: 'Partly', tone: 'warn' },
  gap: { label: 'Gap', tone: 'bad' },
  manual: { label: 'Needs your answer', tone: '' },
  na: { label: 'Not applicable', tone: '' },
};
const BAR: ControlStatus[] = ['met', 'attested', 'partial', 'gap', 'manual'];
const BAR_VAR: Record<string, string> = { met: '--status-good', attested: '--status-good', partial: '--status-warning', gap: '--status-critical', manual: '--axis' };

const label = (c: ControlResult) => (c.stale ? { label: 'Re-check', tone: 'warn' } : STATUS[c.status]);
const needsAttention = (c: ControlResult) => c.status === 'gap' || c.status === 'partial';
const needsAnswer = (c: ControlResult) => c.status === 'manual';
const inPlace = (c: ControlResult) => c.status === 'met' || c.status === 'attested';

/** Your setup against NIST AI RMF, ISO/IEC 42001 and MITRE ATLAS. */
export function BaselinesView({
  inv,
  view,
  onView,
  filter,
  onFilter,
  focusTechnique,
  onSelect,
  onFix,
}: {
  inv: Inventory;
  view: BaselineView;
  onView: (v: BaselineView) => void;
  filter: BaselineFilter;
  onFilter: (f: BaselineFilter) => void;
  /** A technique to open in the ATLAS view (from a finding's tag). */
  focusTechnique?: string;
  onSelect: (assetId: string) => void;
  onFix: (f: Finding) => void;
}) {
  const [data, setData] = useState<Data | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = () =>
    fetch('/api/baselines')
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then(setData)
      .catch((e) => setError((e as Error).message));
  useEffect(() => {
    load();
  }, [inv]);

  return (
    <div className="baselines">
      <div className="panel pad baselines-head">
        <div>
          <h3 className="section-title">How your setup measures up</h3>
          <p className="meta">
            NIST AI RMF and ISO/IEC 42001 are written for organizations. AI-BOM checks the parts your machine can show and asks you about the rest. MITRE
            ATLAS shows which known attack techniques your findings relate to. A self-assessment, not a certification.
          </p>
        </div>
        <div className="segmented" role="radiogroup" aria-label="Framework">
          {([['nist-ai-rmf', 'NIST AI RMF'], ['iso-42001', 'ISO/IEC 42001'], ['atlas', 'MITRE ATLAS']] as [BaselineView, string][]).map(([id, text]) => (
            <label key={id} className={view === id ? 'on' : ''}>
              <input type="radio" name="baseline" checked={view === id} onChange={() => onView(id)} />
              {text}
            </label>
          ))}
        </div>
      </div>
      {error && <ErrorNote message={`Couldn’t evaluate baselines: ${error}`} />}
      {!data && !error && <div className="panel empty"><span className="spinner" aria-hidden /> Evaluating…</div>}
      {data && view !== 'atlas' && <Framework report={data[view]} filter={filter} onFilter={onFilter} inv={inv} onSelect={onSelect} onFix={onFix} onChanged={load} />}
      {data && view === 'atlas' && <Atlas atlas={data.atlas} focusTechnique={focusTechnique} inv={inv} onSelect={onSelect} />}
    </div>
  );
}

function Framework({
  report,
  filter,
  onFilter,
  inv,
  onSelect,
  onFix,
  onChanged,
}: {
  report: BaselineReport;
  filter: BaselineFilter;
  onFilter: (f: BaselineFilter) => void;
  inv: Inventory;
  onSelect: (id: string) => void;
  onFix: (f: Finding) => void;
  onChanged: () => void;
}) {
  const c = report.counts;
  const total = BAR.reduce((n, s) => n + c[s], 0) || 1;
  const attention = report.controls.filter(needsAttention).length;
  const answer = report.controls.filter(needsAnswer).length;
  const shown = report.controls.filter((x) => (filter === 'attention' ? needsAttention(x) : filter === 'answer' ? needsAnswer(x) : true));
  const groups = [...new Set(shown.map((x) => x.group))];

  // Which controls are expanded. Starts with the gaps open; your choices survive reloads of the data.
  const [open, setOpen] = useState<Set<string>>(() => new Set(report.controls.filter((x) => x.status === 'gap').map((x) => x.id)));
  const seen = useRef(report.framework);
  useEffect(() => {
    if (seen.current !== report.framework) {
      seen.current = report.framework;
      setOpen(new Set(report.controls.filter((x) => x.status === 'gap').map((x) => x.id)));
    }
  }, [report]);
  const toggle = (id: string, to: boolean) =>
    setOpen((cur) => {
      const n = new Set(cur);
      if (to) n.add(id);
      else n.delete(id);
      return n;
    });
  const allOpen = shown.length > 0 && shown.every((x) => open.has(x.id));

  return (
    <>
      <div className="panel pad baseline-summary">
        <div className="coverage">
          <span className="tile-value">{report.coverage}%</span>
          <span className="meta">
            in place · {report.name} {report.version}{' '}
            <a href={report.url} target="_blank" rel="noopener">About</a>
          </span>
        </div>
        <div className="sevbar" role="img" aria-label={BAR.filter((s) => c[s]).map((s) => `${c[s]} ${STATUS[s].label}`).join(', ')}>
          {BAR.filter((s) => c[s]).map((s) => (
            <span key={s} style={{ width: `${(c[s] / total) * 100}%`, background: `var(${BAR_VAR[s]})` }} />
          ))}
        </div>
        <div className="sevlegend">
          {(['met', 'attested', 'partial', 'gap', 'manual', 'na'] as ControlStatus[]).filter((s) => c[s]).map((s) => (
            <span key={s} className="sevlegend-item">
              <span className={`status-dot ${STATUS[s].tone}`} aria-hidden /> <b>{c[s]}</b> {STATUS[s].label.toLowerCase()}
            </span>
          ))}
        </div>
        <div className="baseline-tools">
          <div className="segmented" role="radiogroup" aria-label="Which controls">
            {([['all', `All ${report.controls.length}`], ['attention', `Needs attention ${attention}`], ['answer', `Needs your answer ${answer}`]] as [BaselineFilter, string][]).map(([id, text]) => (
              <label key={id} className={filter === id ? 'on' : ''}>
                <input type="radio" name="baseline-filter" checked={filter === id} onChange={() => onFilter(id)} />
                {text}
              </label>
            ))}
          </div>
          <button className="btn small quiet" disabled={!shown.length} onClick={() => setOpen(allOpen ? new Set() : new Set(shown.map((x) => x.id)))}>
            {allOpen ? 'Collapse all' : 'Expand all'}
          </button>
        </div>
      </div>
      {shown.length === 0 && (
        <div className="panel empty">{filter === 'attention' ? 'Nothing needs attention here.' : 'Nothing is waiting on an answer.'} <button className="linklike" onClick={() => onFilter('all')}>Show all controls</button></div>
      )}
      {groups.map((g) => {
        const all = report.controls.filter((x) => x.group === g && x.status !== 'na');
        return (
          <div key={g} className="panel control-group">
            <div className="group-head">
              <h3 className="panel-title">{g}</h3>
              <span className="meta">{all.filter(inPlace).length} of {all.length} in place</span>
            </div>
            <ul className="controls">
              {shown.filter((x) => x.group === g).map((x) => (
                <Control key={x.id} c={x} framework={report.framework} open={open.has(x.id)} onToggle={(to) => toggle(x.id, to)} inv={inv} onSelect={onSelect} onFix={onFix} onChanged={onChanged} />
              ))}
            </ul>
          </div>
        );
      })}
    </>
  );
}

function Control({
  c,
  framework,
  open,
  onToggle,
  inv,
  onSelect,
  onFix,
  onChanged,
}: {
  c: ControlResult;
  framework: FrameworkId;
  open: boolean;
  onToggle: (open: boolean) => void;
  inv: Inventory;
  onSelect: (id: string) => void;
  onFix: (f: Finding) => void;
  onChanged: () => void;
}) {
  const [note, setNote] = useState(c.attestation?.note ?? '');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const s = label(c);
  const findings = c.findings.map((id) => inv.findings.find((f) => f.id === id)).filter(Boolean) as Finding[];
  const fixable = findings.find((f) => !f.muted && f.fixes?.length);
  const save = async (status?: 'done' | 'na') => {
    setBusy(true);
    setErr(null);
    try {
      await post('/api/baselines/attest', { framework, control: c.id, status, note });
      onChanged();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <li>
      <details open={open} onToggle={(e) => onToggle((e.currentTarget as HTMLDetailsElement).open)}>
        <summary>
          <span className={`pill ${s.tone}`}>{s.label}</span>
          <span className="mono control-id">{c.id}</span>
          <span className="control-title">{c.title}</span>
          {c.org && <span className="meta">organization</span>}
          <span className="spacer" />
          <span className="meta">{c.auto ? 'from your scan' : 'your answer'}</span>
        </summary>
        <div className="control-body">
          <p className="meta">{c.ask}</p>
          {c.stale && c.attestation && <p className="callout warn">You confirmed this on {new Date(c.attestation.at).toLocaleDateString()}. Confirm again if it is still true.</p>}
          {c.evidence.length > 0 && <ul className="plain">{c.evidence.map((e) => <li key={e}>{e}</li>)}</ul>}
          {c.action && <p className="callout">{c.action}</p>}
          {fixable && (
            <div className="actions">
              <button className="btn primary small" onClick={() => onFix(fixable)}>{FIX_LABEL[fixable.fixes![0]]}…</button>
              <span className="meta">for “{fixable.title}”</span>
            </div>
          )}
          {findings.length > 0 && (
            <ul className="control-findings">
              {findings.slice(0, 8).map((f) => (
                <li key={f.id}>
                  <span className="dot" style={{ background: `var(${SEV_VAR[f.severity]})` }} aria-hidden />
                  {f.assetId ? <button className="linklike" onClick={() => onSelect(f.assetId!)}>{f.title}</button> : f.title}
                  {f.assetId && <span className="meta">{inv.assets.find((a) => a.id === f.assetId)?.name}</span>}
                </li>
              ))}
              {findings.length > 8 && <li className="meta">and {findings.length - 8} more in Findings</li>}
            </ul>
          )}
          {!c.auto && (
            <div className="attest">
              {c.hint && <p className="meta">Done looks like: {c.hint}</p>}
              <textarea className="input" rows={2} aria-label={`Note for ${c.id}: ${c.title}`} placeholder="Optional note (where it’s written down, what you decided)" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} />
              <div className="actions">
                <button className="btn primary small" disabled={busy} onClick={() => save('done')}>{c.status === 'attested' || c.stale ? 'Confirm again' : 'Mark as done'}</button>
                <button className="btn small" disabled={busy} onClick={() => save('na')}>Not applicable to me</button>
                {c.attestation && <button className="btn small" disabled={busy} onClick={() => save(undefined)}>Clear</button>}
                {c.attestation && !c.stale && <span className="meta">Saved {new Date(c.attestation.at).toLocaleDateString()}. We’ll ask again after 90 days.</span>}
              </div>
              {err && <ErrorNote message={err} />}
            </div>
          )}
        </div>
      </details>
    </li>
  );
}

function Atlas({ atlas, focusTechnique, inv, onSelect }: { atlas: AtlasView; focusTechnique?: string; inv: Inventory; onSelect: (id: string) => void }) {
  const [open, setOpen] = useState<string | null>(focusTechnique ?? null);
  const detail = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!focusTechnique) return;
    setOpen(focusTechnique);
    requestAnimationFrame(() => detail.current?.scrollIntoView({ block: 'nearest', behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' }));
  }, [focusTechnique]);
  const techniques = useMemo(() => atlas.tactics.flatMap((t) => t.techniques.map((x) => ({ ...x, tactic: t.name }))), [atlas]);
  const opened = open ? techniques.find((t) => t.id === open) : undefined;
  // The same technique can appear under several tactics; list each once.
  const top = useMemo(() => {
    const seen = new Set<string>();
    return techniques
      .filter((t) => t.findings.length && !seen.has(t.id) && !!seen.add(t.id))
      .sort((a, b) => sevRank(a.worst) - sevRank(b.worst) || b.findings.length - a.findings.length)
      .slice(0, 3);
  }, [techniques]);
  const tactics = atlas.tactics.filter((t) => t.techniques.some((x) => x.findings.length)).length;

  return (
    <>
      <div className="panel pad baseline-summary">
        <div className="coverage">
          <span className="tile-value">{atlas.seen}</span>
          <span className="meta">
            of {atlas.checked} techniques AI-BOM checks for have open findings, across {tactics} tactic{tactics === 1 ? '' : 's'} · ATLAS {atlas.version}{' '}
            <a href="https://atlas.mitre.org/matrices/ATLAS" target="_blank" rel="noopener">Matrix</a>
          </span>
        </div>
        {top.length > 0 && (
          <div className="atlas-top">
            <span className="meta">Start with</span>
            {top.map((t) => (
              <button key={t.id} className="chip" onClick={() => setOpen(t.id)} aria-pressed={open === t.id}>
                <span className="dot" style={{ background: `var(${SEV_VAR[t.worst ?? 'info']})` }} aria-hidden />
                {t.name} <b>{t.findings.length}</b>
              </button>
            ))}
          </div>
        )}
        <p className="meta">Tactics are the attacker’s goal; techniques are how. Dim techniques were checked and nothing was found. Muted findings are left out.</p>
      </div>
      {opened && (
        <div className="panel pad" ref={detail}>
          <h3 className="section-title">
            {opened.name} <a className="meta" href={`https://atlas.mitre.org/techniques/${opened.id}`} target="_blank" rel="noopener">{opened.id} on atlas.mitre.org</a>
          </h3>
          <ul className="control-findings">
            {opened.findings.map((id) => inv.findings.find((f) => f.id === id)).filter((f): f is Finding => !!f).map((f) => (
              <li key={f.id}>
                <span className="dot" style={{ background: `var(${SEV_VAR[f.severity]})` }} aria-hidden />
                {f.assetId ? <button className="linklike" onClick={() => onSelect(f.assetId!)}>{f.title}</button> : f.title}
                {f.assetId && <span className="meta">{inv.assets.find((a) => a.id === f.assetId)?.name}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="atlas-grid">
        {atlas.tactics.map((t) => (
          <section key={t.id} className="panel atlas-tactic" aria-label={t.name}>
            <h3 className="panel-title">{t.name}</h3>
            <ul>
              {t.techniques.map((x) => (
                <li key={x.id}>
                  <button
                    className={`atlas-tech${x.findings.length ? ' hit' : ''}${open === x.id ? ' on' : ''}`}
                    disabled={!x.findings.length}
                    onClick={() => setOpen(open === x.id ? null : x.id)}
                    aria-expanded={x.findings.length ? open === x.id : undefined}
                  >
                    <span className="atlas-count" style={x.worst ? { background: `color-mix(in srgb, var(${SEV_VAR[x.worst]}) 26%, var(--surface-1))`, boxShadow: `inset 0 0 0 1px var(${SEV_VAR[x.worst]})` } : undefined}>{x.findings.length || '·'}</span>
                    <span className="atlas-name">{x.name}<span className="mono atlas-id">{x.id}</span></span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
        ))}
      </div>
    </>
  );
}
