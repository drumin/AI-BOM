import { useRef } from 'react';
import { KIND_LABEL, SEV_VAR, SEVERITIES, worst, type AssetKind, type Inventory, type Severity } from '../lib';
import { IconTile } from './ui';
import { SevIcon } from './Severity';
import { Sparkline } from './Sparkline';

const TILES: { label: string; kinds: AssetKind[] }[] = [
  { label: 'MCP servers', kinds: ['mcp-server'] },
  { label: 'Skills', kinds: ['skill'] },
  { label: 'Plugins & extensions', kinds: ['plugin', 'extension'] },
  { label: 'Agents & commands', kinds: ['agent', 'command'] },
  { label: 'Hooks & telemetry', kinds: ['hook', 'telemetry'] },
  { label: 'Instruction files', kinds: ['instructions'] },
  { label: 'Cloud connectors', kinds: ['connector'] },
  { label: 'Keys, models & apps', kinds: ['api-key', 'model', 'browser-extension', 'app'] },
];

/** "AI API keys" keeps its acronym; "Local models" becomes "local models". */
const lower = (s: string) => (/^[A-Z]{2}/.test(s) ? s : s[0].toLowerCase() + s.slice(1));

const GRADE_TONE: Record<string, string> = { A: 'ok', B: 'ok', C: 'warn', D: 'bad', F: 'bad' };

export function Summary({
  inv,
  onPick,
  trend = [],
  onNext,
  onFindings,
}: {
  inv: Inventory;
  onPick: (kinds: AssetKind[]) => void;
  /** Open the Findings tab, optionally on one severity or on the muted findings. */
  onFindings?: (show?: { severity?: Severity; muted?: boolean }) => void;
  /** Score per recorded scan, oldest first. */
  trend?: { at: string; value: number }[];
  onNext?: (findingId: string) => void;
}) {
  const active = inv.findings.filter((f) => !f.muted);
  const counts = active.reduce<Record<string, number>>((m, f) => ((m[f.severity] = (m[f.severity] ?? 0) + 1), m), {});
  const total = active.length;
  const muted = inv.findings.length - total;
  const remote = inv.assets.filter((a) => a.kind === 'mcp-server' && (a.mcp?.url || a.mcp?.remoteUrl)).length;

  const strip = TILES.map((t) => {
    const items = inv.assets.filter((a) => t.kinds.includes(a.kind));
    return { ...t, items };
  }).filter((t) => t.items.length || t.kinds[0] !== 'api-key');

  return (
    <section className="summary" aria-label="Summary">
      <div className="hero">
        {inv.score && <ScoreTile score={inv.score} trend={trend} onFindings={() => onFindings?.()} />}
        <div className="tile risk-tile">
          <span className="tile-label">Findings</span>
          {total > 0 ? (
            <button className="link count-link" onClick={() => onFindings?.()} title="Show all findings" aria-label={`${total} findings. Show them`}>
              <span className="tile-value">{total}</span>
            </button>
          ) : (
            <span className="tile-value">{total}</span>
          )}
          {total > 0 ? (
            <>
              <div className="sevbar" role="img" aria-label={SEVERITIES.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(', ')}>
                {SEVERITIES.filter((s) => counts[s]).map((s) => (
                  <span key={s} style={{ width: `${(counts[s] / total) * 100}%`, background: `var(${SEV_VAR[s]})` }} />
                ))}
              </div>
              <div className="sevlegend">
                {SEVERITIES.filter((s) => counts[s]).map((s) => (
                  <button key={s} className="sevlegend-item link" onClick={() => onFindings?.({ severity: s })} title={`Show only ${s} findings`}>
                    <SevIcon severity={s} /> <b>{counts[s]}</b> {s}
                  </button>
                ))}
              </div>
            </>
          ) : (
            <span className="tile-sub">Nothing risky found</span>
          )}
          {muted > 0 && (
            <button className="tile-sub link" onClick={() => onFindings?.({ muted: true })} title="Show the findings you muted">
              {muted} muted by you
            </button>
          )}
        </div>
        {inv.score && <FixFirst next={inv.score.next} onNext={onNext} />}
      </div>

      <div className="stat-strip" role="group" aria-label="What was found">
        {strip.map((t) => {
          const fresh = t.items.filter((a) => a.isNew).length;
          const top = worst(t.items.map((a) => a.risk));
          const detail = [
            fresh > 0 ? `+${fresh} new` : '',
            t.kinds[0] === 'mcp-server' && remote > 0 ? `${remote} remote` : '',
            t.kinds.length > 1
              ? t.kinds
                  .map((k) => [k, inv.assets.filter((a) => a.kind === k).length] as const)
                  .filter(([, n]) => n)
                  .map(([k, n]) => `${n} ${lower(n === 1 ? KIND_LABEL[k].one : KIND_LABEL[k].many)}`)
                  .join(' · ')
              : '',
          ].filter(Boolean).join(' · ');
          return (
            <button
              key={t.label}
              className="stat"
              data-risk={top === 'critical' || top === 'high' ? top : undefined}
              onClick={() => onPick(t.kinds)}
              title={`Show ${t.label.toLowerCase()} in the inventory${detail ? ` (${detail})` : ''}`}
            >
              <IconTile kind={t.kinds[0]} size="sm" />
              <span className="stat-value">{t.items.length}</span>
              <span className="stat-label">{t.label}</span>
              {fresh > 0 && <span className="stat-new">+{fresh}</span>}
              {top && (top === 'critical' || top === 'high') && <span className="stat-risk" style={{ ['--sev' as string]: `var(${SEV_VAR[top]})` }}><SevIcon severity={top} /><span className="sr-only">has {top} findings</span></span>}
            </button>
          );
        })}
      </div>
    </section>
  );
}

const RING = 2 * Math.PI * 38;

function ScoreTile({ score, trend, onFindings }: { score: NonNullable<Inventory['score']>; trend: { at: string; value: number }[]; onFindings: () => void }) {
  const prev = trend.length > 1 ? trend[trend.length - 2].value : undefined;
  const delta = prev === undefined ? 0 : score.value - prev;
  const lastGrade = useRef(score.grade);
  const improved = lastGrade.current !== score.grade && score.grade < lastGrade.current;
  lastGrade.current = score.grade;
  const tone = GRADE_TONE[score.grade];
  const pct = Math.max(0, Math.min(100, score.value)) / 100;
  return (
    <div className="tile score-tile">
      <span className="tile-label">Security score</span>
      <button className="score-row link" onClick={onFindings} title="See the findings behind this score" aria-label={`Score ${score.value}, grade ${score.grade}. See the findings behind it`}>
        <span className="score-ring">
          <svg className={`ring-chart ${tone}`} width="92" height="92" viewBox="0 0 92 92" aria-hidden>
            <circle className="ring-track" cx="46" cy="46" r="38" />
            <circle className="ring-arc" cx="46" cy="46" r="38" strokeDasharray={RING} strokeDashoffset={RING * (1 - pct)} transform="rotate(-90 46 46)" />
          </svg>
          <span className="ring-center">
            <span className="tile-value">{score.value}</span>
            <span key={score.grade} className={`grade ${tone}${improved ? ' up' : ''}`} aria-hidden="true">{score.grade}</span>
          </span>
        </span>
        {delta !== 0 && <span className={`delta ${delta > 0 ? 'up' : 'down'}`}>{delta > 0 ? '▲' : '▼'} {Math.abs(delta)}</span>}
      </button>
      <Sparkline points={trend} label="Security score over recent scans" width={200} height={32} />
    </div>
  );
}

/** The few changes that raise the score most, in order. */
function FixFirst({ next, onNext }: { next: NonNullable<Inventory['score']>['next']; onNext?: (id: string) => void }) {
  if (!next.length) {
    return (
      <div className="tile fix-first">
        <span className="tile-label">Fix these first</span>
        <span className="tile-sub">Nothing left to fix</span>
      </div>
    );
  }
  return (
    <div className="tile fix-first">
      <span className="tile-label">Fix these first</span>
      <ol className="fix-list">
        {next.slice(0, 3).map((n, i) => (
          <li key={n.findingId}>
            <button className="next-action" onClick={() => onNext?.(n.findingId)}>
              <span className="next-num" aria-hidden>{i + 1}</span>
              <span className="next-title">{n.fix ?? n.title}</span>
              <span className="next-gain" title="Points this would add to your score">+{n.gain}</span>
            </button>
          </li>
        ))}
      </ol>
    </div>
  );
}
