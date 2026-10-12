import { useEffect, useRef, useState } from 'react';
import { SEV_VAR, type Severity } from '../lib';
import { SevIcon } from './Severity';

export interface TrendRow {
  at: string;
  active: Partial<Record<Severity, number>>;
}

/** Worst at the bottom, so each band can be compared from the same baseline. */
const STACK: Severity[] = ['critical', 'high', 'medium', 'low'];
const WORD: Record<Severity, string> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' };

const when = (iso: string) => new Date(iso).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
const day = (iso: string) => new Date(iso).toLocaleDateString([], { month: 'short', day: 'numeric' });

/** A round top for the axis that is close to the data (so 68 gets 80, not 100). */
function niceMax(v: number): number {
  if (v <= 4) return Math.max(v, 1);
  const p = 10 ** Math.floor(Math.log10(v));
  return [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10].map((m) => m * p).find((m) => m >= v)!;
}

/**
 * Findings per scan, stacked by severity. One axis, thin bars with a 2px gap between bands, recessive grid,
 * severity named in the legend with its icon (never color alone). Every column is focusable and spoken in
 * full; the Scans table below is the data table for it.
 */
export function SeverityTrend({ rows, max = 30, height = 180 }: { rows: TrendRow[]; max?: number; height?: number }) {
  const wrap = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(640);
  const [active, setActive] = useState<number | null>(null);
  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setWidth(Math.max(240, Math.round(el.clientWidth))));
    ro.observe(el);
    setWidth(Math.max(240, Math.round(el.clientWidth)));
    return () => ro.disconnect();
  }, []);

  const data = rows.slice(-max);
  if (data.length < 2) return null;
  const left = 34;
  const right = 8;
  const top = 10;
  const bottom = 24;
  const plotW = width - left - right;
  const plotH = height - top - bottom;
  const totals = data.map((r) => STACK.reduce((n, s) => n + (r.active[s] ?? 0), 0));
  const yMax = niceMax(Math.max(...totals, 1));
  const y = (v: number) => top + plotH - (v / yMax) * plotH;
  const slot = plotW / data.length;
  const barW = Math.max(6, Math.min(28, slot - 4));
  const x = (i: number) => left + slot * i + (slot - barW) / 2;
  const ticks = [0, yMax / 2, yMax].filter((v, i, a) => a.indexOf(v) === i);
  const first = totals[0];
  const last = totals[totals.length - 1];
  const summary = `Findings per scan, ${data.length} scans from ${day(data[0].at)} to ${day(data[data.length - 1].at)}. ${first} at the start, ${last} now.`;
  const present = STACK.filter((s) => data.some((r) => r.active[s]));
  const tip = active !== null ? data[active] : null;

  return (
    <div className="trend" ref={wrap}>
      <svg width={width} height={height} role="group" aria-label={summary} onPointerLeave={() => setActive(null)}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={left} x2={width - right} y1={y(t)} y2={y(t)} className={t === 0 ? 'trend-base' : 'trend-grid'} />
            <text x={left - 6} y={y(t) + 4} textAnchor="end" className="trend-axis">{t}</text>
          </g>
        ))}
        {data.map((r, i) => {
          let acc = 0;
          const label = `${when(r.at)}: ${STACK.map((s) => `${r.active[s] ?? 0} ${WORD[s]}`).join(', ')}`;
          const bands = STACK.map((s) => ({ s, n: r.active[s] ?? 0 })).filter((b) => b.n > 0);
          return (
            <g
              key={r.at + i}
              className="trend-col"
              data-active={active === i}
              tabIndex={0}
              role="img"
              aria-label={label}
              onPointerEnter={() => setActive(i)}
              onFocus={() => setActive(i)}
              onBlur={() => setActive(null)}
            >
              <rect x={left + slot * i} y={top} width={slot} height={plotH} className="trend-hit" />
              {bands.map((b, k) => {
                const y0 = y(acc);
                acc += b.n;
                const y1 = y(acc);
                const isTop = k === bands.length - 1;
                // 2px of surface between bands; the top band gets a rounded end.
                const h = Math.max(1, y0 - y1 - (isTop ? 0 : 2));
                const common = { x: x(i), y: y1, width: barW, height: h, fill: `var(${SEV_VAR[b.s]})` };
                return isTop && h > 4 ? <path key={b.s} d={`M${common.x},${common.y + h} V${common.y + 4} Q${common.x},${common.y} ${common.x + 4},${common.y} H${common.x + barW - 4} Q${common.x + barW},${common.y} ${common.x + barW},${common.y + 4} V${common.y + h} Z`} fill={common.fill} /> : <rect key={b.s} {...common} />;
              })}
            </g>
          );
        })}
        <text x={left} y={height - 6} className="trend-axis">{day(data[0].at)}</text>
        <text x={width - right} y={height - 6} textAnchor="end" className="trend-axis">{day(data[data.length - 1].at)}</text>
      </svg>
      {tip && active !== null && (
        <div className="trend-tip" style={{ left: Math.min(Math.max(left + slot * active + slot / 2, 90), width - 90) }}>
          <b>{when(tip.at)}</b>
          {STACK.filter((s) => tip.active[s]).map((s) => (
            <span key={s}><SevIcon severity={s} /> {tip.active[s]} {WORD[s]}</span>
          ))}
          {!STACK.some((s) => tip.active[s]) && <span>No findings</span>}
        </div>
      )}
      <div className="sevlegend" aria-hidden>
        {present.map((s) => (
          <span key={s} className="sevlegend-item"><SevIcon severity={s} /> {WORD[s]}</span>
        ))}
      </div>
    </div>
  );
}
