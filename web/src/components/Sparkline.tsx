import { useState } from 'react';

/**
 * Single-series trend (security score over scans). One hue, 2px line,
 * recessive baseline, crosshair + tooltip on hover. No legend: the tile names it.
 */
export function Sparkline({ points, width = 220, height = 44, label }: { points: { at: string; value: number }[]; width?: number; height?: number; label: string }) {
  const [hover, setHover] = useState<number | null>(null);
  if (points.length < 2) return null;
  const pad = 4;
  const xs = (i: number) => pad + (i / (points.length - 1)) * (width - pad * 2);
  const ys = (v: number) => pad + (1 - v / 100) * (height - pad * 2);
  const d = points.map((p, i) => `${i ? 'L' : 'M'}${xs(i).toFixed(1)},${ys(p.value).toFixed(1)}`).join(' ');
  const h = hover !== null ? points[hover] : undefined;
  return (
    <div className="sparkline" style={{ width }}>
      <svg
        width={width}
        height={height}
        role="img"
        aria-label={`${label}: from ${points[0].value} to ${points[points.length - 1].value} over ${points.length} scans`}
        onPointerMove={(e) => {
          const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
          const i = Math.round(((e.clientX - r.left - pad) / (width - pad * 2)) * (points.length - 1));
          setHover(Math.max(0, Math.min(points.length - 1, i)));
        }}
        onPointerLeave={() => setHover(null)}
      >
        <line x1={pad} x2={width - pad} y1={ys(0)} y2={ys(0)} className="spark-base" />
        <path d={d} className="spark-line" />
        {h && hover !== null && (
          <>
            <line x1={xs(hover)} x2={xs(hover)} y1={pad} y2={height - pad} className="spark-cross" />
            <circle cx={xs(hover)} cy={ys(h.value)} r={4} className="spark-dot" />
          </>
        )}
        {!h && <circle cx={xs(points.length - 1)} cy={ys(points[points.length - 1].value)} r={3.5} className="spark-dot" />}
      </svg>
      {h && hover !== null && (
        <div className="spark-tip">
          <b>{h.value}</b> · {new Date(h.at).toLocaleDateString([], { month: 'short', day: 'numeric' })}
        </div>
      )}
    </div>
  );
}
