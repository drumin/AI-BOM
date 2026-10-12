import { KIND_VAR, monogram, SEV_VAR, sevRank, type Asset, type AssetKind, type ClientId, type Severity } from '../lib';
import { KindMark } from './KindMark';
import { SevIcon } from './Severity';

/**
 * Small, consistent building blocks. Color is used sparingly: asset types
 * appear as soft tinted tiles, tools as neutral tiles, and saturated color is
 * kept for risk.
 */

export function IconTile({ kind, size = 'md' }: { kind: AssetKind; size?: 'sm' | 'md' }) {
  return (
    <span className={`icon-tile ${size}`} style={{ ['--tile' as string]: `var(${KIND_VAR[kind]})` }} aria-hidden>
      <KindMark kind={kind} size={size === 'sm' ? 11 : 15} />
    </span>
  );
}

export function ToolTile({ id, name, size = 'md' }: { id: ClientId; name: string; size?: 'sm' | 'md' }) {
  const cloud = id.startsWith('cloud:');
  return (
    <span className={`tool-tile ${size}${cloud ? ' cloud' : ''}`} aria-hidden>
      {monogram(id, name)}
    </span>
  );
}

export function CountPill({ n, label }: { n: number; label?: string }) {
  return (
    <span className="count-pill" aria-label={label ? `${n} ${label}` : undefined}>
      {n}
    </span>
  );
}

const WORD: Record<Severity, string> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' };

/** "3 issues" with the worst severity's icon and tint; the breakdown is in the tooltip. */
export function RiskPill({ assets, severities }: { assets?: Asset[]; severities?: (Severity | undefined)[] }) {
  const list = (severities ?? (assets ?? []).map((a) => a.risk)).filter((s): s is Severity => !!s && s !== 'info');
  if (!list.length) {
    return (
      <span className="risk-pill ok">
        <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden><path d="M2.5 6.2l2.3 2.3 4.7-5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
        No issues
      </span>
    );
  }
  const top = [...list].sort((a, b) => sevRank(a) - sevRank(b))[0];
  const counts = (['critical', 'high', 'medium', 'low'] as Severity[]).map((s) => [s, list.filter((x) => x === s).length] as const).filter(([, n]) => n);
  const breakdown = counts.map(([s, n]) => `${n} ${WORD[s]}`).join(', ');
  return (
    <span className="risk-pill" style={{ ['--sev' as string]: `var(${SEV_VAR[top]})` }} title={breakdown} aria-label={`${list.length} with issues: ${breakdown}`}>
      <SevIcon severity={top} />
      {list.length} {list.length === 1 ? 'issue' : 'issues'}
    </span>
  );
}

/** Single severity as a labelled pill (for one asset). */
export function SevPill({ severity }: { severity?: Severity }) {
  if (!severity || severity === 'info') return null;
  return (
    <span className="risk-pill" style={{ ['--sev' as string]: `var(${SEV_VAR[severity]})` }}>
      <SevIcon severity={severity} />
      {severity[0].toUpperCase() + severity.slice(1)}
    </span>
  );
}

export function Chevron({ open }: { open: boolean }) {
  return (
    <svg className={`chev${open ? ' open' : ''}`} width="16" height="16" viewBox="0 0 16 16" aria-hidden>
      <path d="M4.5 6.5l3.5 3.5 3.5-3.5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** An error that is announced when it appears and says what to do next. */
export function ErrorNote({ message, hint = true }: { message: string; hint?: boolean }) {
  return (
    <div className="callout warn" role="alert">
      {message}
      {hint && <div className="meta">Try again. If it keeps happening, run <code>ai-bom doctor</code> in a terminal.</div>}
    </div>
  );
}
