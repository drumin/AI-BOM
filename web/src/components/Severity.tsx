import { SEV_VAR, type Severity } from '../lib';

const LABEL: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

/** Status is always icon + label, never color alone. */
export function SevIcon({ severity }: { severity: Severity }) {
  const color = `var(${SEV_VAR[severity]})`;
  if (severity === 'critical')
    return (
      <svg className="sev-icon" viewBox="0 0 16 16" aria-hidden>
        <path d="M5 1h6l4 4v6l-4 4H5l-4-4V5z" fill={color} />
        <path d="M8 4.5v4.5M8 11v.5" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" />
      </svg>
    );
  if (severity === 'high')
    return (
      <svg className="sev-icon" viewBox="0 0 16 16" aria-hidden>
        <path d="M8 1.5l7 12.5H1z" fill={color} />
        <path d="M8 6v4M8 12v.2" stroke="#fff" strokeWidth="1.7" strokeLinecap="round" />
      </svg>
    );
  if (severity === 'medium')
    return (
      <svg className="sev-icon" viewBox="0 0 16 16" aria-hidden>
        <rect x="2.5" y="2.5" width="11" height="11" rx="2" transform="rotate(45 8 8)" fill={color} />
        <path d="M8 5.2v3.6M8 10.6v.2" stroke="#0b0b0b" strokeWidth="1.6" strokeLinecap="round" />
      </svg>
    );
  return (
    <svg className="sev-icon" viewBox="0 0 16 16" aria-hidden>
      <circle cx="8" cy="8" r="6.5" fill={color} />
      <path d="M8 7v4.2M8 4.8v.2" stroke="#fff" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

export function Sev({ severity }: { severity?: Severity }) {
  if (!severity) return <span className="sev sev-none">—</span>;
  return (
    <span className="sev">
      <SevIcon severity={severity} />
      {LABEL[severity]}
    </span>
  );
}
