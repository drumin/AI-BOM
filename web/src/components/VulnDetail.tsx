import { useState } from 'react';
import type { Finding } from '../lib';

const SOURCE_LABEL: Record<string, string> = { bundled: 'AI-BOM advisories', osv: 'OSV.dev', nvd: 'NIST NVD' };
const HOW: Record<string, string> = {
  pinned: 'Pinned in your config',
  installed: 'Cached copy on disk',
  latest: 'Latest release (unpinned)',
  unknown: 'Version unknown',
};

/** CVSS score chip. The score is a label; severity is carried by the finding's icon. */
export function Cvss({ v }: { v: NonNullable<Finding['vuln']>['cvss'] }) {
  if (!v) return null;
  return (
    <span className="cvss" title={v.vector ?? undefined}>
      CVSS{v.version ? ` ${v.version}` : ''} <b>{v.score.toFixed(1)}</b>
    </span>
  );
}

export function VulnDetail({ f }: { f: Finding }) {
  const v = f.vuln;
  const [copied, setCopied] = useState(false);
  if (!v) return null;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(v.fixCommand!);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* clipboard unavailable: the command stays selectable */
    }
  };
  return (
    <div className="vuln">
      <div className="vuln-facts">
        <Cvss v={v.cvss} />
        {v.version !== 'any' && (
          <span className="fact"><span className="meta">Runs</span> <b className="mono">{v.version}</b> <span className="meta">· {HOW[v.versionSource]}</span></span>
        )}
        {v.fixedVersion && <span className="fact"><span className="meta">Fixed in</span> <b className="mono">{v.fixedVersion}</b></span>}
        {v.cwe?.map((c) => <span key={c} className="tag">{c}</span>)}
        {v.confidence === 'possible' && <span className="tag strong">Needs checking</span>}
      </div>
      {v.fixCommand && (
        <div className="fixcmd">
          <span className="fixcmd-label">Use this call instead</span>
          <div className="fixcmd-row">
            <code className="mono">{v.fixCommand}</code>
            <button className="btn small" onClick={copy} aria-live="polite">{copied ? 'Copied' : 'Copy'}</button>
          </div>
        </div>
      )}
      <div className="meta vuln-src">Source: {v.sources.map((s) => SOURCE_LABEL[s] ?? s).join(', ')}</div>
    </div>
  );
}
