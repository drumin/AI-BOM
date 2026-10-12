import { Fragment, useEffect, useMemo, useState, type CSSProperties, type ReactNode } from 'react';
import { post, SEV_VAR, type Asset, type Finding } from '../lib';
import { Sev } from './Severity';
import { ErrorNote } from './ui';
import { Sheet } from './Sheet';
import { Markdown } from './Markdown';

interface SourceFile {
  name: string;
  format: 'markdown' | 'json' | 'text';
  text: string;
  truncated?: boolean;
}

const JSON_TOKEN = /("(?:[^"\\]|\\.)*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

function jsonLine(line: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  JSON_TOKEN.lastIndex = 0;
  while ((m = JSON_TOKEN.exec(line))) {
    if (m.index > last) nodes.push(line.slice(last, m.index));
    const cls = m[1] ? (m[2] ? 'j-key' : 'j-str') : m[3] ? 'j-lit' : 'j-num';
    nodes.push(<span key={m.index} className={cls}>{m[1] ?? m[3] ?? m[4]}</span>);
    if (m[2]) nodes.push(m[2]);
    last = m.index + m[0].length;
  }
  nodes.push(line.slice(last));
  return nodes;
}

/** Pretty-print strict JSON; keep JSONC (comments, formatting) as written. */
function prettyJson(text: string): string {
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; }
}

/**
 * Find the lines a finding points at. Evidence is a short redacted excerpt, and the file text is
 * redacted the same way, so it usually appears verbatim; otherwise fall back to its longest word.
 */
function locate(lines: string[], evidence: string): number[] {
  const ev = evidence.trim().replace(/…$/, '');
  if (ev.length < 3) return [];
  const text = lines.join('\n');
  const at = text.indexOf(ev);
  if (at >= 0) {
    const first = text.slice(0, at).split('\n').length - 1;
    return Array.from({ length: ev.split('\n').length }, (_, n) => first + n);
  }
  const tokens = [...new Set(ev.split(/\s+/).map((t) => t.replace(/^["'`]+|["'`,]+$/g, '')).filter((t) => t.length >= 6))].sort((a, b) => b.length - a.length);
  for (const t of tokens) {
    const i = lines.findIndex((l) => l.includes(t));
    if (i >= 0) return [i];
  }
  return [];
}

interface Hit { finding: Finding; line: number }

function Lines({ text, json, hits }: { text: string; json: boolean; hits: Hit[] }) {
  const lines = text.split('\n');
  const byLine = new Map<number, Finding[]>();
  for (const h of hits) byLine.set(h.line, [...(byLine.get(h.line) ?? []), h.finding]);
  return (
    <pre className="src-code">
      {lines.map((l, i) => {
        const fs = byLine.get(i);
        const top = fs?.[0];
        return (
          <Fragment key={i}>
            <span
              className={`src-line${fs ? ' flagged' : ''}`}
              data-finding={top?.id}
              style={top ? ({ '--hl': `var(${SEV_VAR[top.severity]})` } as CSSProperties) : undefined}
            >
              {l === '' ? '\u200b' : json ? jsonLine(l) : l}
            </span>
            {fs && fs.map((f) => (
              <span key={f.id} className="src-note" style={{ '--hl': `var(${SEV_VAR[f.severity]})` } as CSSProperties}>
                <Sev severity={f.severity} />
                <span className="src-note-title">{f.title}</span>
              </span>
            ))}
          </Fragment>
        );
      })}
    </pre>
  );
}

/** Read-only view of the files behind an asset (secrets already masked by the server), with its findings marked. */
export function SourceSheet({ asset, findings, onClose }: { asset: Asset; findings: Finding[]; onClose: () => void }) {
  const [files, setFiles] = useState<SourceFile[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [active, setActive] = useState(0);
  const [raw, setRaw] = useState<boolean | undefined>(undefined);

  useEffect(() => {
    post<{ files: SourceFile[] }>('/api/asset/source', { assetId: asset.id })
      .then((r) => setFiles(r.files))
      .catch((e) => setError((e as Error).message));
  }, [asset.id]);

  const shown = useMemo(
    () => (files ?? []).map((x) => (x.format === 'json' ? { ...x, text: prettyJson(x.text) } : x)),
    [files],
  );
  const live = findings.filter((f) => !f.muted && f.evidence);
  const hitsByFile = useMemo(
    () => shown.map((x) => {
      const lines = x.text.split('\n');
      return live.flatMap((f) => locate(lines, f.evidence!).map((line) => ({ finding: f, line })));
    }),
    [shown, live],
  );
  const placed = new Set(hitsByFile.flat().map((h) => h.finding.id));
  const unplaced = findings.filter((f) => !f.muted && !placed.has(f.id));

  const f = shown[active];
  const hits = hitsByFile[active] ?? [];
  // Formatted Markdown can't mark lines, so open on the source view when there is something to show.
  const showSource = raw ?? hits.length > 0;
  return (
    <Sheet title={asset.name} onClose={onClose} wide>
      {error && <ErrorNote message={error} hint={false} />}
      {!files && !error && <p className="meta"><span className="spinner" aria-hidden /> Reading…</p>}
      {f && (
        <>
          <div className="src-bar">
            {shown.length > 1 ? (
              <select value={active} onChange={(e) => { setActive(Number(e.target.value)); setRaw(undefined); }} aria-label="File">
                {shown.map((x, n) => <option key={x.name} value={n}>{x.name}{hitsByFile[n]?.length ? ` · ${new Set(hitsByFile[n].map((h) => h.finding.id)).size} flagged` : ''}</option>)}
              </select>
            ) : (
              <span className="mono">{f.name}</span>
            )}
            {f.format === 'markdown' && <button className="btn small" onClick={() => setRaw(!showSource)}>{showSource ? 'Show formatted' : 'Show source'}</button>}
          </div>
          <div className="src-view">
            {f.format === 'markdown' && !showSource ? <Markdown text={f.text} /> : <Lines text={f.text} json={f.format === 'json'} hits={hits} />}
          </div>
          {unplaced.length > 0 && (
            <p className="meta">
              {hits.length > 0 ? 'Not tied to a specific line here: ' : 'No exact line to mark for: '}
              {unplaced.map((x) => x.title).join('; ')}.
            </p>
          )}
          <p className="meta">Read-only. Secret values are hidden.{f.truncated && ' Long file: showing the first part.'}</p>
        </>
      )}
    </Sheet>
  );
}
