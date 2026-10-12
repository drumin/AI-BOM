import { Fragment, type ReactNode } from 'react';

/** Wrap each occurrence of the given terms in <mark>, case-insensitively, earliest (then longest) first. */
export function highlight(text: string, terms: { term?: string; cls: string }[]): ReactNode {
  const live = terms.filter((t): t is { term: string; cls: string } => !!t.term && t.term.length > 1);
  if (!live.length) return text;
  const lower = text.toLowerCase();
  const out: ReactNode[] = [];
  let at = 0;
  while (at < text.length) {
    let best: { i: number; len: number; cls: string } | undefined;
    for (const t of live) {
      const i = lower.indexOf(t.term.toLowerCase(), at);
      if (i >= 0 && (!best || i < best.i || (i === best.i && t.term.length > best.len))) best = { i, len: t.term.length, cls: t.cls };
    }
    if (!best) break;
    if (best.i > at) out.push(text.slice(at, best.i));
    out.push(<mark key={best.i} className={best.cls}>{text.slice(best.i, best.i + best.len)}</mark>);
    at = best.i + best.len;
  }
  if (at < text.length) out.push(text.slice(at));
  return out;
}

/** Inline markdown: `code`, **bold**, *italic*, ~~strike~~, [links](https://…). Built as React nodes, never raw HTML. */
function inline(text: string, mark?: string): ReactNode[] {
  const out: ReactNode[] = [];
  const hl = (t: string) => highlight(t, [{ term: mark, cls: 'q-mark' }]);
  const re = /`([^`]+)`|\*\*([^*]+)\*\*|~~([^~]+)~~|(?<![\w*])\*([^*\s][^*]*)\*(?!\w)|\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(hl(text.slice(last, m.index)));
    const k = m.index;
    if (m[1] !== undefined) out.push(<code key={k}>{hl(m[1])}</code>);
    else if (m[2] !== undefined) out.push(<strong key={k}>{hl(m[2])}</strong>);
    else if (m[3] !== undefined) out.push(<del key={k}>{hl(m[3])}</del>);
    else if (m[4] !== undefined) out.push(<em key={k}>{hl(m[4])}</em>);
    else out.push(<a key={k} href={m[6]} target="_blank" rel="noopener noreferrer">{hl(m[5])}</a>);
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(hl(text.slice(last)));
  return out;
}

const LIST_ITEM = /^(\s*)([-*+]|\d+\.)\s+(.*)$/;
const TABLE_SEP = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;
const cells = (row: string) => row.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());

/**
 * A small, safe Markdown renderer for file contents and agent replies: headings, paragraphs, lists
 * (with nesting by indent and task boxes), tables, code blocks, quotes, rules, and front-matter.
 */
/** `plainHeadings` renders headings as styled text, for content embedded under a page's own headings (agent replies). */
export function Markdown({ text, className = '', mark, plainHeadings }: { text: string; className?: string; mark?: string; plainHeadings?: boolean }) {
  let lines = text.replace(/\r\n?/g, '\n').split('\n');
  const blocks: ReactNode[] = [];
  if (lines[0] === '---') {
    const end = lines.indexOf('---', 1);
    if (end > 0) {
      blocks.push(<pre key="fm" className="src-code frontmatter">{lines.slice(1, end).join('\n')}</pre>);
      lines = lines.slice(end + 1);
    }
  }
  let i = 0;
  const startsBlock = (l: string, next?: string) =>
    /^(#{1,6}\s|```|>\s?|\s*(---+|\*\*\*+)\s*$)/.test(l) || LIST_ITEM.test(l) || (l.includes('|') && next !== undefined && TABLE_SEP.test(next));
  while (i < lines.length) {
    const l = lines[i];
    const key = blocks.length;
    if (!l.trim()) { i++; continue; }
    const fence = l.match(/^```\s*([\w+-]*)/);
    if (fence) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) body.push(lines[i++]);
      i++;
      blocks.push(
        <pre key={key} className="src-code" data-lang={fence[1] || undefined}>{highlight(body.join('\n'), [{ term: mark, cls: 'q-mark' }])}</pre>,
      );
      continue;
    }
    const h = l.match(/^(#{1,6})\s+(.*)$/);
    if (h) {
      const Tag = (plainHeadings ? 'p' : `h${Math.min(h[1].length + 2, 6)}`) as 'h3';
      blocks.push(<Tag key={key} className={plainHeadings ? `md-h md-h${h[1].length}` : undefined}>{inline(h[2], mark)}</Tag>);
      i++;
      continue;
    }
    if (/^\s*(---+|\*\*\*+)\s*$/.test(l)) { blocks.push(<hr key={key} />); i++; continue; }
    if (l.includes('|') && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1])) {
      const head = cells(l);
      i += 2;
      const body: string[][] = [];
      while (i < lines.length && lines[i].includes('|') && lines[i].trim()) body.push(cells(lines[i++]));
      blocks.push(
        <div key={key} className="md-table">
          <table>
            <thead><tr>{head.map((c, n) => <th key={n}>{inline(c, mark)}</th>)}</tr></thead>
            <tbody>{body.map((r, n) => <tr key={n}>{r.map((c, m) => <td key={m}>{inline(c, mark)}</td>)}</tr>)}</tbody>
          </table>
        </div>,
      );
      continue;
    }
    if (/^>\s?/.test(l)) {
      const q: string[] = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) q.push(lines[i++].replace(/^>\s?/, ''));
      blocks.push(<blockquote key={key}>{inline(q.join(' '), mark)}</blockquote>);
      continue;
    }
    if (LIST_ITEM.test(l)) {
      const items: { level: number; marker?: string; text: string }[] = [];
      while (i < lines.length && LIST_ITEM.test(lines[i])) {
        const m = lines[i++].match(LIST_ITEM)!;
        items.push({ level: Math.min(3, Math.floor(m[1].replace(/\t/g, '  ').length / 2)), marker: /\d/.test(m[2]) ? m[2] : undefined, text: m[3] });
      }
      blocks.push(
        <ul key={key} className="md-list">
          {items.map((it, n) => {
            const task = it.text.match(/^\[([ xX])\]\s+(.*)$/);
            return (
              <li key={n} className={task ? 'task' : undefined} style={it.level ? { marginLeft: it.level * 18 } : undefined}>
                {it.marker ? <span className="num">{it.marker}</span> : !task && <span className="bullet" aria-hidden />}
                {task && <span className="box" role="img" aria-label={task[1] === ' ' ? 'not done' : 'done'}>{task[1] === ' ' ? '' : '✓'}</span>}
                {inline(task ? task[2] : it.text, mark)}
              </li>
            );
          })}
        </ul>,
      );
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() && !(para.length && startsBlock(lines[i], lines[i + 1]))) para.push(lines[i++]);
    blocks.push(<p key={key}>{para.map((x, n) => <Fragment key={n}>{n > 0 && ' '}{inline(x, mark)}</Fragment>)}</p>);
  }
  return <div className={`src-md ${className}`.trim()}>{blocks}</div>;
}
