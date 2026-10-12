import { useEffect, useMemo, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import { trapTab, useModalInert } from '../a11y';

export interface Command {
  id: string;
  label: string;
  /** Section it belongs to, shown beside the label. */
  group: string;
  /** Extra words people might type. */
  keywords?: string;
  /** Only offered once something is typed (assets and findings; they would swamp the empty list). */
  searchOnly?: boolean;
  run: () => void;
}

const MAX = 12;

/** Every word typed must be found; earlier and word-start matches rank higher. */
function score(c: Command, words: string[]): number {
  const label = c.label.toLowerCase();
  const all = `${label} ${c.group.toLowerCase()} ${(c.keywords ?? '').toLowerCase()}`;
  let total = 0;
  for (const w of words) {
    if (!all.includes(w)) return -1;
    const at = label.indexOf(w);
    total += at === 0 ? 3 : at > 0 && /[\s\-_/.@:]/.test(label[at - 1]) ? 2 : at > 0 ? 1 : 0;
  }
  return total;
}

/**
 * Search everything and run anything from the keyboard. It is opened and closed by keystroke many times a day,
 * so it appears and disappears instantly, with no animation.
 */
export function CommandPalette({ commands, onClose }: { commands: Command[]; onClose: () => void }) {
  const [query, setQuery] = useState('');
  const [at, setAt] = useState(0);
  const panel = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const back = useRef<Element | null>(null);
  useModalInert(() => [panel.current?.parentElement ?? null]);

  const results = useMemo(() => {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean);
    const pool = words.length ? commands : commands.filter((c) => !c.searchOnly);
    if (!words.length) return pool.slice(0, MAX);
    return pool
      .map((c, i) => ({ c, s: score(c, words), i }))
      .filter((x) => x.s >= 0)
      .sort((a, b) => b.s - a.s || a.i - b.i)
      .slice(0, MAX)
      .map((x) => x.c);
  }, [commands, query]);

  useEffect(() => setAt(0), [query]);
  useEffect(() => {
    back.current = document.activeElement;
    input.current?.focus();
  }, []);
  useEffect(() => {
    document.getElementById(`cmd-${at}`)?.scrollIntoView({ block: 'nearest' });
  }, [at]);

  const close = () => {
    flushSync(onClose);
    (back.current as HTMLElement | null)?.focus?.();
  };
  const run = (c: Command) => {
    flushSync(onClose);
    c.run();
  };
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      close();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (results.length) setAt((at + 1) % results.length);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (results.length) setAt((at - 1 + results.length) % results.length);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (results[at]) run(results[at]);
    } else if (e.key === 'Tab') {
      trapTab(e.nativeEvent, panel.current);
    }
  };

  return (
    <div className="palette-layer" onKeyDown={onKey}>
      <div className="palette-scrim" onClick={close} />
      <div className="palette" role="dialog" aria-modal="true" aria-label="Search and commands" ref={panel}>
        <input
          ref={input}
          className="palette-input"
          role="combobox"
          aria-expanded="true"
          aria-controls="cmd-list"
          aria-autocomplete="list"
          aria-activedescendant={results.length ? `cmd-${at}` : undefined}
          aria-label="Search assets, findings and commands"
          placeholder="Search assets, findings and commands…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
        <ul id="cmd-list" role="listbox" aria-label="Results" className="palette-list">
          {results.map((c, i) => (
            <li key={c.id} id={`cmd-${i}`} role="option" aria-selected={i === at} className={i === at ? 'on' : ''} onPointerMove={() => setAt(i)} onClick={() => run(c)}>
              <span className="palette-label">{c.label}</span>
              <span className="meta">{c.group}</span>
            </li>
          ))}
        </ul>
        {!results.length && <div className="palette-empty">No match for “{query}”.</div>}
        <div className="palette-foot meta" role="status">
          <span>{results.length ? `${results.length} result${results.length === 1 ? '' : 's'}` : 'No results'}</span>
          <span aria-hidden>↑↓ to move · Enter to open · Esc to close</span>
        </div>
      </div>
    </div>
  );
}
