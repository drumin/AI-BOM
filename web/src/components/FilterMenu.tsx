import { useEffect, useId, useRef, useState, type ReactNode } from 'react';

export interface FilterOption {
  value: string;
  label: string;
  count?: number;
  icon?: ReactNode;
}

/**
 * A filter or sort control: a button that shows what is chosen and opens a short list with counts.
 * Single choice (radio) or several (checkboxes). Arrow keys move, Escape closes and returns focus.
 */
export function FilterMenu({
  label,
  options,
  value,
  onChange,
  multiple = false,
  allLabel = 'All',
  prefix,
}: {
  label: string;
  options: FilterOption[];
  value: string[];
  onChange: (next: string[]) => void;
  multiple?: boolean;
  /** Shown when nothing is chosen (single choice: the "no filter" row). */
  allLabel?: string;
  /** Sorting reads better as "Sort: Risk" than "Sort  Risk". */
  prefix?: string;
}) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const id = useId();

  useEffect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => root.current && !root.current.contains(e.target as Node) && setOpen(false);
    document.addEventListener('pointerdown', onDown);
    const raf = requestAnimationFrame(() => (root.current?.querySelector<HTMLElement>('[aria-checked="true"]') ?? root.current?.querySelector<HTMLElement>('[role^="menuitem"]'))?.focus());
    return () => {
      document.removeEventListener('pointerdown', onDown);
      cancelAnimationFrame(raf);
    };
  }, [open]);

  const chosen = options.filter((o) => value.includes(o.value));
  const summary = chosen.length === 0 ? 'All' : chosen.length === 1 ? chosen[0].label : `${chosen.length} selected`;
  const active = chosen.length > 0 && !(!multiple && prefix);

  const toggle = (v: string) => {
    if (multiple) onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v]);
    else {
      onChange(v === '' ? [] : [v]);
      setOpen(false);
      button.current?.focus();
    }
  };

  const onKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      setOpen(false);
      button.current?.focus();
      return;
    }
    const items = [...e.currentTarget.querySelectorAll<HTMLElement>('[role^="menuitem"]')];
    const at = items.indexOf(document.activeElement as HTMLElement);
    const to = e.key === 'ArrowDown' ? (at + 1) % items.length : e.key === 'ArrowUp' ? (at - 1 + items.length) % items.length : e.key === 'Home' ? 0 : e.key === 'End' ? items.length - 1 : -1;
    if (to < 0) return;
    e.preventDefault();
    items[to].focus();
  };

  return (
    <div className="menu filter" ref={root} onBlur={(e) => open && !e.currentTarget.contains(e.relatedTarget as Node | null) && setOpen(false)}>
      <button
        ref={button}
        className={`btn filter-btn${active ? ' on' : ''}`}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? id : undefined}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') {
            e.preventDefault();
            setOpen(true);
          }
        }}
      >
        <span className="filter-label">{prefix ?? label}</span>
        <span className="filter-value">{summary}</span>
        <svg className="chev" width="12" height="12" viewBox="0 0 16 16" aria-hidden><path d="M4.5 6.5l3.5 3.5 3.5-3.5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>
      </button>
      {open && (
        <div className="menu-pop filter-pop" id={id} role="menu" aria-label={label} tabIndex={0} onKeyDown={onKey}>
          {!multiple && !prefix && (
            <button role="menuitemradio" aria-checked={chosen.length === 0} tabIndex={-1} onClick={() => toggle('')}>
              <span className="mark" aria-hidden>{chosen.length === 0 ? '✓' : ''}</span>
              <span className="grow">{allLabel}</span>
            </button>
          )}
          {options.map((o) => {
            const on = value.includes(o.value);
            return (
              <button key={o.value} role={multiple ? 'menuitemcheckbox' : 'menuitemradio'} aria-checked={on} tabIndex={-1} onClick={() => toggle(o.value)}>
                <span className={multiple ? 'box' : 'mark'} aria-hidden>{on ? '✓' : ''}</span>
                {o.icon}
                <span className="grow">{o.label}</span>
                {o.count !== undefined && <span className="meta">{o.count}</span>}
              </button>
            );
          })}
          {multiple && chosen.length > 0 && (
            <button className="filter-clear" role="menuitem" tabIndex={-1} onClick={() => onChange([])}>
              Clear {label.toLowerCase()}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
