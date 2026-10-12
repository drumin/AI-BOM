import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { TABS, TAB_LABEL, type Tab } from '../nav';

/**
 * The view tabs. Every tab shows while they fit. When the window is too narrow the ones that don't fit
 * move into a "More" menu (the open view always stays in the row).
 */
export function TabBar({ tab, onTab, counts, dot }: { tab: Tab; onTab: (t: Tab) => void; counts: Partial<Record<Tab, number>>; dot?: Tab }) {
  const bar = useRef<HTMLDivElement>(null);
  const measure = useRef<HTMLDivElement>(null);
  const menuRoot = useRef<HTMLDivElement>(null);
  const moreBtn = useRef<HTMLButtonElement>(null);
  const [fit, setFit] = useState(TABS.length);
  const [open, setOpen] = useState(false);

  // How many tabs fit? Measure every tab (and the More button) once in a hidden copy, then count.
  const key = TABS.map((t) => counts[t] ?? '').join(',');
  useLayoutEffect(() => {
    const compute = () => {
      const m = measure.current;
      const b = bar.current;
      if (!m || !b) return;
      const sizes = [...m.children].map((c) => (c as HTMLElement).offsetWidth);
      const moreW = sizes.pop() ?? 0;
      const gap = 4;
      const room = b.clientWidth - 18; // 8px padding each side + borders
      const all = sizes.reduce((a, w) => a + w, 0) + gap * (sizes.length - 1);
      if (all <= room) return setFit(TABS.length);
      let used = moreW + gap;
      let n = 0;
      for (const w of sizes) {
        if (used + w + gap > room) break;
        used += w + gap;
        n++;
      }
      setFit(Math.max(1, n));
    };
    compute();
    const ro = new ResizeObserver(compute);
    if (bar.current) ro.observe(bar.current);
    return () => ro.disconnect();
  }, [key]);

  const base = TABS.slice(0, fit);
  const visible: Tab[] = fit >= TABS.length || base.includes(tab) ? base : [...base.slice(0, -1), tab];
  const overflow = TABS.filter((t) => !visible.includes(t));

  useEffect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => menuRoot.current && !menuRoot.current.contains(e.target as Node) && setOpen(false);
    document.addEventListener('pointerdown', onDown);
    const raf = requestAnimationFrame(() => menuRoot.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus());
    return () => {
      document.removeEventListener('pointerdown', onDown);
      cancelAnimationFrame(raf);
    };
  }, [open]);
  useEffect(() => {
    if (!overflow.length) setOpen(false);
  }, [overflow.length]);

  const onTabKey = (e: React.KeyboardEvent, i: number) => {
    const last = visible.length - 1;
    const to = e.key === 'ArrowRight' ? (i + 1) % visible.length : e.key === 'ArrowLeft' ? (i - 1 + visible.length) % visible.length : e.key === 'Home' ? 0 : e.key === 'End' ? last : -1;
    if (to < 0) return;
    e.preventDefault();
    onTab(visible[to]);
    document.getElementById(`tab-${visible[to]}`)?.focus();
  };

  const onMenuKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      setOpen(false);
      moreBtn.current?.focus();
      return;
    }
    const items = [...e.currentTarget.querySelectorAll<HTMLElement>('[role="menuitem"]')];
    const at = items.indexOf(document.activeElement as HTMLElement);
    const to = e.key === 'ArrowDown' ? (at + 1) % items.length : e.key === 'ArrowUp' ? (at - 1 + items.length) % items.length : e.key === 'Home' ? 0 : e.key === 'End' ? items.length - 1 : -1;
    if (to < 0) return;
    e.preventDefault();
    items[to].focus();
  };

  const label = (t: Tab) => (
    <>
      {TAB_LABEL[t]}
      {counts[t] !== undefined && <span className="count">{counts[t]}</span>}
    </>
  );

  return (
    <div className="tabbar" ref={bar}>
      <nav className="tabs" role="tablist" aria-label="Views">
        {visible.map((id, i) => (
          <button
            key={id}
            id={`tab-${id}`}
            className="tab"
            role="tab"
            aria-selected={tab === id}
            aria-controls="view-panel"
            tabIndex={tab === id ? 0 : -1}
            onClick={() => onTab(id)}
            onKeyDown={(e) => onTabKey(e, i)}
          >
            {label(id)}
          </button>
        ))}
      </nav>
      {overflow.length > 0 && (
        <div className="menu tabs-more" ref={menuRoot} onBlur={(e) => open && !e.currentTarget.contains(e.relatedTarget as Node | null) && setOpen(false)}>
          <button
            ref={moreBtn}
            className="tab more-btn"
            aria-expanded={open}
            aria-haspopup="menu"
            onClick={() => setOpen((o) => !o)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setOpen(true);
              }
            }}
          >
            More
            {dot && overflow.includes(dot) && <span className="more-dot"><span className="sr-only">{TAB_LABEL[dot]} has changes</span></span>}
            <svg className="chev" width="12" height="12" viewBox="0 0 16 16" aria-hidden><path d="M4.5 6.5l3.5 3.5 3.5-3.5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>
          </button>
          {open && (
            <div className="menu-pop" role="menu" aria-label="More views" onKeyDown={onMenuKey}>
              {overflow.map((id) => (
                <button key={id} role="menuitem" tabIndex={-1} onClick={() => { setOpen(false); onTab(id); }}>
                  {TAB_LABEL[id]}
                  {counts[id] !== undefined && <small>{counts[id]}</small>}
                </button>
              ))}
            </div>
          )}
        </div>
      )}
      {/* Hidden copy used only to measure how wide each tab is. */}
      <div className="tabs-measure" ref={measure} aria-hidden inert>
        {TABS.map((id) => (
          <span key={id} className="tab">{label(id)}</span>
        ))}
        <span className="tab more-btn">More<svg width="12" height="12" viewBox="0 0 16 16" /></span>
      </div>
    </div>
  );
}
