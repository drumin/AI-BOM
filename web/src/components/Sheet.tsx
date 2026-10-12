import { flushSync } from 'react-dom';
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { trapTab, useModalInert } from '../a11y';

/**
 * A centered modal sheet: rises from below, dims what's behind it, traps
 * focus, closes on Escape or a click outside, and returns focus on close.
 */
export function Sheet({ title, onClose, children, footer, wide }: { title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  const [state, setState] = useState<'entering' | 'open' | 'closing'>('entering');
  const panel = useRef<HTMLDivElement>(null);
  const layer = useRef<HTMLDivElement>(null);
  useModalInert(() => [layer.current]);
  const back = useRef<Element | null>(null);
  const close = () => {
    setState('closing');
    window.setTimeout(() => {
      // Unmount synchronously so `inert` is lifted from what was behind before focus goes back to it.
      flushSync(onClose);
      (back.current as HTMLElement | null)?.focus?.();
    }, 200);
  };
  useLayoutEffect(() => {
    back.current = document.activeElement;
    const raf = requestAnimationFrame(() => setState('open'));
    panel.current?.querySelector<HTMLElement>('[data-autofocus], button')?.focus({ preventScroll: true });
    return () => cancelAnimationFrame(raf);
  }, []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        close();
      }
      trapTab(e, panel.current);
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  });
  return (
    <div className="sheet-layer" data-state={state} ref={layer}>
      <div className="sheet-scrim" onClick={close} />
      <div className={`sheet${wide ? ' wide' : ''}`} role="dialog" aria-modal="true" aria-label={title} ref={panel}>
        <header className="sheet-head">
          <h2>{title}</h2>
          <button className="btn icon" onClick={close} aria-label="Close">
            <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden><path d="M3 3l8 8M11 3l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></svg>
          </button>
        </header>
        <div className="sheet-body">{children}</div>
        {footer && <footer className="sheet-foot">{footer}</footer>}
      </div>
    </div>
  );
}
