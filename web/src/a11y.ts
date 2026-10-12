import { useLayoutEffect } from 'react';

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])';

/** Everything inside `root` that Tab can reach, in order (skips inert and hidden subtrees). */
export function focusables(root: Element): HTMLElement[] {
  return [...root.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => !el.closest('[inert]') && el.getClientRects().length > 0);
}

/** Wrap Tab / Shift+Tab inside `root`. Returns true when it handled the key. */
export function trapTab(e: KeyboardEvent, root: Element | null): boolean {
  if (e.key !== 'Tab' || !root) return false;
  const items = focusables(root);
  if (!items.length) return false;
  const first = items[0];
  const last = items[items.length - 1];
  const at = document.activeElement;
  if (e.shiftKey && (at === first || !root.contains(at))) {
    e.preventDefault();
    last.focus();
    return true;
  }
  if (!e.shiftKey && (at === last || !root.contains(at))) {
    e.preventDefault();
    first.focus();
    return true;
  }
  return false;
}

/**
 * While a dialog is open, everything else in the app is inert: not focusable, not clickable and hidden
 * from screen readers. `own` returns the elements that make up the dialog (and so stay live). Layered
 * dialogs work because each one restores only what it changed itself.
 */
export function useModalInert(own: () => (Element | null)[]) {
  useLayoutEffect(() => {
    const app = document.querySelector('.app');
    if (!app) return;
    const mine = new Set(own().filter(Boolean));
    const changed: HTMLElement[] = [];
    for (const child of app.children) {
      if (mine.has(child) || child.classList.contains('toast-region') || (child as HTMLElement).inert) continue;
      (child as HTMLElement).inert = true;
      changed.push(child as HTMLElement);
    }
    return () => changed.forEach((el) => (el.inert = false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
}
