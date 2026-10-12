import { useEffect, useRef } from 'react';

/**
 * Shown once, the first time the dashboard opens. Says what you are looking at, where the data stays, and
 * how to undo; then gets out of the way. Dismissing it is remembered with the other preferences.
 */
export function Welcome({ onStart, onDismiss, canStart }: { onStart: () => void; onDismiss: () => void; canStart: boolean }) {
  const box = useRef<HTMLElement>(null);
  useEffect(() => {
    box.current?.scrollIntoView?.({ block: 'nearest' });
  }, []);
  return (
    <section className="panel pad welcome" aria-labelledby="welcome-title" ref={box}>
      <h2 id="welcome-title">Welcome to AI-BOM</h2>
      <p className="meta">This is everything AI-related on your computer: the tools, the servers they talk to, and what they are allowed to do. Three things to know:</p>
      <ul className="welcome-points">
        <li><strong>The score</strong> sums up what was found. “Next best step” is the single change that improves it most.</li>
        <li><strong>It stays here.</strong> Scanning is local. Nothing leaves your computer unless you run the online check or ask for an AI review.</li>
        <li><strong>You can undo.</strong> Every change AI-BOM makes is saved and can be reversed from History.</li>
      </ul>
      <p className="meta">Tip: press <kbd>⌘K</kbd> or <kbd>Ctrl</kbd>+<kbd>K</kbd> to search everything and run any command.</p>
      <div className="actions">
        {canStart && <button className="btn primary" onClick={onStart}>Show me the biggest problem</button>}
        <button className="btn" onClick={onDismiss}>Got it</button>
      </div>
    </section>
  );
}
