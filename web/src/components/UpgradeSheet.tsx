import { useEffect, useState } from 'react';
import { post, type Asset, type Inventory } from '../lib';
import { ErrorNote } from './ui';
import { Sheet } from './Sheet';

interface Diff {
  candidate: { current: string; latest: string; package: string };
  toolsAdded: string[];
  toolsRemoved: string[];
  descriptionsChanged: string[];
  newHosts: string[];
  newMismatches: string[];
  installScripts: string[];
  newFindings: { severity: string; title: string }[];
  fixedFindings: { severity: string; title: string }[];
  verdict: 'safe' | 'review' | 'dangerous';
}

function Row({ label, items, tone }: { label: string; items: string[]; tone?: 'bad' | 'warn' | 'ok' }) {
  if (!items.length) return null;
  return (
    <div className={`diff-row ${tone ?? ''}`}>
      <strong>{label}</strong>
      <ul className="plain">{items.map((x) => <li key={x}>{x}</li>)}</ul>
    </div>
  );
}

/** What changes between the version you run and the latest, before you move. */
export function UpgradeSheet({ asset, onClose, onDone }: { asset: Asset; onClose: () => void; onDone: (r: { snapshot: { id: string; title: string }; inventory: Inventory }) => void }) {
  const [d, setD] = useState<Diff | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    post<Diff>('/api/upgrade/diff', { assetId: asset.id }).then(setD).catch((e) => setError((e as Error).message));
  }, [asset.id]);
  const quiet = d && !d.toolsAdded.length && !d.toolsRemoved.length && !d.descriptionsChanged.length && !d.newHosts.length && !d.newFindings.length && !d.installScripts.length;
  return (
    <Sheet
      title={d ? `${asset.name}: ${d.candidate.current} → ${d.candidate.latest}` : `Update ${asset.name}`}
      wide
      onClose={onClose}
      footer={
        <>
          <span className="spacer" />
          <button className="btn" onClick={onClose}>Not now</button>
          <button
            className="btn primary"
            disabled={!d || busy || d.verdict === 'dangerous'}
            onClick={async () => {
              setBusy(true);
              try {
                onDone(await post('/api/upgrade/apply', { assetId: asset.id, version: d!.candidate.latest }));
              } catch (e) {
                setError((e as Error).message);
                setBusy(false);
              }
            }}
          >
            {busy ? 'Updating…' : `Pin ${d?.candidate.latest ?? ''}`}
          </button>
        </>
      }
    >
      {error && <ErrorNote message={error} />}
      {!d && !error && <div className="meta"><span className="spinner" aria-hidden /> Downloading both versions to compare (nothing is installed or run)…</div>}
      {d && (
        <>
          <div className={`verdict ${d.verdict === 'dangerous' ? 'bad' : d.verdict === 'review' ? 'warn' : 'ok'}`}>
            <strong>{d.verdict === 'dangerous' ? 'Don’t upgrade' : d.verdict === 'review' ? 'Review first' : 'Looks safe'}</strong> — {d.candidate.package} {d.candidate.latest}
          </div>
          {quiet && <p>No changes to its tools, the hosts it contacts, or its findings.</p>}
          <Row label="New tools" items={d.toolsAdded} tone="warn" />
          <Row label="Removed tools" items={d.toolsRemoved} />
          <Row label="Changed tool descriptions" items={d.descriptionsChanged} tone="warn" />
          <Row label="New hosts it contacts" items={d.newHosts} tone="bad" />
          <Row label="Now does more than it says" items={d.newMismatches} tone="bad" />
          <Row label="Install scripts" items={d.installScripts} tone="warn" />
          <Row label="New findings" items={d.newFindings.map((f) => `${f.severity}: ${f.title}`)} tone="bad" />
          <Row label="Fixed" items={d.fixedFindings.map((f) => f.title)} tone="ok" />
        </>
      )}
    </Sheet>
  );
}
