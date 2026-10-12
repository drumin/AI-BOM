import { useEffect, useState } from 'react';
import { post, type Asset } from '../lib';
import { ErrorNote } from './ui';
import { Sheet } from './Sheet';

interface Preview {
  files: string[];
  chars: number;
  truncated: boolean;
  model: string;
  cached?: Review;
}

interface Review {
  summary: string;
  whatItDoes: string[];
  dataItTouches: string[];
  whereDataGoes: string[];
  mismatches: string[];
  verdict: 'looks-fine' | 'review' | 'avoid';
  reason: string;
  backend: string;
  model: string;
  truncated: boolean;
}

const VERDICT = { 'looks-fine': ['Looks fine', 'ok'], review: ['Worth a closer look', 'warn'], avoid: ['Avoid', 'bad'] } as const;

function List({ title, items }: { title: string; items: string[] }) {
  if (!items.length) return null;
  return (
    <>
      <h4>{title}</h4>
      <ul className="plain">{items.map((x, i) => <li key={i}>{x}</li>)}</ul>
    </>
  );
}

/** Opt-in AI review: shows exactly what would be sent and where, and only sends on "Review". */
export function ExplainSheet({ asset, onClose }: { asset: Asset; onClose: () => void }) {
  const [preview, setPreview] = useState<Preview | null>(null);
  const [backend, setBackend] = useState<'claude' | 'ollama'>('claude');
  const [review, setReview] = useState<Review | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    post<Preview>('/api/explain/preview', { assetId: asset.id })
      .then((p) => {
        setPreview(p);
        if (p.cached) setReview(p.cached);
      })
      .catch((e) => setError((e as Error).message));
  }, [asset.id]);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setReview(await post<Review>('/api/explain', { assetId: asset.id, backend }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet
      title={`Explain “${asset.name}”`}
      onClose={onClose}
      footer={
        !review ? (
          <>
            <span className="spacer" />
            <button className="btn" onClick={onClose}>Cancel</button>
            <button className="btn primary" onClick={run} disabled={!preview || busy || !preview.files.length} data-autofocus>
              {busy ? <><span className="spinner light" aria-hidden /> Reviewing</> : 'Review'}
            </button>
          </>
        ) : (
          <>
            <span className="meta">Reviewed by {review.backend === 'claude' ? 'Claude' : 'a local model'} ({review.model}). AI reviews can be wrong.</span>
            <span className="spacer" />
            <button className="btn" onClick={onClose}>Done</button>
          </>
        )
      }
    >
      {error && <ErrorNote message={error} />}
      {!review && preview && (
        <>
          <p>
            A model reads this {asset.kind === 'mcp-server' ? 'server’s tool list and code' : 'item’s files'} and explains what it really does, in plain words.
          </p>
          <div className="consent">
            <div><strong>What is sent:</strong> {preview.files.join(', ') || 'nothing readable'} ({preview.chars.toLocaleString()} characters{preview.truncated ? ', cut at 60,000' : ''}). Secret values are masked first.</div>
            <div className="segmented" role="radiogroup" aria-label="Where to send it">
              <label className={backend === 'claude' ? 'on' : ''}><input type="radio" name="backend" checked={backend === 'claude'} onChange={() => setBackend('claude')} />Claude API</label>
              <label className={backend === 'ollama' ? 'on' : ''}><input type="radio" name="backend" checked={backend === 'ollama'} onChange={() => setBackend('ollama')} />Local (Ollama)</label>
            </div>
            <div className="meta">
              {backend === 'claude'
                ? 'Sent to Anthropic’s API using your ANTHROPIC_API_KEY (or `ant auth login` profile). Results are cached on this machine.'
                : 'Sent to Ollama on this machine (127.0.0.1:11434). Nothing leaves your computer.'}
            </div>
          </div>
        </>
      )}
      {!review && !preview && !error && <div className="meta"><span className="spinner" aria-hidden /> Collecting files…</div>}
      {review && (
        <div className="review">
          <div className={`verdict ${VERDICT[review.verdict][1]}`}><strong>{VERDICT[review.verdict][0]}</strong> — {review.reason}</div>
          <p>{review.summary}</p>
          <List title="What it does" items={review.whatItDoes} />
          <List title="Data it touches" items={review.dataItTouches} />
          <List title="Where data goes" items={review.whereDataGoes} />
          <List title="Not mentioned in its description" items={review.mismatches} />
        </div>
      )}
    </Sheet>
  );
}
