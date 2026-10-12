import { useState } from 'react';
import { daysSince, relativeTime, type Asset, type Inventory } from '../lib';
import { Sev } from './Severity';

const PLATFORMS = ['claude.ai', 'ChatGPT', 'Gemini', 'Microsoft Copilot', 'Perplexity', 'Other'];
const COMMON = [
  'Gmail', 'Google Drive', 'Google Calendar', 'Outlook', 'OneDrive', 'SharePoint', 'Microsoft Teams', 'Slack', 'GitHub', 'GitLab',
  'Notion', 'Linear', 'Jira', 'Confluence', 'Asana', 'Figma', 'Canva', 'Dropbox', 'Box', 'HubSpot', 'Salesforce', 'Stripe', 'Zapier',
];

export interface ConnectorDraft {
  platform: string;
  name: string;
  access: 'read' | 'read-write' | 'unknown';
  notes?: string;
}

export function Connectors({
  inv,
  onAdd,
  onAction,
  onSelect,
}: {
  inv: Inventory;
  onAdd: (d: ConnectorDraft) => Promise<void>;
  onAction: (a: Asset, action: 'review' | 'remove') => void;
  onSelect: (id: string) => void;
}) {
  const [draft, setDraft] = useState<ConnectorDraft>({ platform: 'claude.ai', name: '', access: 'read-write' });
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const connectors = inv.assets.filter((a) => a.kind === 'connector');
  const byPlatform = new Map<string, Asset[]>();
  for (const c of connectors) {
    const p = c.connector!.platform;
    byPlatform.set(p, [...(byPlatform.get(p) ?? []), c]);
  }
  const detected = connectors.filter((c) => c.connector!.detectedIn);
  const remoteMcp = inv.assets.filter((a) => a.kind === 'mcp-server' && (a.mcp?.url || a.mcp?.remoteUrl));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!draft.name.trim()) return setError('Give the connector a name, e.g. Gmail.');
    setSaving(true);
    setError(null);
    try {
      await onAdd(draft);
      setDraft((d) => ({ ...d, name: '', notes: '' }));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="connectors">
      {detected.length > 0 && (
        <p className="notice" role="note">
          Found {detected.length} {detected.length === 1 ? 'connector' : 'connectors'} automatically, but this list is probably not complete. Claude Code only
          shows the connectors it uses or is waiting for you to sign in to, so your account may have more. Add the others below to keep track of them.
        </p>
      )}
      <section className="panel pad">
        <h3 className="section-title">Add a cloud connector</h3>
        <p className="meta">
          Connectors you enabled in claude.ai, ChatGPT and similar apps live in your online account, where AI-BOM can’t see them.
          List them here so they sit next to everything else and get a review reminder every 90 days. Stored only in <span className="mono">~/.ai-bom/connectors.json</span>.
        </p>
        <form className="form-row" onSubmit={submit}>
          <label>
            <span>Platform</span>
            <select className="input" value={draft.platform} onChange={(e) => setDraft({ ...draft, platform: e.target.value })}>
              {PLATFORMS.map((p) => <option key={p}>{p}</option>)}
            </select>
          </label>
          <label className="grow">
            <span>Service</span>
            <input className="input" list="common-connectors" placeholder="Gmail, GitHub, Notion…" value={draft.name} maxLength={80}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })} aria-invalid={!!error} aria-describedby={error ? 'conn-error' : undefined} />
            <datalist id="common-connectors">{COMMON.map((c) => <option key={c} value={c} />)}</datalist>
          </label>
          <fieldset className="segmented">
            <legend>Access</legend>
            {(['read', 'read-write', 'unknown'] as const).map((a) => (
              <label key={a} className={draft.access === a ? 'on' : ''}>
                <input type="radio" name="access" value={a} checked={draft.access === a} onChange={() => setDraft({ ...draft, access: a })} />
                {a === 'read' ? 'Read' : a === 'read-write' ? 'Read & write' : 'Not sure'}
              </label>
            ))}
          </fieldset>
          <button className="btn primary" type="submit" disabled={saving}>{saving ? 'Adding…' : 'Add'}</button>
        </form>
        {error && <p className="form-error" id="conn-error" role="alert">{error}</p>}
      </section>

      {connectors.length === 0 ? (
        <div className="panel empty">No cloud connectors registered yet.</div>
      ) : (
        [...byPlatform.entries()].map(([platform, list]) => (
          <section className="panel" key={platform}>
            <div className="toolbar"><strong>{platform}</strong><span className="count">{list.length}</span></div>
            <ul className="conn-list">
              {list.map((a) => {
                const c = a.connector!;
                const stale = !c.detectedIn && daysSince(c.reviewedAt ?? c.addedAt) >= 90;
                return (
                  <li key={a.id}>
                    <button className="linklike conn-name" onClick={() => onSelect(a.id)}>{a.name}</button>
                    <span className="tag">{c.access === 'read-write' ? 'Read & write' : c.access === 'read' ? 'Read only' : 'Access unknown'}</span>
                    {c.detectedIn ? (
                      <span className="meta">Found automatically in {c.detectedIn}</span>
                    ) : (
                      <span className="meta">reviewed {relativeTime(c.reviewedAt ?? c.addedAt)}</span>
                    )}
                    {stale && <Sev severity="low" />}
                    <span className="spacer" />
                    {!c.detectedIn && (
                      <>
                        <button className="btn small" onClick={() => onAction(a, 'review')}>Still in use</button>
                        <button className="btn small" onClick={() => onAction(a, 'remove')}>Remove</button>
                      </>
                    )}
                  </li>
                );
              })}
            </ul>
          </section>
        ))
      )}

      {remoteMcp.length > 0 && (
        <section className="panel pad">
          <h3 className="section-title">Remote MCP servers found on disk</h3>
          <p className="meta">These are connectors too: they send data to a third-party server. They were found automatically.</p>
          <div className="tags">
            {remoteMcp.map((a) => <button key={a.id} className="tag linklike" onClick={() => onSelect(a.id)}>{a.name}</button>)}
          </div>
        </section>
      )}
    </div>
  );
}
