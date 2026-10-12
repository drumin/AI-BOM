import { clientName, KIND_LABEL, type Inventory } from '../lib';
import { KindMark } from './KindMark';

/** Tokens each agent loads before you type anything: one bar per agent (single hue), values labelled. */
export function ContextView({ inv, onSelect }: { inv: Inventory; onSelect: (id: string) => void }) {
  const list = inv.context ?? [];
  if (!list.length) return <div className="panel empty">No agent configuration found.</div>;
  const max = Math.max(...list.map((c) => c.total), 1);
  return (
    <div className="panel pad context-view">
      <h3 className="section-title">What every conversation starts with</h3>
      <p className="meta">
        Estimated tokens each agent loads before you type anything: tool descriptions of enabled MCP servers, the names and descriptions of skills,
        subagents and commands, and instruction files in full. Less context means cheaper, faster and more focused answers.
      </p>
      <div className="ctx-rows">
        {list.slice(0, 16).map((c) => (
          <details key={`${c.client}|${c.project ?? ''}`} className="ctx-row">
            <summary>
              <span className="ctx-name">
                {clientName(inv, c.client)}
                <span className="meta"> · {c.project ? c.project.split('/').pop() : 'everywhere'}</span>
              </span>
              <span className="ctx-bar" title={`${c.total.toLocaleString()} tokens`}>
                <span style={{ width: `${(c.total / max) * 100}%` }} />
              </span>
              <span className="ctx-val">{c.total.toLocaleString()}</span>
            </summary>
            <ul className="ctx-items">
              {c.items.slice(0, 20).map((i) => (
                <li key={i.assetId}>
                  <KindMark kind={i.kind} />
                  <button className="linklike" onClick={() => onSelect(i.assetId)}>{i.name}</button>
                  <span className="meta">{KIND_LABEL[i.kind].one}</span>
                  {i.unused && <span className="pill warn">never used</span>}
                  <span className="spacer" />
                  <span className="mono">{i.tokens.toLocaleString()}{i.estimated ? ' ≈' : ''}</span>
                </li>
              ))}
            </ul>
            {c.suggestions.map((s) => <p key={s} className="callout">{s}</p>)}
          </details>
        ))}
      </div>
      <p className="meta">≈ = tools not visible (remote or not on disk); a typical server size is assumed. Estimates use ~4 characters per token.</p>
    </div>
  );
}
