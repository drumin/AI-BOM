import { useMemo, useState } from 'react';
import {
  CAPABILITY_LABEL,
  clientName,
  daysSince,
  isPendingApproval,
  isSynced,
  KIND_LABEL,
  KIND_ORDER,
  lastChanged,
  relativeTime,
  SCOPE_LABEL,
  SENSITIVE_CAPS,
  sevRank,
  subtitle,
  type AssetKind,
  type Inventory,
  onActivate,
} from '../lib';
import { FilterMenu } from './FilterMenu';
import { KindMark } from './KindMark';
import { Sev } from './Severity';

/** Six months without a change is our working definition of "forgotten". */
const STALE_DAYS = 180;

export function InventoryTable({
  inv,
  kinds,
  setKinds,
  onSelect,
  selectedId,
}: {
  inv: Inventory;
  kinds: AssetKind[];
  setKinds: (k: AssetKind[]) => void;
  /** `ids` is the list as shown, so the open asset's panel can step through it. */
  onSelect: (id: string, ids?: string[]) => void;
  selectedId?: string | null;
}) {
  const [q, setQ] = useState('');
  const [clients, setClients] = useState<string[]>([]);
  const [onlyNew, setOnlyNew] = useState(false);
  const [onlyStale, setOnlyStale] = useState(false);
  const [sort, setSort] = useState<'risk' | 'name' | 'kind' | 'changed'>('risk');

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return inv.assets
      .filter((a) => !kinds.length || kinds.includes(a.kind))
      .filter((a) => !clients.length || a.occurrences.some((o) => clients.includes(o.client)))
      .filter((a) => !onlyNew || a.isNew)
      .filter((a) => !onlyStale || (a.origin === 'local' && daysSince(lastChanged(a)) >= STALE_DAYS))
      .filter((a) => !needle || `${a.name} ${subtitle(a)} ${a.path ?? ''}`.toLowerCase().includes(needle))
      .sort((x, y) =>
        sort === 'risk'
          ? sevRank(x.risk) - sevRank(y.risk) || x.name.localeCompare(y.name)
          : sort === 'kind'
            ? KIND_ORDER.indexOf(x.kind) - KIND_ORDER.indexOf(y.kind) || x.name.localeCompare(y.name)
            : sort === 'changed'
              ? (lastChanged(x) ?? '').localeCompare(lastChanged(y) ?? '')
              : x.name.localeCompare(y.name),
      );
  }, [inv, kinds, clients, onlyNew, onlyStale, q, sort]);
  const staleCount = useMemo(() => inv.assets.filter((a) => a.origin === 'local' && daysSince(lastChanged(a)) >= STALE_DAYS).length, [inv]);

  const presentKinds = KIND_ORDER.filter((k) => inv.assets.some((a) => a.kind === k));

  return (
    <div className="panel">
      <div className="toolbar">
        <input className="input search" placeholder="Search name, package, path…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search" />
        <FilterMenu
          label="Type"
          multiple
          allLabel="All types"
          options={presentKinds.map((k) => ({ value: k, label: KIND_LABEL[k].many, count: inv.assets.filter((a) => a.kind === k).length, icon: <KindMark kind={k} /> }))}
          value={kinds}
          onChange={(v) => setKinds(v as AssetKind[])}
        />
        <FilterMenu
          label="AI tool"
          multiple
          allLabel="All AI tools"
          options={inv.clients.map((c) => ({ value: c.id, label: c.name, count: inv.assets.filter((a) => a.occurrences.some((o) => o.client === c.id)).length })).filter((o) => o.count > 0)}
          value={clients}
          onChange={setClients}
        />
        <FilterMenu
          label="Sort by"
          prefix="Sort"
          options={[
            { value: 'risk', label: 'Risk' },
            { value: 'name', label: 'Name' },
            { value: 'kind', label: 'Type' },
            { value: 'changed', label: 'Oldest change' },
          ]}
          value={[sort]}
          onChange={(v) => v[0] && setSort(v[0] as typeof sort)}
        />
        <button className="chip" aria-pressed={onlyNew} onClick={() => setOnlyNew((v) => !v)}>
          New since last scan
        </button>
        {staleCount > 0 && (
          <button className="chip" aria-pressed={onlyStale} onClick={() => setOnlyStale((v) => !v)} title="Config not changed in 6+ months">
            Untouched 6+ months <span className="count">{staleCount}</span>
          </button>
        )}
        {(kinds.length > 0 || clients.length > 0 || onlyNew || onlyStale || q) && (
          <button className="linklike" onClick={() => { setKinds([]); setClients([]); setOnlyNew(false); setOnlyStale(false); setQ(''); }}>Clear filters</button>
        )}
        <span className="spacer" />
        <span className="meta" aria-live="polite">{rows.length} of {inv.assets.length}</span>
      </div>
      <div className="table-wrap">
        <table className="inv-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Used by</th>
              <th className="col-scope">Scope</th>
              <th className="col-changed">Changed</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => {
              const clients = [...new Set(a.occurrences.map((o) => o.client))];
              const scopes = [...new Set(a.occurrences.map((o) => (o.project ? `${SCOPE_LABEL[o.scope]} · ${o.project.split('/').pop()}` : SCOPE_LABEL[o.scope])))];
              const disabled = a.occurrences.every((o) => o.enabled === false);
              const pending = !disabled && isPendingApproval(a);
              const changed = lastChanged(a);
              const caps = (a.skill?.capabilities ?? []).filter((c) => SENSITIVE_CAPS.has(c));
              return (
                <tr key={a.id} tabIndex={0} className={selectedId === a.id ? 'selected' : undefined} aria-current={selectedId === a.id ? 'true' : undefined} onClick={() => onSelect(a.id, rows.map((r) => r.id))} onKeyDown={onActivate(() => onSelect(a.id, rows.map((r) => r.id)))}>
                  <td>
                    <div>
                      <strong>{a.name}</strong>
                      {a.isNew && <span className="badge-new">NEW</span>}
                      {disabled && <span className="tag inline">off</span>}
                      {pending && <span className="tag inline" title={a.occurrences.find((o) => o.note)?.note}>not approved</span>}
                      {isSynced(a) && <span className="tag inline" title="Synced from your Claude account">synced</span>}
                      {caps.map((c) => <span key={c} className="tag inline cap strong">{CAPABILITY_LABEL[c]}</span>)}
                    </div>
                    <div className="sub mono" title={subtitle(a)}>{subtitle(a)}</div>
                  </td>
                  <td>
                    <span className="kind">
                      <KindMark kind={a.kind} />
                      {KIND_LABEL[a.kind].one}
                    </span>
                  </td>
                  <td>
                    <div className="tags">
                      {clients.map((c) => (
                        <span className="tag" key={c}>{clientName(inv, c)}</span>
                      ))}
                    </div>
                  </td>
                  <td className="col-scope">
                    <div className="tags">
                      {scopes.map((s) => (
                        <span className="tag" key={s}>{s}</span>
                      ))}
                    </div>
                  </td>
                  <td className="nowrap meta col-changed" title={changed ? new Date(changed).toLocaleString() : undefined}>{relativeTime(changed)}</td>
                  <td>
                    <Sev severity={a.risk} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {rows.length === 0 && <div className="empty">No assets match these filters.</div>}
      </div>
    </div>
  );
}
