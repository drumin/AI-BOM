import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import {
  clientName,
  isSynced,
  KIND_LABEL,
  KIND_ORDER,
  relativeTime,
  sevRank,
  subtitle,
  TOOL_GROUP_ORDER,
  toolGroup,
  type Asset,
  type AssetKind,
  type ClientId,
  type Inventory,
  type Severity,
} from '../lib';
import { KindMark } from './KindMark';
import { CountPill, IconTile, RiskPill, SevPill, ToolTile } from './ui';

/**
 * "All connections": a three-column flow that answers, for every asset,
 *   which AI tool  →  configured where  →  uses what.
 * Real HTML rows (not a canvas), smooth links drawn underneath, and focus by
 * dimming: hover anything to light up its whole chain, click a tool or a
 * source to pin that focus, click an asset to open its details.
 */

interface Source {
  id: string;
  tool: ClientId;
  label: string;
  detail?: string;
  assets: Set<string>;
}

type Focus = { kind: 'tool' | 'source' | 'asset'; id: string } | null;

function sourceOf(a: Asset, o: Asset['occurrences'][number], byId: Map<string, Asset>, home: string) {
  if (o.via) {
    const parent = byId.get(o.via);
    return { key: `via:${o.via}`, label: `${parent ? KIND_LABEL[parent.kind].one : 'Plugin'} · ${parent?.name ?? '?'}`, detail: 'Installed with it' };
  }
  if (o.client.startsWith('cloud:')) return { key: 'account', label: `${o.client.slice(6)} account`, detail: 'Online, not on this machine' };
  if (o.scope === 'managed') return { key: 'managed', label: 'Managed by an admin', detail: o.source };
  if (o.project) {
    const isHome = o.project === home || o.project === '~';
    return { key: `project:${o.project}`, label: isHome ? 'Home folder' : `Project · ${o.project.split('/').pop()}`, detail: o.project };
  }
  if (a.occurrences.length && o.note?.startsWith('Synced')) return { key: 'synced', label: 'Synced from your account', detail: 'Claude account' };
  return { key: 'user', label: 'User settings', detail: o.source };
}

export function FlowMap({ inv, onSelect, selectedId }: { inv: Inventory; onSelect: (id: string) => void; selectedId?: string | null }) {
  const body = useRef<HTMLDivElement>(null);
  const anchors = useRef(new Map<string, HTMLElement>());
  const [hidden, setHidden] = useState<Set<AssetKind>>(new Set());
  const [riskyOnly, setRiskyOnly] = useState(false);
  const [query, setQuery] = useState('');
  const [hover, setHover] = useState<Focus>(null);
  const [pinned, setPinned] = useState<Focus>(null);
  const [paths, setPaths] = useState<{ key: string; d: string; from: string; to: string; risk?: Severity }[]>([]);
  const presentKinds = useMemo(() => KIND_ORDER.filter((k) => inv.assets.some((a) => a.kind === k)), [inv]);

  const model = useMemo(() => {
    const byId = new Map(inv.assets.map((a) => [a.id, a]));
    const q = query.trim().toLowerCase();
    const visible = inv.assets.filter(
      (a) =>
        !hidden.has(a.kind) &&
        (!riskyOnly || (a.risk && a.risk !== 'info')) &&
        (!q || `${a.name} ${subtitle(a)}`.toLowerCase().includes(q)),
    );
    const sources = new Map<string, Source>();
    const assetSources = new Map<string, Set<string>>();
    for (const a of visible) {
      for (const o of a.occurrences) {
        const s = sourceOf(a, o, byId, '~');
        const id = `${o.client}|${s.key}`;
        if (!sources.has(id)) sources.set(id, { id, tool: o.client, label: s.label, detail: s.detail, assets: new Set() });
        sources.get(id)!.assets.add(a.id);
        if (!assetSources.has(a.id)) assetSources.set(a.id, new Set());
        assetSources.get(a.id)!.add(id);
      }
    }
    const toolIds = [...new Set([...sources.values()].map((s) => s.tool))];
    const tools = inv.clients
      .filter((c) => toolIds.includes(c.id))
      .sort((a, b) => TOOL_GROUP_ORDER.indexOf(toolGroup(a.id)) - TOOL_GROUP_ORDER.indexOf(toolGroup(b.id)) || a.name.localeCompare(b.name));
    const toolIndex = new Map(tools.map((t, i) => [t.id, i]));
    const rank = (s: Source) => (s.label === 'User settings' ? 0 : s.label.startsWith('Synced') ? 1 : s.label.startsWith('Home') ? 2 : s.label.startsWith('Project') ? 3 : 4);
    const sourceList = [...sources.values()].sort((a, b) => toolIndex.get(a.tool)! - toolIndex.get(b.tool)! || rank(a) - rank(b) || a.label.localeCompare(b.label));
    const sourceIndex = new Map(sourceList.map((s, i) => [s.id, i]));
    // Place each asset near the sources that use it (fewer crossing links).
    const pos = (a: Asset) => Math.min(...[...(assetSources.get(a.id) ?? [])].map((s) => sourceIndex.get(s) ?? 0));
    const groups = KIND_ORDER.map((k) => ({
      kind: k,
      assets: visible.filter((a) => a.kind === k).sort((x, y) => pos(x) - pos(y) || sevRank(x.risk) - sevRank(y.risk) || x.name.localeCompare(y.name)),
    })).filter((g) => g.assets.length);
    return { tools, sources: sourceList, groups, assetSources };
  }, [inv, hidden, riskyOnly, query]);

  // What is lit: the focused item and everything connected to it.
  const focus = pinned ?? hover;
  const lit = useMemo(() => {
    if (!focus) return null;
    const ids = new Set<string>();
    const add = (s: Source) => {
      ids.add(`s:${s.id}`);
      ids.add(`t:${s.tool}`);
    };
    for (const s of model.sources) {
      if (focus.kind === 'tool' && s.tool === focus.id) {
        add(s);
        s.assets.forEach((a) => ids.add(`a:${a}`));
      } else if (focus.kind === 'source' && s.id === focus.id) {
        add(s);
        s.assets.forEach((a) => ids.add(`a:${a}`));
      } else if (focus.kind === 'asset' && s.assets.has(focus.id)) {
        add(s);
        ids.add(`a:${focus.id}`);
      }
    }
    return ids;
  }, [focus, model]);
  const on = (id: string) => !lit || lit.has(id);

  const anchor = useCallback(
    (key: string) => (el: HTMLElement | null) => {
      if (el) anchors.current.set(key, el);
      else anchors.current.delete(key);
    },
    [],
  );

  useLayoutEffect(() => {
    const root = body.current;
    if (!root) return;
    let raf = 0;
    const draw = () => {
      raf = 0;
      if (getComputedStyle(root).getPropertyValue('--links').trim() === 'off') return setPaths([]);
      const box = root.getBoundingClientRect();
      const byIdRisk = new Map(inv.assets.map((x) => [x.id, x.risk === 'critical' || x.risk === 'high' ? x.risk : undefined] as const));
      const link = (from: string, to: string, risk?: Severity) => {
        const a = anchors.current.get(from)?.getBoundingClientRect();
        const b = anchors.current.get(to)?.getBoundingClientRect();
        if (!a || !b) return [];
        const x1 = a.right - box.left;
        const y1 = a.top + a.height / 2 - box.top;
        const x2 = b.left - box.left;
        const y2 = b.top + b.height / 2 - box.top;
        const mx = x1 + (x2 - x1) * 0.5;
        return [{ key: `${from}>${to}`, d: `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`, from, to, risk }];
      };
      setPaths([
        ...model.sources.flatMap((s) => link(`t:${s.tool}`, `s:${s.id}`)),
        ...model.sources.flatMap((s) => [...s.assets].flatMap((a) => link(`s:${s.id}`, `a:${a}`, byIdRisk.get(a)))),
      ]);
    };
    const schedule = () => {
      if (!raf) raf = requestAnimationFrame(draw);
    };
    const ro = new ResizeObserver(schedule);
    ro.observe(root);
    window.addEventListener('resize', schedule);
    draw();
    return () => {
      ro.disconnect();
      window.removeEventListener('resize', schedule);
      if (raf) cancelAnimationFrame(raf);
    };
  }, [model, inv]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && !document.querySelector('[role="dialog"][aria-modal="true"]') && setPinned(null);
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const pin = (f: NonNullable<Focus>) => setPinned((cur) => (cur && cur.kind === f.kind && cur.id === f.id ? null : f));
  const toggleKind = (k: AssetKind) =>
    setHidden((h) => {
      const n = new Set(h);
      if (n.has(k)) n.delete(k);
      else n.add(k);
      return n;
    });
  const focusLabel = pinned
    ? pinned.kind === 'tool'
      ? clientName(inv, pinned.id as ClientId)
      : pinned.kind === 'source'
        ? model.sources.find((s) => s.id === pinned.id)?.label
        : inv.assets.find((a) => a.id === pinned.id)?.name
    : undefined;
  const assetCount = model.groups.reduce((n, g) => n + g.assets.length, 0);
  // The lines are visual only; say the same thing in words.
  const countOf = (prefix: string) => (lit ? [...lit].filter((id) => id.startsWith(prefix)).length : 0);
  const litCounts = `${countOf('t:')} tool${countOf('t:') === 1 ? '' : 's'}, ${countOf('s:')} source${countOf('s:') === 1 ? '' : 's'}, ${countOf('a:')} asset${countOf('a:') === 1 ? '' : 's'}`;

  return (
    <div className="panel flow">
      <div className="toolbar" role="group" aria-label="Filter">
        <input className="input flow-search" placeholder="Find an asset…" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Find an asset" />
        {presentKinds.map((k) => (
          <button key={k} className="chip" aria-pressed={!hidden.has(k)} onClick={() => toggleKind(k)}>
            <KindMark kind={k} />
            {KIND_LABEL[k].many}
          </button>
        ))}
        <span className="spacer" />
        <button className="chip" aria-pressed={riskyOnly} onClick={() => setRiskyOnly((v) => !v)}>
          Only risky
        </button>
      </div>

      <div className="flow-status" aria-live="polite">
        {pinned ? (
          <>
            Showing what’s connected to <strong>{focusLabel}</strong>
            <span className="sr-only">: {litCounts}</span>
            <button className="linklike" onClick={() => setPinned(null)}>Show everything</button>
          </>
        ) : (
          <span className="meta">Point at anything to trace its connections. Click a tool or a source to keep it in focus.</span>
        )}
      </div>

      {assetCount === 0 ? (
        <div className="empty">Nothing matches these filters.</div>
      ) : (
        <div className="flow-body" ref={body} onPointerLeave={() => setHover(null)} onBlur={(e) => !e.currentTarget.contains(e.relatedTarget as Node | null) && setHover(null)}>
          <svg className="flow-links" aria-hidden>
            {paths.map((p) => {
              const hot = lit && lit.has(p.from) && lit.has(p.to);
              return <path key={p.key} d={p.d} data-risk={p.risk} className={hot ? 'hot' : lit ? 'cold' : ''} />;
            })}
          </svg>

          <section className="flow-col" aria-label="AI tools">
            <header className="flow-col-title">AI tools <CountPill n={model.tools.length} /></header>
            {model.tools.map((t) => {
              const count = new Set(model.sources.filter((s) => s.tool === t.id).flatMap((s) => [...s.assets])).size;
              const assets = inv.assets.filter((a) => a.occurrences.some((o) => o.client === t.id));
              return (
                <button
                  key={t.id}
                  ref={anchor(`t:${t.id}`)}
                  className={`flow-node tool${on(`t:${t.id}`) ? '' : ' dim'}${pinned?.id === t.id ? ' pinned' : ''}`}
                  onPointerEnter={() => setHover({ kind: 'tool', id: t.id })}
                  onFocus={() => setHover({ kind: 'tool', id: t.id })}
                  onClick={() => pin({ kind: 'tool', id: t.id })}
                  aria-pressed={pinned?.id === t.id}
                >
                  <ToolTile id={t.id} name={t.name} />
                  <span className="flow-text">
                    <span className="flow-title">{t.name}</span>
                    <span className="flow-sub">{count} asset{count === 1 ? '' : 's'}</span>
                  </span>
                  <RiskPill assets={assets} />
                </button>
              );
            })}
          </section>

          <section className="flow-col" aria-label="Configured in">
            <header className="flow-col-title">Configured in <CountPill n={model.sources.length} /></header>
            {model.sources.map((s) => (
              <button
                key={s.id}
                ref={anchor(`s:${s.id}`)}
                className={`flow-node source${on(`s:${s.id}`) ? '' : ' dim'}${pinned?.id === s.id ? ' pinned' : ''}`}
                onPointerEnter={() => setHover({ kind: 'source', id: s.id })}
                onFocus={() => setHover({ kind: 'source', id: s.id })}
                onClick={() => pin({ kind: 'source', id: s.id })}
                aria-pressed={pinned?.id === s.id}
                title={s.detail}
              >
                <span className="flow-text">
                  <span className="flow-title">{s.label}</span>
                  <span className="flow-sub">
                    {clientName(inv, s.tool)} · {s.assets.size} item{s.assets.size === 1 ? '' : 's'}
                  </span>
                </span>
              </button>
            ))}
          </section>

          <section className="flow-col assets" aria-label="Assets">
            <header className="flow-col-title">Assets <CountPill n={assetCount} /></header>
            {model.groups.map((g) => (
              <div key={g.kind} className="flow-group">
                <div className="flow-group-title">
                  <IconTile kind={g.kind} size="sm" /> {KIND_LABEL[g.kind].many} <CountPill n={g.assets.length} />
                </div>
                {g.assets.map((a) => {
                  const facts = [
                    a.usage ? `Last used ${relativeTime(a.usage.lastUsedAt)}` : undefined,
                    isSynced(a) ? 'Synced' : undefined,
                    (model.assetSources.get(a.id)?.size ?? 0) > 1 ? `In ${model.assetSources.get(a.id)!.size} places` : undefined,
                    subtitle(a),
                  ].filter(Boolean);
                  return (
                    <button
                      key={a.id}
                      ref={anchor(`a:${a.id}`)}
                      className={`flow-node asset${on(`a:${a.id}`) ? '' : ' dim'}${a.id === selectedId ? ' selected' : ''}`}
                      data-sev={a.risk === 'critical' || a.risk === 'high' ? a.risk : undefined}
                      aria-current={a.id === selectedId ? 'true' : undefined}
                      onPointerEnter={() => setHover({ kind: 'asset', id: a.id })}
                      onFocus={() => setHover({ kind: 'asset', id: a.id })}
                      onClick={() => onSelect(a.id)}
                    >
                      <span className="flow-text">
                        <span className="flow-title">
                          {a.name}
                          {a.isNew && <span className="badge-new">NEW</span>}
                        </span>
                        <span className="flow-sub">{facts.join('  ·  ')}</span>
                      </span>
                      <SevPill severity={a.risk} />
                    </button>
                  );
                })}
              </div>
            ))}
          </section>
        </div>
      )}
    </div>
  );
}
