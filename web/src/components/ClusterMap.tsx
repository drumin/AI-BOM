import { useCallback, useLayoutEffect, useMemo, useRef, useState } from 'react';
import {
  clientName,
  KIND_LABEL,
  KIND_ORDER,
  isPendingApproval,
  isSynced,
  relativeTime,
  SCOPE_LABEL,
  sevRank,
  subtitle,
  TOOL_GROUP_ORDER,
  toolGroup,
  worst,
  type Asset,
  type AssetKind,
  type ClientId,
  type Inventory,
  type Severity,
} from '../lib';
import { Chevron, CountPill, IconTile, RiskPill, SevPill, ToolTile } from './ui';

/**
 * Overview map: AI tools on the left, what they use on the right (clubbed by
 * type), linked by how many assets connect them. Each card shows its facts
 * inside and opens like a dropdown to list its contents.
 */

interface Link {
  tool: ClientId;
  kind: AssetKind;
  count: number;
  risk?: Severity;
}

const LIST_LIMIT = 8;

/** Only the two worst levels get a visual signal on a card; the rest stay quiet. */
const riskAttr = (list: (Severity | undefined)[]) => {
  const w = worst(list);
  return w === 'critical' || w === 'high' ? w : undefined;
};

function AssetRow({ a, inv, onSelect, context, dim, selected }: { a: Asset; inv: Inventory; onSelect: (id: string) => void; context: 'tool' | 'kind'; dim?: boolean; selected?: boolean }) {
  const tools = [...new Set(a.occurrences.map((o) => o.client))].map((t) => clientName(inv, t));
  const projects = [...new Set(a.occurrences.map((o) => (o.project ? o.project.split('/').pop() : undefined)).filter(Boolean))];
  const off = a.occurrences.every((o) => o.enabled === false);
  const pending = !off && isPendingApproval(a);
  // Short facts first so truncation only ever cuts the free-text description.
  const detail = [
    a.usage ? `Last used ${relativeTime(a.usage.lastUsedAt)}` : undefined,
    context === 'kind' ? `Used by ${tools.join(', ')}` : undefined,
    projects.length ? `Project: ${projects.join(', ')}` : undefined,
    subtitle(a),
  ].filter(Boolean);
  return (
    <li className={dim ? 'dim' : undefined}>
      <button className={`arow${selected ? ' selected' : ''}`} aria-current={selected ? 'true' : undefined} onClick={() => onSelect(a.id)}>
        <span className="arow-main">
          <span className="arow-line">
            <span className="arow-name">{a.name}</span>
            {a.isNew && <span className="badge-new">NEW</span>}
            {off && <span className="tag">Off</span>}
            {pending && <span className="tag">Not approved</span>}
            {isSynced(a) && <span className="tag">Synced</span>}
          </span>
          <span className="arow-detail">{detail.join('  ·  ')}</span>
        </span>
        <SevPill severity={a.risk} />
      </button>
    </li>
  );
}

function Expander({ open, children, id }: { open: boolean; children: React.ReactNode; id: string }) {
  return (
    // Content stays mounted so closing animates too; `inert` keeps it out of the tab order while closed.
    <div className="expander" data-open={open} id={id} inert={!open}>
      <div className="expander-inner">{children}</div>
    </div>
  );
}

export function ClusterMap({ inv, onSelect, selectedId }: { inv: Inventory; onSelect: (id: string) => void; selectedId?: string | null }) {
  const body = useRef<HTMLDivElement>(null);
  const anchors = useRef(new Map<string, HTMLElement>());
  const [paths, setPaths] = useState<{ key: string; d: string; w: number; tool: string; kind: string; risk?: Severity }[]>([]);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [hover, setHover] = useState<{ tool?: ClientId; kind?: AssetKind } | null>(null);
  const [showAll, setShowAll] = useState<Set<string>>(new Set());

  const { tools, kinds, links, byTool, byKind } = useMemo(() => {
    const byTool = new Map<ClientId, Asset[]>();
    const byKind = new Map<AssetKind, Asset[]>();
    const linkMap = new Map<string, Link>();
    for (const a of inv.assets) {
      byKind.set(a.kind, [...(byKind.get(a.kind) ?? []), a]);
      for (const t of new Set(a.occurrences.map((o) => o.client))) {
        byTool.set(t, [...(byTool.get(t) ?? []), a]);
        const key = `${t}|${a.kind}`;
        const l = linkMap.get(key) ?? { tool: t, kind: a.kind, count: 0 };
        l.count++;
        l.risk = worst([l.risk, a.risk]);
        linkMap.set(key, l);
      }
    }
    const tools = inv.clients
      .filter((c) => byTool.has(c.id))
      .sort((a, b) => TOOL_GROUP_ORDER.indexOf(toolGroup(a.id)) - TOOL_GROUP_ORDER.indexOf(toolGroup(b.id)) || byTool.get(b.id)!.length - byTool.get(a.id)!.length);
    const kinds = KIND_ORDER.filter((k) => byKind.has(k));
    return { tools, kinds, links: [...linkMap.values()], byTool, byKind };
  }, [inv]);
  const idle = inv.clients.filter((c) => !byTool.has(c.id));

  const toggle = (key: string) =>
    setOpen((cur) => {
      const n = new Set(cur);
      if (n.has(key)) n.delete(key);
      else n.add(key);
      return n;
    });

  const anchor = useCallback(
    (key: string) => (el: HTMLElement | null) => {
      if (el) anchors.current.set(key, el);
      else anchors.current.delete(key);
    },
    [],
  );

  // Links run from each tool card's header to each type card's header; redrawn on
  // every size change (opening cards animates their height), batched per frame.
  useLayoutEffect(() => {
    const root = body.current;
    if (!root) return;
    let raf = 0;
    const draw = () => {
      raf = 0;
      const box = root.getBoundingClientRect();
      if (getComputedStyle(root).getPropertyValue('--links').trim() === 'off') return setPaths([]);
      setPaths(
        links.flatMap((l) => {
          const a = anchors.current.get(`tool:${l.tool}`)?.getBoundingClientRect();
          const b = anchors.current.get(`kind:${l.kind}`)?.getBoundingClientRect();
          if (!a || !b) return [];
          const x1 = a.right - box.left;
          const y1 = a.top + a.height / 2 - box.top;
          const x2 = b.left - box.left;
          const y2 = b.top + b.height / 2 - box.top;
          const mx = (x1 + x2) / 2;
          return [{ key: `${l.tool}|${l.kind}`, d: `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`, w: 1 + Math.min(l.count, 12) * 0.35, tool: l.tool, kind: l.kind, risk: l.risk }];
        }),
      );
    };
    const schedule = () => {
      if (!raf) raf = requestAnimationFrame(draw);
    };
    const ro = new ResizeObserver(schedule);
    ro.observe(root);
    root.querySelectorAll('.ccard').forEach((c) => ro.observe(c));
    window.addEventListener('resize', schedule);
    draw();
    return () => {
      ro.disconnect();
      window.removeEventListener('resize', schedule);
      if (raf) cancelAnimationFrame(raf);
    };
  }, [links, tools, kinds]);

  const active = (tool: string, kind: string) => !hover || ((hover.tool ? hover.tool === tool : true) && (hover.kind ? hover.kind === kind : true));
  const toolLinked = (t: ClientId) => !hover || (hover.tool ? hover.tool === t : links.some((l) => l.tool === t && l.kind === hover.kind));
  const kindLinked = (k: AssetKind) => !hover || (hover.kind ? hover.kind === k : links.some((l) => l.kind === k && l.tool === hover.tool));

  let lastGroup = '';

  return (
    <div className="panel cmap">
      <div className="cmap-status meta" aria-hidden>
        {hover?.tool
          ? `Showing what ${clientName(inv, hover.tool)} uses. Lines that end at an orange or red card lead to something risky.`
          : hover?.kind
            ? `Showing which tools use ${KIND_LABEL[hover.kind].many.toLowerCase()}.`
            : 'Point at a tool or a type to trace what connects. Lines that end at an orange or red card lead to something risky. Open a card to see what is inside.'}
      </div>
      <div className="cmap-body" ref={body} onPointerLeave={() => setHover(null)} onBlur={(e) => !e.currentTarget.contains(e.relatedTarget as Node | null) && setHover(null)}>
        <svg className="cmap-links" aria-hidden>
          {paths.map((p) => (
            <path key={p.key} d={p.d} strokeWidth={p.w} data-risk={p.risk === 'critical' || p.risk === 'high' ? p.risk : undefined} className={active(p.tool, p.kind) ? (hover ? 'hot' : '') : 'cold'} />
          ))}
        </svg>

        <section className="cmap-col" aria-label="AI tools">
          <header className="cmap-col-title">
            AI tools <CountPill n={tools.length} />
          </header>
          {tools.map((c) => {
            const list = byTool.get(c.id)!;
            const key = `tool:${c.id}`;
            const isOpen = open.has(key);
            const group = toolGroup(c.id);
            const header = group !== lastGroup ? <div className="cmap-group">{group}</div> : null;
            lastGroup = group;
            const perKind = KIND_ORDER.map((k) => [k, list.filter((a) => a.kind === k)] as const).filter(([, l]) => l.length);
            const places = [
              ...new Set(list.flatMap((a) => a.occurrences.filter((o) => o.client === c.id).map((o) => (o.project ? `${SCOPE_LABEL[o.scope]}: ${o.project.split('/').pop()}` : SCOPE_LABEL[o.scope])))),
            ];
            return (
              <div key={c.id} className="cmap-slot">
                {header}
                <div className={`ccard${toolLinked(c.id) ? '' : ' faded'}`} data-sev={riskAttr(list.map((a) => a.risk))} onPointerEnter={() => setHover({ tool: c.id })}>
                  <button className="ccard-head" ref={anchor(key)} aria-expanded={isOpen} aria-controls={`${key}-list`} onClick={() => toggle(key)} onFocus={() => setHover({ tool: c.id })}>
                    <ToolTile id={c.id} name={c.name} />
                    <span className="ccard-text">
                      <span className="ccard-title">
                        {c.name}
                        <CountPill n={list.length} label="assets" />
                      </span>
                      <span className="ccard-sub">
                        {perKind.map(([k, l]) => `${l.length} ${(l.length === 1 ? KIND_LABEL[k].one : KIND_LABEL[k].many).toLowerCase()}`).join(', ')}
                      </span>
                    </span>
                    <RiskPill assets={list} />
                    <Chevron open={isOpen} />
                  </button>
                  <Expander open={isOpen} id={`${key}-list`}>
                    <div className="facts">
                      <span className="fact-k">Configured at</span>
                      <span className="fact-v">{places.join(', ')}</span>
                    </div>
                    {perKind.map(([k, l]) => (
                      <div key={k} className="sublist">
                        <div className="sublist-title">
                          <IconTile kind={k} size="sm" /> {KIND_LABEL[k].many} <CountPill n={l.length} />
                        </div>
                        <ul>
                          {[...l].sort((x, y) => sevRank(x.risk) - sevRank(y.risk) || x.name.localeCompare(y.name)).map((a) => (
                            <AssetRow key={a.id} a={a} inv={inv} onSelect={onSelect} context="tool" selected={a.id === selectedId} />
                          ))}
                        </ul>
                      </div>
                    ))}
                  </Expander>
                </div>
              </div>
            );
          })}
          {idle.length > 0 && <p className="meta idle">Installed, nothing configured: {idle.map((c) => c.name).join(', ')}</p>}
        </section>

        <section className="cmap-col" aria-label="What they use">
          <header className="cmap-col-title">
            What they use <CountPill n={inv.assets.length} />
          </header>
          {kinds.map((k) => {
            const list = [...byKind.get(k)!].sort((x, y) => sevRank(x.risk) - sevRank(y.risk) || x.name.localeCompare(y.name));
            const key = `kind:${k}`;
            const isOpen = open.has(key);
            const shared = list.filter((a) => new Set(a.occurrences.map((o) => o.client)).size > 1).length;
            const fresh = list.filter((a) => a.isNew).length;
            const remote = k === 'mcp-server' ? list.filter((a) => a.mcp?.url || a.mcp?.remoteUrl).length : 0;
            const visible = showAll.has(k) ? list : list.slice(0, LIST_LIMIT);
            const forTool = hover?.tool ? list.filter((a) => a.occurrences.some((o) => o.client === hover.tool)).length : undefined;
            const facts = [
              forTool !== undefined ? `${forTool} used by ${clientName(inv, hover!.tool!)}` : '',
              remote ? `${remote} remote` : '',
              shared ? `${shared} in several tools` : '',
              fresh ? `${fresh} new` : '',
            ].filter(Boolean);
            return (
              <div key={k} className={`ccard ccard-kind${kindLinked(k) ? '' : ' faded'}`} data-sev={riskAttr(list.map((a) => a.risk))} onPointerEnter={() => setHover({ kind: k })}>
                <button className="ccard-head" ref={anchor(key)} aria-expanded={isOpen} aria-controls={`${key}-list`} onClick={() => toggle(key)} onFocus={() => setHover({ kind: k })}>
                  <IconTile kind={k} />
                  <span className="ccard-text">
                    <span className="ccard-title">
                      {KIND_LABEL[k].many}
                      <CountPill n={list.length} />
                    </span>
                    <span className="ccard-sub">{facts.join(', ') || ' '}</span>
                  </span>
                  <RiskPill assets={list} />
                  <Chevron open={isOpen} />
                </button>
                <Expander open={isOpen} id={`${key}-list`}>
                  <ul>
                    {visible.map((a) => (
                      <AssetRow key={a.id} a={a} inv={inv} onSelect={onSelect} context="kind" selected={a.id === selectedId} dim={!!hover?.tool && !a.occurrences.some((o) => o.client === hover.tool)} />
                    ))}
                  </ul>
                  {list.length > LIST_LIMIT && !showAll.has(k) && (
                    <button className="linklike more" onClick={() => setShowAll((s) => new Set(s).add(k))}>
                      Show all {list.length}
                    </button>
                  )}
                </Expander>
              </div>
            );
          })}
        </section>
      </div>
    </div>
  );
}
