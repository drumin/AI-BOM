import { useCallback, useEffect, useRef, useState } from 'react';
import { KIND_LABEL, mutate, onActivate, post, relativeTime, type Asset, type AssetKind, type Finding, type FixKind, type Inventory, type Severity } from './lib';
import { FixSheet, type Applied, type FixTarget } from './components/FixSheet';
import { ExplainSheet } from './components/ExplainSheet';
import { SourceSheet } from './components/SourceSheet';
import type { TriageAction } from './components/FindingCard';
import { Summary } from './components/Summary';
import { FlowMap } from './components/FlowMap';
import { ClusterMap } from './components/ClusterMap';
import { InventoryTable } from './components/InventoryTable';
import { FindingsList } from './components/FindingsList';
import { AssetPane } from './components/AssetPane';
import { Connectors, type ConnectorDraft } from './components/Connectors';
import { KindMark } from './components/KindMark';
import { ActivityView } from './components/ActivityView';
import { ContextView } from './components/ContextView';
import { AddSheet } from './components/AddSheet';
import { UpgradeSheet } from './components/UpgradeSheet';
import { IncidentSheet } from './components/IncidentSheet';
import { Welcome } from './components/Welcome';
import { SeverityTrend } from './components/SeverityTrend';
import { CommandPalette, type Command } from './components/CommandPalette';
import { SafeguardsView } from './components/SafeguardsView';
import { TabBar } from './components/TabBar';
import { BaselinesView, type BaselineFilter, type BaselineView } from './components/BaselinesView';
import { buildHash, parseHash, TAB_LABEL, TABS, type Nav, type Tab } from './nav';

interface ScanRow {
  at: string;
  source: string;
  assets: number;
  active: Partial<Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>>;
  muted: number;
  added: number;
  removed: number;
  score?: number;
}

/** Preferences live in ~/.ai-bom/preferences.json, so they survive a new port or browser. */
const savePref = (patch: Record<string, string>) => {
  post('/api/preferences', patch).catch(() => {});
};

interface SnapshotRow {
  id: string;
  createdAt: string;
  title: string;
  files: string[];
  status: 'applied' | 'undone';
}
type Theme = 'system' | 'light' | 'dark';

interface Toast {
  text: string;
  undo?: () => void;
  /** Errors and toasts that carry an action stay until dismissed; plain confirmations clear themselves. */
  sticky?: boolean;
  leaving?: boolean;
}

const NEXT_THEME: Record<Theme, Theme> = { system: 'light', light: 'dark', dark: 'system' };
const prefersReducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function readTheme(): Theme {
  try {
    const t = localStorage.getItem('ai-bom-theme');
    return t === 'light' || t === 'dark' ? t : 'system';
  } catch {
    return 'system';
  }
}

const readNav = (): Nav => {
  const p = parseHash();
  const trail = (history.state as { trail?: string[] } | null)?.trail;
  return { ...p, trail: trail?.length ? trail : p.asset ? [p.asset] : [] };
};

/** Close a popover on outside click / Escape. */
function useDismiss(open: boolean, close: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => ref.current && !ref.current.contains(e.target as Node) && close();
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      close();
      ref.current?.querySelector<HTMLElement>('button[aria-expanded]')?.focus();
    };
    document.addEventListener('pointerdown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('pointerdown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open, close]);
  return ref;
}

export function App() {
  const [inv, setInv] = useState<Inventory | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<null | 'scan' | 'online'>(null);
  const [status, setStatus] = useState('');
  // Where you are (view, open asset, type filter) lives in the URL, so Back, Forward and reload all work.
  const [nav, setNav] = useState<Nav>(readNav);
  const navRef = useRef(nav);
  const [siblings, setSiblings] = useState<string[]>([]);
  const tab = nav.tab;
  const selected = nav.asset;
  const kinds = nav.kinds;
  const [activityQ, setActivityQ] = useState('');
  const [theme, setTheme] = useState<Theme>(readTheme);
  const [menu, setMenu] = useState<null | 'export' | 'online'>(null);
  const [toast, setToast] = useState<Toast | null>(null);
  const [scrolled, setScrolled] = useState(false);
  const [fixTarget, setFixTarget] = useState<FixTarget | null>(null);
  const [explain, setExplain] = useState<Asset | null>(null);
  const [source, setSource] = useState<Asset | null>(null);
  const [snapshots, setSnapshots] = useState<SnapshotRow[]>([]);
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [sheet, setSheet] = useState<null | 'add' | 'incident'>(null);
  const [palette, setPalette] = useState(false);
  // Hidden until the saved preferences have loaded, so it never flashes for someone who dismissed it.
  const [welcomed, setWelcomed] = useState(true);
  const [upgradeAsset, setUpgradeAsset] = useState<Asset | null>(null);
  const [findingsView, setFindingsView] = useState<'active' | 'muted'>('active');
  // Set by the summary's severity / muted links; `n` remounts the list so it applies even when Findings is already open.
  const [findingsFocus, setFindingsFocus] = useState<{ severity?: Severity; n: number }>({ n: 0 });
  const [baselineView, setBaselineView] = useState<BaselineView>('nist-ai-rmf');
  const [baselineFilter, setBaselineFilter] = useState<BaselineFilter>('all');
  const [atlasFocus, setAtlasFocus] = useState<string | undefined>();
  const prefsLoaded = useRef(false);
  const [mapView, setMapView] = useState<'overview' | 'network'>(() => {
    try {
      return localStorage.getItem('ai-bom-map') === 'network' ? 'network' : 'overview';
    } catch {
      return 'overview';
    }
  });
  const chooseMap = (v: 'overview' | 'network') => {
    setMapView(v);
    savePref({ mapView: v });
    try {
      localStorage.setItem('ai-bom-map', v);
    } catch {
      /* storage unavailable */
    }
  };
  const closeMenu = useCallback(() => setMenu(null), []);
  const exportRef = useDismiss(menu === 'export', closeMenu);
  const onlineRef = useDismiss(menu === 'online', closeMenu);

  /** Move to a new place. Opening a view or an asset adds a history entry; filters replace the current one. */
  const navigate = useCallback((patch: Partial<Pick<Nav, 'tab' | 'asset' | 'kinds' | 'trail'>>, mode: 'push' | 'replace' = 'push') => {
    const cur = navRef.current;
    const next: Nav = { ...cur, ...patch };
    if (patch.asset !== undefined && patch.trail === undefined) next.trail = patch.asset ? [patch.asset] : [];
    const same = buildHash(next) === buildHash(cur);
    history[mode === 'push' && !same ? 'pushState' : 'replaceState']({ trail: next.trail }, '', buildHash(next));
    navRef.current = next;
    setNav(next);
  }, []);

  const setTab = (t: Tab) => {
    if (t === navRef.current.tab && !navRef.current.asset) return;
    if (t !== 'baselines') setAtlasFocus(undefined);
    navigate({ tab: t, asset: null });
  };
  const setKinds = useCallback((k: AssetKind[]) => navigate({ kinds: k }, 'replace'), [navigate]);
  /** Open an asset in the side panel. `siblings` is the list it was opened from, for ‹ ›. */
  const openAsset = useCallback(
    (id: string, o?: { fromPane?: boolean; siblings?: string[] }) => {
      const cur = navRef.current;
      if (o?.siblings) setSiblings(o.siblings);
      else if (!o?.fromPane) setSiblings([]);
      if (o?.fromPane && cur.asset) {
        if (cur.asset === id) return;
        navigate({ asset: id, trail: [...cur.trail, id].slice(-20) });
      } else navigate({ asset: id }, cur.asset ? 'replace' : 'push');
    },
    [navigate],
  );
  const closePane = useCallback(() => navigate({ asset: null }, 'replace'), [navigate]);
  const stepAsset = useCallback(
    (dir: -1 | 1) => {
      const cur = navRef.current.asset;
      const i = cur ? siblings.indexOf(cur) : -1;
      const to = siblings[i + dir];
      if (to) navigate({ asset: to }, 'replace');
    },
    [siblings, navigate],
  );

  // [ and ] step through the list the open asset came from.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.key !== '[' && e.key !== ']') || e.metaKey || e.ctrlKey || e.altKey || !navRef.current.asset) return;
      const t = e.target as HTMLElement | null;
      if (t?.closest('input, textarea, select, [contenteditable="true"]') || document.querySelector('[aria-modal="true"]')) return;
      e.preventDefault();
      stepAsset(e.key === '[' ? -1 : 1);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [stepAsset]);

  useEffect(() => {
    fetch('/api/preferences')
      .then((r) => (r.ok ? r.json() : {}))
      .then((p: { theme?: Theme; mapView?: 'overview' | 'network'; findingsView?: 'active' | 'muted'; baselineView?: BaselineView; baselineFilter?: BaselineFilter; welcomed?: 'yes' | 'no' }) => {
        if (p.theme) setTheme(p.theme);
        if (p.mapView) setMapView(p.mapView);
        if (p.findingsView) setFindingsView(p.findingsView);
        if (p.baselineView) setBaselineView(p.baselineView);
        if (p.baselineFilter) setBaselineFilter(p.baselineFilter);
        setWelcomed(p.welcomed === 'yes');
      })
      .catch(() => {})
      .finally(() => (prefsLoaded.current = true));
    fetch('/api/scans').then((r) => (r.ok ? r.json() : [])).then(setScans).catch(() => {});
    fetch('/api/inventory')
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then(setInv)
      .catch((e) => setError(String(e.message ?? e)));
    const onPop = () => {
      const next = readNav();
      navRef.current = next;
      setNav(next);
    };
    const onScroll = () => setScrolled(window.scrollY > 4);
    window.addEventListener('popstate', onPop);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => {
      window.removeEventListener('popstate', onPop);
      window.removeEventListener('scroll', onScroll);
    };
  }, []);

  useEffect(() => {
    if (theme === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', theme);
    try {
      localStorage.setItem('ai-bom-theme', theme);
    } catch {
      /* storage unavailable */
    }
    if (prefsLoaded.current) savePref({ theme });
  }, [theme]);

  // ⌘K / Ctrl+K opens the command palette, unless a dialog is already open.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k' && !document.querySelector('[aria-modal="true"]')) {
        e.preventDefault();
        setPalette(true);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const dismissToast = useCallback(() => {
    setToast((t) => (t ? { ...t, leaving: true } : t));
    window.setTimeout(() => setToast((t) => (t?.leaving ? null : t)), prefersReducedMotion() ? 0 : 160);
  }, []);
  useEffect(() => {
    if (!toast || toast.sticky || toast.undo || toast.leaving) return;
    const t = window.setTimeout(dismissToast, 6000);
    return () => window.clearTimeout(t);
  }, [toast, dismissToast]);

  /** Change theme as one crossfade (when supported and allowed) so the page doesn't flash or smear. */
  const changeTheme = (next: Theme) => {
    const apply = () => {
      if (next === 'system') document.documentElement.removeAttribute('data-theme');
      else document.documentElement.setAttribute('data-theme', next);
      setTheme(next);
    };
    const vt = (document as Document & { startViewTransition?: (cb: () => void) => unknown }).startViewTransition;
    if (vt && !prefersReducedMotion()) vt.call(document, apply);
    else apply();
  };

  const fail = (text: string) => setToast({ text, sticky: true });

  // When a popover opens, move focus into it so keyboard users land on its first control.
  useEffect(() => {
    if (!menu) return;
    const root = menu === 'export' ? exportRef.current : onlineRef.current;
    const raf = requestAnimationFrame(() => root?.querySelector<HTMLElement>('[role="menuitem"], .actions button')?.focus());
    return () => cancelAnimationFrame(raf);
  }, [menu, exportRef, onlineRef]);
  /** Close a popover when focus moves out of it (Tab away). */
  const closeOnBlur = (name: 'export' | 'online') => (e: React.FocusEvent<HTMLDivElement>) => {
    if (menu === name && !e.currentTarget.contains(e.relatedTarget as Node | null)) setMenu(null);
  };
  /** Menu keys: arrows and Home/End move between items; Escape is handled by useDismiss. */
  const onMenuKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const items = [...e.currentTarget.querySelectorAll<HTMLElement>('[role="menuitem"]')];
    const at = items.indexOf(document.activeElement as HTMLElement);
    const to = e.key === 'ArrowDown' ? (at + 1) % items.length : e.key === 'ArrowUp' ? (at - 1 + items.length) % items.length : e.key === 'Home' ? 0 : e.key === 'End' ? items.length - 1 : -1;
    if (to < 0) return;
    e.preventDefault();
    items[to].focus();
  };

  const apply = (next: Inventory) => {
    setInv(next);
    setError(null);
    if (selected && !next.assets.some((a) => a.id === selected)) closePane();
  };

  const rescan = async (online?: boolean) => {
    setMenu(null);
    setBusy(online ? 'online' : 'scan');
    setStatus(online ? 'Checking packages against OSV.dev…' : 'Scanning…');
    try {
      const next = await mutate(`/api/rescan${online === undefined ? '' : `?online=${online ? 1 : 0}`}`);
      apply(next);
      const vulns = next.findings.filter((f) => f.ruleId.startsWith('VULN-')).length;
      setStatus(
        next.vulnCheck?.errors.length
          ? `Scan updated. ${next.vulnCheck.errors.join(' · ')}`
          : online
            ? `Checked ${next.vulnCheck?.packages ?? 0} packages · ${vulns ? `${vulns} known issue${vulns === 1 ? '' : 's'}` : 'no known issues'}`
            : 'Scan updated',
      );
    } catch (e) {
      setStatus(`Scan failed: ${(e as Error).message}`);
    } finally {
      setBusy(null);
      fetch('/api/scans').then((r) => (r.ok ? r.json() : [])).then(setScans).catch(() => {});
    }
  };

  const addConnector = async (d: ConnectorDraft) => apply(await mutate('/api/connectors', 'POST', d));

  const loadSnapshots = useCallback(() => {
    fetch('/api/snapshots').then((r) => (r.ok ? r.json() : [])).then(setSnapshots).catch(() => {});
    fetch('/api/scans').then((r) => (r.ok ? r.json() : [])).then(setScans).catch(() => {});
  }, []);
  useEffect(() => {
    if (tab === 'history') loadSnapshots();
  }, [tab, loadSnapshots]);

  const undo = async (id: string, title: string) => {
    try {
      const r = await post<Applied>(`/api/snapshots/${id}/undo`);
      apply(r.inventory);
      setToast({ text: `Undone: ${title}` });
      loadSnapshots();
    } catch (e) {
      fail(`Couldn’t undo: ${(e as Error).message}`);
    }
  };

  const onApplied = (r: Applied) => {
    setFixTarget(null);
    apply(r.inventory);
    loadSnapshots();
    setToast({ text: `Done: ${r.snapshot.title}`, undo: () => undo(r.snapshot.id, r.snapshot.title) });
  };

  const triage = async (f: Finding, a: TriageAction): Promise<void> => {
    try {
      if (a.status === 'clear') {
        apply(await post<Inventory>(`/api/triage/${f.id}`, undefined, 'DELETE'));
        setToast({ text: `“${f.title}” is active again` });
        return;
      }
      apply(await post<Inventory>('/api/triage', { findingId: f.id, status: a.status, reason: a.reason, until: a.until }));
      const verb = a.status === 'accepted' ? 'Accepted' : a.status === 'snoozed' ? 'Snoozed' : 'Dismissed';
      setToast({
        text: `${verb}: ${f.title}`,
        undo: async () => {
          apply(await post<Inventory>(`/api/triage/${f.id}`, undefined, 'DELETE'));
          dismissToast();
        },
      });
    } catch (e) {
      fail(`Couldn’t update: ${(e as Error).message}`);
    }
  };

  /** Apply one decision to several findings. One toast, one Undo; failures are reported, not hidden. */
  const triageMany = async (list: Finding[], a: TriageAction): Promise<void> => {
    let r: { done: string[]; failed: number; inventory: Inventory };
    try {
      r = await post(`/api/triage/bulk`, { findingIds: list.map((f) => f.id), ...a });
    } catch {
      return fail(`${list.length} couldn’t be updated.`);
    }
    const { done, failed } = r;
    apply(r.inventory);
    const n = done.length;
    const plural = `${n} finding${n === 1 ? '' : 's'}`;
    if (failed) return fail(`${n ? `Updated ${plural}, but ` : ''}${failed} couldn’t be updated.`);
    if (a.status === 'clear') return setToast({ text: `${plural} active again` });
    const verb = a.status === 'accepted' ? 'Accepted' : a.status === 'snoozed' ? 'Snoozed' : 'Dismissed';
    setToast({
      text: `${verb} ${plural}`,
      undo: async () => {
        apply((await post<{ inventory: Inventory }>(`/api/triage/bulk`, { findingIds: done, status: 'clear' })).inventory);
        dismissToast();
      },
    });
  };

  /** Result of a change made through a sheet (add, upgrade, incident): refresh and offer undo. */
  const onChanged = (r: { snapshot?: { id: string; title: string }; inventory: Inventory }, text?: string) => {
    setSheet(null);
    setUpgradeAsset(null);
    apply(r.inventory);
    loadSnapshots();
    const sn = r.snapshot;
    setToast({ text: text ?? (sn ? `Done: ${sn.title}` : 'Done'), undo: sn ? () => undo(sn.id, sn.title) : undefined });
  };

  const showFindings = (show: { severity?: Severity; muted?: boolean } = {}) => {
    const view = show.muted ? 'muted' : 'active';
    if (view !== findingsView) {
      setFindingsView(view);
      savePref({ findingsView: view });
    }
    setFindingsFocus((f) => ({ severity: show.severity, n: f.n + 1 }));
    setTab('findings');
  };

  const onNext = (findingId: string) => {
    const f = inv?.findings.find((x) => x.id === findingId);
    if (!f) return;
    if (f.fixes?.length) setFixTarget({ findingId: f.id, kinds: f.fixes });
    else if (f.assetId) openAsset(f.assetId);
    else setTab('findings');
  };

  const dismissWelcome = () => {
    setWelcomed(true);
    savePref({ welcomed: 'yes' });
    document.getElementById('main')?.focus();
  };
  const chooseBaseline = (v: BaselineView) => {
    setBaselineView(v);
    savePref({ baselineView: v });
  };
  const chooseBaselineFilter = (f: BaselineFilter) => {
    setBaselineFilter(f);
    savePref({ baselineFilter: f });
  };
  /** From a finding's ATLAS tag: close whatever is open and show that technique in the Baselines tab. */
  const openAtlas = useCallback((technique: string) => {
    setBaselineView('atlas');
    setAtlasFocus(technique);
    savePref({ baselineView: 'atlas' });
    setTab('baselines');
  }, []);

  const onFix = useCallback((f: Finding) => f.fixes?.length && setFixTarget({ findingId: f.id, kinds: f.fixes }), []);
  const onAssetFix = useCallback((a: Asset, kinds: FixKind[]) => setFixTarget({ assetId: a.id, kinds }), []);

  const connectorAction = async (a: Asset, action: 'review' | 'remove') => {
    const rid = a.connector?.id;
    if (!rid) return;
    try {
      if (action === 'review') {
        apply(await mutate(`/api/connectors/${rid}/review`));
        setToast({ text: `${a.name} marked as still in use` });
      } else {
        const c = a.connector!;
        apply(await mutate(`/api/connectors/${rid}`, 'DELETE'));
        setToast({
          text: `Removed ${a.name}`,
          // Forgiveness over confirmation: removal is one click, undo is one more.
          undo: async () => {
            apply(await mutate('/api/connectors', 'POST', { platform: c.platform, name: a.name, access: c.access, notes: c.notes }));
            dismissToast();
          },
        });
      }
    } catch (e) {
      fail(`Couldn’t update ${a.name}: ${(e as Error).message}`);
    }
  };

  const download = (name: string, data: unknown) => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
    setMenu(null);
  };

  const onSelect = useCallback((id: string, siblings?: string[]) => openAsset(id, { siblings }), [openAsset]);
  const onSelectFromPane = useCallback((id: string) => openAsset(id, { fromPane: true }), [openAsset]);

  const commands: Command[] = inv
    ? [
        ...TABS.map((t): Command => ({ id: `go-${t}`, label: `Go to ${TAB_LABEL[t]}`, group: 'Go to', keywords: 'open show view tab', run: () => setTab(t) })),
        { id: 'act-rescan', label: 'Rescan now', group: 'Action', keywords: 'scan refresh', run: () => void rescan() },
        { id: 'act-add', label: 'Add a server…', group: 'Action', keywords: 'mcp install', run: () => setSheet('add') },
        { id: 'act-online', label: 'Check vulnerabilities online…', group: 'Action', keywords: 'osv nvd cve', run: () => setMenu('online') },
        { id: 'act-incident', label: 'Respond to an incident…', group: 'Action', keywords: 'pause rotate emergency', run: () => setSheet('incident') },
        { id: 'exp-json', label: 'Export inventory JSON', group: 'Export', keywords: 'download ai-bom', run: () => download('ai-bom.json', inv) },
        { id: 'exp-cdx', label: 'Export CycloneDX', group: 'Export', keywords: 'sbom download', run: () => void fetch('/api/cyclonedx').then((r) => r.json()).then((d) => download('ai-bom.cdx.json', d)) },
        { id: 'exp-report', label: 'Open printable report', group: 'Export', keywords: 'html pdf', run: () => window.open('/api/report.html', '_blank', 'noopener') },
        { id: 'exp-md', label: 'Export Markdown report', group: 'Export', keywords: 'download', run: () => { window.location.href = '/api/report.md'; } },
        { id: 'exp-sarif', label: 'Export SARIF', group: 'Export', keywords: 'github code scanning download', run: () => { window.location.href = '/api/report.sarif'; } },
        ...(['system', 'light', 'dark'] as Theme[]).map((t): Command => ({ id: `theme-${t}`, label: `Theme: ${t}`, group: 'Appearance', keywords: 'dark light mode', run: () => changeTheme(t) })),
        ...inv.assets.map((a): Command => ({ id: `asset-${a.id}`, label: a.name, group: KIND_LABEL[a.kind].one, searchOnly: true, keywords: a.mcp?.package?.name ?? '', run: () => openAsset(a.id) })),
        ...inv.findings.filter((f) => !f.muted).map((f): Command => ({ id: `finding-${f.id}`, label: f.title, group: `${inv.assets.find((a) => a.id === f.assetId)?.name ?? 'Finding'} · ${f.severity}`, searchOnly: true, keywords: `${f.ruleId} ${inv.assets.find((a) => a.id === f.assetId)?.name ?? ''}`, run: () => (f.assetId ? openAsset(f.assetId) : setTab('findings')) })),
      ]
    : [];

  if (error && !inv) return <div className="loading">Could not load inventory: {error}</div>;
  if (!inv) return <div className="loading"><span className="spinner" aria-hidden /> Scanning your AI setup…</div>;

  const asset = selected ? inv.assets.find((a) => a.id === selected) : undefined;
  const newCount = inv.assets.filter((a) => a.isNew).length;
  const activeCount = inv.findings.filter((f) => !f.muted).length;
  const removed = inv.removed ?? [];
  const connectorCount = inv.assets.filter((a) => a.kind === 'connector').length;
  const pkgCount = inv.assets.filter((a) => a.mcp?.package && ['npm', 'pypi'].includes(a.mcp.package.ecosystem)).length;

  return (
    <div className="app">
      <a className="skip" href="#main" onClick={(e) => { e.preventDefault(); document.getElementById('main')?.focus(); }}>Skip to content</a>
      <header className="topbar" data-scrolled={scrolled}>
        <h1 className="brand">
          <span className="brand-mark" aria-hidden>
            <svg width="16" height="16" viewBox="0 0 16 16"><circle cx="4" cy="5" r="2" fill="#fff" /><circle cx="12" cy="5" r="2" fill="#fff" /><circle cx="8" cy="12" r="2" fill="#fff" /><path d="M4 5L8 12L12 5" stroke="#fff" strokeWidth="1.2" fill="none" /></svg>
          </span>
          AI-BOM
        </h1>
        <span className="meta host">
          {inv.host.user}@{inv.host.hostname} · scanned {relativeTime(inv.scannedAt) === 'today' ? new Date(inv.scannedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : relativeTime(inv.scannedAt)}
        </span>
        <span className="spacer" />
        <span className="status meta" role="status" aria-live="polite" title={status}>{status}</span>
        <button className="btn icon" onClick={() => setPalette(true)} aria-label="Search and commands" aria-keyshortcuts="Meta+K Control+K" title={`Search and commands (${/Mac|iPhone|iPad/.test(navigator.platform) ? '⌘K' : 'Ctrl+K'})`}>
          <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden><circle cx="7" cy="7" r="4.6" fill="none" stroke="currentColor" strokeWidth="1.5" /><path d="M10.5 10.5L14 14" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></svg>
        </button>
        <button className="btn icon" onClick={() => changeTheme(NEXT_THEME[theme])} aria-label={`Theme: ${theme}. Switch to ${NEXT_THEME[theme]}`} title={`Theme: ${theme}`}>
          {theme === 'system' ? (
            <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden><rect x="1.75" y="2.75" width="12.5" height="8.5" rx="1.5" fill="none" stroke="currentColor" strokeWidth="1.4" /><path d="M5.5 14h5M8 11.5V14" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" /></svg>
          ) : theme === 'dark' ? (
            <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden><path d="M13.5 9.8A5.8 5.8 0 0 1 6.2 2.5a5.8 5.8 0 1 0 7.3 7.3z" fill="currentColor" /></svg>
          ) : (
            <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden><circle cx="8" cy="8" r="3.2" fill="currentColor" /><g stroke="currentColor" strokeWidth="1.4" strokeLinecap="round">{[0, 45, 90, 135, 180, 225, 270, 315].map((d) => <line key={d} x1="8" y1="1.5" x2="8" y2="3" transform={`rotate(${d} 8 8)`} />)}</g></svg>
          )}
        </button>
        <button className="btn" onClick={() => setSheet('add')}>Add server</button>
        <div className="menu" ref={exportRef} onBlur={closeOnBlur('export')}>
          <button className="btn" onClick={() => setMenu(menu === 'export' ? null : 'export')} onKeyDown={(e) => { if (e.key === 'ArrowDown') { e.preventDefault(); setMenu('export'); } }} aria-expanded={menu === 'export'} aria-haspopup="menu">
            Export
          </button>
          {menu === 'export' && (
            <div className="menu-pop" role="menu" aria-label="Export" onKeyDown={onMenuKey}>
              <button role="menuitem" tabIndex={-1} onClick={() => download('ai-bom.json', inv)}>
                Inventory JSON<small>Full ai-bom format</small>
              </button>
              <button role="menuitem" tabIndex={-1} onClick={async () => download('ai-bom.cdx.json', await (await fetch('/api/cyclonedx')).json())}>
                CycloneDX 1.6<small>Standard AI-BOM / SBOM</small>
              </button>
              <a role="menuitem" tabIndex={-1} href="/api/report.html" target="_blank" rel="noopener" onClick={() => setMenu(null)}>
                Report<small>Printable HTML, save as PDF</small>
              </a>
              <a role="menuitem" tabIndex={-1} href="/api/report.sarif" download="ai-bom.sarif" onClick={() => setMenu(null)}>
                SARIF<small>GitHub code scanning</small>
              </a>
              <a role="menuitem" tabIndex={-1} href="/api/report.md" download="ai-bom.md" onClick={() => setMenu(null)}>
                Markdown<small>For a note or an issue</small>
              </a>
            </div>
          )}
        </div>
        <div className="menu" ref={onlineRef} onBlur={closeOnBlur('online')}>
          <button className="btn" onClick={() => setMenu(menu === 'online' ? null : 'online')} aria-expanded={menu === 'online'} aria-haspopup="dialog" disabled={!!busy}>
            {busy === 'online' ? <><span className="spinner" aria-hidden /> Checking…</> : 'Check vulnerabilities'}
          </button>
          {menu === 'online' && (
            <div className="menu-pop explain" role="dialog" aria-label="Online vulnerability check">
              <strong>Check {pkgCount} MCP package{pkgCount === 1 ? '' : 's'} online?</strong>
              <p>
                Looks up each MCP package in <strong>OSV.dev</strong> and the <strong>NIST NVD</strong>, and asks npm/PyPI which version an unpinned
                call would fetch. Only package <em>names and versions</em> are sent. No paths, settings, keys or file contents leave your machine.
              </p>
              <p className="meta">
                The NVD allows 5 requests per 30 seconds, so the first check takes about {Math.max(1, Math.round((pkgCount * 1.5 * 6.5) / 60))} min; results are cached for a day.
                Bundled advisories and cached package versions are always checked offline.
              </p>
              <div className="actions">
                <button className="btn primary" onClick={() => rescan(true)}>Check now</button>
                {inv.vulnCheck && <button className="btn" onClick={() => rescan(false)}>Go back offline</button>}
              </div>
            </div>
          )}
        </div>
        <button className="btn primary" onClick={() => rescan()} disabled={!!busy}>
          {busy === 'scan' ? <><span className="spinner light" aria-hidden /> Scanning</> : 'Rescan'}
        </button>
      </header>

      <div className="workspace" data-pane={asset ? 'open' : 'closed'}>
      <main id="main" tabIndex={-1}>
        {newCount + removed.length > 0 && (
          <div className="notice">
            <strong>{newCount} new</strong> asset{newCount === 1 ? '' : 's'} since your last scan
            {removed.length > 0 && <>, {removed.length} removed</>}.{' '}
            <button className="linklike" onClick={() => setTab('history')}>Review changes</button>
          </div>
        )}

        {!welcomed && (
          <Welcome
            canStart={!!inv.score?.next[0]}
            onStart={() => {
              dismissWelcome();
              if (inv.score?.next[0]) onNext(inv.score.next[0].findingId);
            }}
            onDismiss={dismissWelcome}
          />
        )}

        <Summary inv={inv} onFindings={showFindings} trend={scans.filter((r) => typeof r.score === 'number').map((r) => ({ at: r.at, value: r.score! })).reverse()} onNext={onNext} onPick={(k) => { setKinds(k); setTab(k[0] === 'connector' ? 'connectors' : 'inventory'); }} />

        <TabBar
          tab={tab}
          onTab={setTab}
          counts={{ inventory: inv.assets.length, findings: activeCount, connectors: connectorCount || undefined, history: newCount + removed.length || undefined }}
          dot={newCount + removed.length > 0 ? 'history' : undefined}
        />

        <div role="tabpanel" id="view-panel" aria-labelledby={`tab-${tab}`} className="tabpanel" key={tab}>
          <h2 className="sr-only">{TAB_LABEL[tab]}</h2>
          {tab === 'map' &&
            (inv.assets.length ? (
              <>
                <div className="view-switch">
                  <div className="segmented" role="radiogroup" aria-label="Map view">
                    {(['overview', 'network'] as const).map((v) => (
                      <label key={v} className={mapView === v ? 'on' : ''}>
                        <input type="radio" name="mapview" checked={mapView === v} onChange={() => chooseMap(v)} />
                        {v === 'overview' ? 'Overview' : 'All connections'}
                      </label>
                    ))}
                  </div>
                  <span className="meta">{mapView === 'overview' ? 'Grouped by tool and type. Open a card to see what’s inside.' : 'Which tool, configured where, uses what. Point at anything to trace it.'}</span>
                </div>
                {mapView === 'overview' ? (
                  <ClusterMap inv={inv} onSelect={onSelect} selectedId={selected} />
                ) : (
                  <FlowMap inv={inv} onSelect={onSelect} selectedId={selected} />
                )}
              </>
            ) : (
              <div className="panel empty-state">
                <h3>{inv.clients.length ? `Found ${inv.clients.map((c) => c.name).join(', ')}, but nothing configured in them` : 'No AI tools found'}</h3>
                <p>
                  No MCP servers, skills, plugins, hooks or instruction files were found in their configuration. If you expected some, run{' '}
                  <code>npm start -- doctor</code> (or <code>ai-bom doctor</code>) in a terminal: it lists every location checked and what was in it,
                  without showing any values, so it’s safe to share.
                </p>
                <p className="meta">Repos outside ~/Projects, ~/code or ~/Developer can be added with <code>--discover &lt;folder&gt;</code>.</p>
              </div>
            ))}
          {tab === 'inventory' && <InventoryTable inv={inv} kinds={kinds} setKinds={setKinds} onSelect={onSelect} selectedId={selected} />}
          {tab === 'findings' && <FindingsList
              key={findingsFocus.n}
              onlySeverity={findingsFocus.severity}
              onFocusUsed={() => setFindingsFocus((f) => (f.severity ? { n: f.n, severity: undefined } : f))}
              inv={inv}
              onSelect={onSelect}
              onFix={onFix}
              onTriage={triage}
              onTriageMany={triageMany}
              onAtlas={openAtlas}
              view={findingsView}
              onView={(v) => {
                setFindingsView(v);
                savePref({ findingsView: v });
              }}
            />}
          {tab === 'baselines' && <BaselinesView inv={inv} view={baselineView} onView={chooseBaseline} filter={baselineFilter} onFilter={chooseBaselineFilter} focusTechnique={atlasFocus} onSelect={onSelect} onFix={onFix} />}
          {tab === 'safeguards' && <SafeguardsView onChanged={(r, text) => onChanged(r, text)} />}
          {tab === 'activity' && (
            <ActivityView
              onIncident={() => setSheet('incident')}
              query={activityQ}
              onQuery={setActivityQ}
              openServer={(name) => {
                const a = inv.assets.find((x) => x.kind === 'mcp-server' && x.name === name);
                if (a) openAsset(a.id);
              }}
            />
          )}
          {tab === 'context' && <ContextView inv={inv} onSelect={onSelect} />}
          {tab === 'connectors' && <Connectors inv={inv} onAdd={addConnector} onAction={connectorAction} onSelect={onSelect} />}
          {tab === 'history' && (
            <>
              <div className="panel">
                <h3 className="panel-title">Since your last scan</h3>
                {newCount + removed.length === 0 ? (
                  <div className="empty">No assets were added or removed since the previous scan.</div>
                ) : (
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>Change</th><th>Name</th><th>Type</th></tr></thead>
                      <tbody>
                        {inv.assets.filter((a) => a.isNew).map((a) => (
                          <tr key={a.id} tabIndex={0} onClick={() => onSelect(a.id)} onKeyDown={onActivate(() => onSelect(a.id))}>
                            <td><span className="badge-new">ADDED</span></td><td>{a.name}</td><td><span className="kind"><KindMark kind={a.kind} />{KIND_LABEL[a.kind].one}</span></td>
                          </tr>
                        ))}
                        {removed.map((a) => (
                          <tr key={a.id} className="static">
                            <td><span className="tag">REMOVED</span></td><td>{a.name}</td><td>{KIND_LABEL[a.kind]?.one ?? a.kind}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
              {scans.length > 1 && (
                <div className="panel pad">
                  <h3 className="section-title">Findings over time</h3>
                  <p className="meta">Active findings per scan, newest on the right. The table below has the same numbers.</p>
                  <SeverityTrend rows={[...scans].reverse()} />
                </div>
              )}
              <div className="panel">
                <h3 className="panel-title">Scans</h3>
                {scans.length === 0 ? (
                  <div className="empty">No scans recorded yet.</div>
                ) : (
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>When</th><th>From</th><th>Assets</th><th>Active findings</th><th>Muted</th></tr></thead>
                      <tbody>
                        {scans.map((r, i) => (
                          <tr key={`${r.at}-${i}`} className="static">
                            <td>{new Date(r.at).toLocaleString()}</td>
                            <td>{r.source}</td>
                            <td>{r.assets}{r.added ? <span className="meta"> · +{r.added}</span> : null}{r.removed ? <span className="meta"> · −{r.removed}</span> : null}</td>
                            <td>{(['critical', 'high', 'medium', 'low'] as const).filter((k) => r.active[k]).map((k) => `${r.active[k]} ${k}`).join(' · ') || 'None'}</td>
                            <td>{r.muted || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
              <div className="panel">
                <h3 className="panel-title">Changes made by AI-BOM</h3>
                {snapshots.length === 0 ? (
                  <div className="empty">Nothing yet. Fixes you apply show up here, and each one can be undone.</div>
                ) : (
                  <ul className="snapshots">
                    {snapshots.map((sn) => (
                      <li key={sn.id} className={sn.status}>
                        <div>
                          <strong>{sn.title}</strong>
                          <div className="meta">{new Date(sn.createdAt).toLocaleString()} · {sn.files.join(', ')}</div>
                        </div>
                        {sn.status === 'applied' ? (
                          <button className="btn small" onClick={() => undo(sn.id, sn.title)}>Undo</button>
                        ) : (
                          <span className="meta">Undone</span>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </>
          )}
        </div>

        {tab === 'history' && (
          <p className="meta footnote">Muted findings, fixes, preferences and this history are saved in ~/.ai-bom. Back them up with <code>ai-bom state export</code>.</p>
        )}
        {inv.errors.length > 0 && (
          <details className="notice">
            <summary>{inv.errors.length} config file(s) could not be read</summary>
            <ul>
              {inv.errors.map((e, i) => (
                <li key={i}><span className="mono">{e.file}</span> — {e.message}</li>
              ))}
            </ul>
          </details>
        )}
        {inv.coverage && inv.coverage.gaps.length > 0 && (
          <details className="notice coverage">
            <summary>What this scan didn’t look at ({inv.coverage.gaps.length})</summary>
            <p className="meta">A clean result only covers what was checked.</p>
            <ul>
              {inv.coverage.gaps.map((g) => (
                <li key={g.what}><strong>{g.what}.</strong> {g.why}</li>
              ))}
            </ul>
          </details>
        )}
        <p className="meta footnote">
          {inv.vulnCheck
            ? `Known-vulnerability data from bundled advisories, ${inv.vulnCheck.sources.join(' and ')} (${relativeTime(inv.vulnCheck.checkedAt)}). `
            : 'Scanned locally. '}
          {inv.sessions ? `Usage from ${inv.sessions.files} agent session log${inv.sessions.files === 1 ? "" : "s"} (read locally). ` : ""}
          {inv.feed ? `Signed advisory feed from ${new Date(inv.feed.generatedAt).toLocaleDateString()}. ` : ''}
          Secret values are redacted; nothing leaves this machine unless you run the online check or ask for an AI review.
        </p>
      </main>

      {asset && (
        <AssetPane
          inv={inv}
          asset={asset}
          onClose={closePane}
          onSelect={onSelectFromPane}
          previous={nav.trail.length > 1 ? inv.assets.find((x) => x.id === nav.trail[nav.trail.length - 2]) : undefined}
          onBack={() => history.back()}
          position={siblings.includes(asset.id) ? { index: siblings.indexOf(asset.id), total: siblings.length } : undefined}
          onStep={stepAsset}
          onConnectorAction={connectorAction}
          onFix={onFix}
          onAssetFix={onAssetFix}
          onTriage={triage}
          onAtlas={openAtlas}
          onExplain={setExplain}
          onViewSource={setSource}
          onViewActivity={(a) => {
            setActivityQ(a.name);
            setTab('activity');
          }}
          onUpgrade={setUpgradeAsset}
          onInventory={apply}
        />
      )}
      </div>

      {fixTarget && <FixSheet target={fixTarget} onClose={() => setFixTarget(null)} onApplied={onApplied} />}
      {explain && <ExplainSheet asset={explain} onClose={() => setExplain(null)} />}
      {source && <SourceSheet asset={source} findings={inv?.findings.filter((f) => f.assetId === source.id) ?? []} onClose={() => setSource(null)} />}
      {sheet === 'add' && <AddSheet onClose={() => setSheet(null)} onAdded={(r) => onChanged(r)} />}
      {sheet === 'incident' && (
        <IncidentSheet
          onClose={() => setSheet(null)}
          onDone={(r) => onChanged(r, `Incident steps applied. Report saved to ${r.report}`)}
        />
      )}
      {upgradeAsset && <UpgradeSheet asset={upgradeAsset} onClose={() => setUpgradeAsset(null)} onDone={(r) => onChanged(r)} />}

      {palette && <CommandPalette commands={commands} onClose={() => setPalette(false)} />}

      <div className="toast-region" role="status" aria-live="polite">
        {toast && (
          <div className="toast" data-leaving={toast.leaving ? 'true' : 'false'}>
            <span>{toast.text}</span>
            {toast.undo && <button className="linklike" onClick={toast.undo}>Undo</button>}
            {(toast.undo || toast.sticky) && <button className="linklike dismiss" onClick={dismissToast} aria-label="Dismiss">×</button>}
          </div>
        )}
      </div>
    </div>
  );
}
