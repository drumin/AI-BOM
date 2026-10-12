import { KIND_LABEL, type AssetKind } from './lib';

export type Tab = 'map' | 'inventory' | 'findings' | 'baselines' | 'safeguards' | 'activity' | 'context' | 'connectors' | 'history';

export const TABS: Tab[] = ['map', 'inventory', 'findings', 'baselines', 'safeguards', 'activity', 'context', 'connectors', 'history'];

export const TAB_LABEL: Record<Tab, string> = {
  map: 'Map',
  inventory: 'Inventory',
  findings: 'Findings',
  baselines: 'Baselines',
  safeguards: 'Safeguards',
  activity: 'Activity',
  context: 'Context',
  connectors: 'Connectors',
  history: 'History',
};

/**
 * Where the user is: a view, optionally an open asset, and the inventory's type filter.
 * `trail` is the chain of assets opened by following links inside the detail pane (for "Back").
 */
export interface Nav {
  tab: Tab;
  asset: string | null;
  kinds: AssetKind[];
  trail: string[];
}

type Place = Pick<Nav, 'tab' | 'asset' | 'kinds'>;

/** `#inventory?a=<asset id>&k=skill,hook`. A bare `#findings` is still valid. */
export function parseHash(hash: string = location.hash): Place {
  const raw = hash.replace(/^#/, '');
  const [name, query = ''] = raw.split('?');
  const tab = (name === 'changes' ? 'history' : name) as Tab;
  const params = new URLSearchParams(query);
  const kinds = (params.get('k') ?? '').split(',').filter((k): k is AssetKind => k in KIND_LABEL);
  return { tab: TABS.includes(tab) ? tab : 'map', asset: params.get('a') || null, kinds };
}

export function buildHash(p: Place): string {
  const params = new URLSearchParams();
  if (p.asset) params.set('a', p.asset);
  if (p.kinds.length) params.set('k', p.kinds.join(','));
  const q = params.toString();
  return `#${p.tab}${q ? `?${q}` : ''}`;
}

export const sameHash = (a: Place, b: Place) => buildHash(a) === buildHash(b);
