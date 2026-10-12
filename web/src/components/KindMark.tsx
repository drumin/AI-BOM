import { KIND_VAR, type AssetKind } from '../lib';

/**
 * Kind swatch that carries shape as well as color, matching the graph nodes,
 * so asset types stay distinguishable without relying on hue alone.
 */
const PATHS: Record<AssetKind, string> = {
  'mcp-server': 'M6 1a5 5 0 1 1 0 10A5 5 0 0 1 6 1z',
  skill: 'M6 1.2l5 9.3H1z',
  plugin: 'M3.2 1.2h5.6L11.5 6l-2.7 4.8H3.2L.5 6z',
  extension: 'M3.2 1.2h5.6L11.5 6l-2.7 4.8H3.2L.5 6z',
  hook: 'M6 .8L11.2 6 6 11.2.8 6z',
  agent: 'M6 .9l5 3.7-1.9 6H2.9L1 4.6z',
  command: 'M2.5 1.5h7a1.5 1.5 0 0 1 1.5 1.5v6a1.5 1.5 0 0 1-1.5 1.5h-7A1.5 1.5 0 0 1 1 9V3a1.5 1.5 0 0 1 1.5-1.5z',
  instructions: 'M1.5 1.5h9v9h-9z',
  connector: 'M3 3.5h6a2.5 2.5 0 0 1 0 5H3a2.5 2.5 0 0 1 0-5z',
  // Wider inventory: shapes, not new hues, tell these apart.
  telemetry: 'M1 7.5h2l1.5-4 3 7 1.5-3H11v1.5H9.8L8 12.5l-3-7-1 3.5H1z',
  model: 'M6 .8l4.8 2.7v5L6 11.2 1.2 8.5v-5z',
  'api-key': 'M4 2.2a3 3 0 0 1 2.8 4H11v2H9.5v1.5h-2V8.2h-.7A3 3 0 1 1 4 2.2zm0 2a1 1 0 1 0 0 2 1 1 0 0 0 0-2z',
  app: 'M3 1h6a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V3a2 2 0 0 1 2-2z',
  'browser-extension': 'M1 3.5h3.2a1.6 1.6 0 1 1 3.2 0H11V11H1zM1 5.5',
};

export function KindMark({ kind, size = 12 }: { kind: AssetKind; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 12 12" aria-hidden className="kindmark">
      <path d={PATHS[kind]} fill={`var(${KIND_VAR[kind]})`} />
    </svg>
  );
}
