import { scan, type ScanOptions } from './scan.js';
import type { Inventory } from './types.js';
import { tilde } from './util/paths.js';

/** A scan with the list of every location checked, grouped for `ai-bom doctor` and the dashboard. Paths use `~`. */
export async function doctorScan(opts: ScanOptions, home: string) {
  const inv: Inventory = await scan({ ...opts, historyFile: undefined, trace: true });
  const trace = inv.trace ?? [];
  const uniq = (xs: { path: string; note?: string }[]) => [...new Map(xs.map((t) => [`${t.path}|${t.note ?? ''}`, { path: tilde(t.path, home), note: t.note }])).values()];
  return {
    inv,
    trace,
    found: uniq(trace.filter((t) => t.status === 'found')),
    errors: uniq(trace.filter((t) => t.status === 'error')),
    missing: trace.filter((t) => t.status === 'missing').map((t) => tilde(t.path, home)),
  };
}
