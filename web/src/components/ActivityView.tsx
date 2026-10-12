import { createPortal } from 'react-dom';
import { createContext, memo, useContext, useDeferredValue, useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { post } from '../lib';
import { highlight, Markdown } from './Markdown';
import { Sheet } from './Sheet';

interface Ev {
  at?: string;
  kind: string;
  text: string;
  detail?: string;
  flag?: string;
  why?: string;
  match?: string;
  mutedFlag?: string;
  mutedKey?: string;
  server?: string;
  output?: string;
  outputHidden?: boolean;
  failed?: boolean;
  sub?: string;
  sensitive?: string;
  auto?: Autonomy;
  injected?: boolean;
  after?: string;
}
type Autonomy = 'auto' | 'bypass' | 'headless' | 'no-approval' | 'edits' | 'background';
interface Exposure {
  sensitive: { what: string; at?: string; count: number }[];
  contacts: { name: string; type: 'host' | 'tool'; count: number; first?: string; last?: string; after: boolean }[];
}
interface Touched {
  path: string;
  read: number;
  wrote: number;
  edited: number;
}
interface Session {
  agent: string;
  session: string;
  project?: string;
  start?: string;
  end?: string;
  counts: Record<string, number>;
  flagged: number;
  events: Ev[];
  hosts: string[];
  files: string[];
  touched: Touched[];
  omitted: number;
  exposure?: Exposure;
  modes: Autonomy[];
  followed: number;
}

/** How a step was approved when no person was asked, and what that means. */
const AUTO: Record<Autonomy, [string, string]> = {
  auto: ['Auto mode', 'Tool calls were approved automatically, not by you.'],
  bypass: ['Permissions bypassed', 'Approval prompts were turned off, so nothing asked you before tools ran.'],
  headless: ['Headless', 'Started without a terminal (a script, scheduler or the Agent SDK), so nobody was watching.'],
  'no-approval': ['No approvals', 'The agent was set never to ask for approval.'],
  edits: ['Edits auto-accepted', 'File edits were accepted without asking you.'],
  background: ['Background agent', 'Claude Desktop ran this as a delegated agent, on its own, while you did something else.'],
};

const AGENT: Record<string, string> = { 'claude-code': 'Claude Code', codex: 'Codex', 'gemini-cli': 'Gemini CLI', 'claude-desktop': 'Claude Desktop', 'copilot-cli': 'Copilot CLI', cline: 'Cline / Roo / Kilo' };
const KIND: Record<string, [string, string]> = {
  prompt: ['prompt', 'prompts'], response: ['reply', 'replies'], command: ['command', 'commands'], write: ['file created', 'files created'], edit: ['edit', 'edits'], read: ['read', 'reads'],
  fetch: ['fetch', 'fetches'], search: ['search', 'searches'], mcp: ['MCP call', 'MCP calls'], skill: ['skill', 'skills'], agent: ['subagent', 'subagents'], other: ['other step', 'other steps'],
};

/** The groups shown as filters. Flagged steps always stay visible. */
const GROUPS = [
  { id: 'prompt', label: 'Your prompts', kinds: ['prompt'] },
  { id: 'reply', label: 'Agent replies', kinds: ['response'] },
  { id: 'command', label: 'Commands', kinds: ['command'] },
  { id: 'file', label: 'Files', kinds: ['read', 'write', 'edit'] },
  { id: 'web', label: 'Web', kinds: ['fetch', 'search'] },
  { id: 'tool', label: 'Tools & agents', kinds: ['mcp', 'skill', 'agent', 'other'] },
] as const;
type GroupId = (typeof GROUPS)[number]['id'];

const CONTEXT = 3;
const PAGE = 150;
const TURNS = 20;
type Mode = 'conversation' | 'all' | 'flagged';

const time = (at?: string) => (at ? new Date(at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '');
/** "12 min ago", "3 h ago", then the date. */
function ago(iso: string): string {
  const mins = Math.round((Date.now() - Date.parse(iso)) / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  if (mins < 24 * 60) return `${Math.round(mins / 60)} h ago`;
  return new Date(iso).toLocaleDateString([], { month: 'short', day: 'numeric' });
}
const plural = (n: number, k: string) => `${n} ${KIND[k]?.[n === 1 ? 0 : 1] ?? k}`;

/** A mute rule in words: the kind, "kind — only x", or "kind — one step at <time>". */
function muteLabel(rule: string): string {
  const [flag, how, rest] = rule.split('::');
  return how === 'match' ? `${flag} — only “${rest}”` : how === 'step' ? `${flag} — one step${rest ? ` at ${new Date(rest).toLocaleString()}` : ''}` : rule;
}

/* ---------------- shared state for rows ---------------- */

interface Tools {
  q: string;
  mode: Mode;
  /** A mute rule: a kind, `kind::match::x` or `kind::step::time` (see activity.ts). `days` snoozes it. */
  mute: (rule: string, on: boolean, days?: number) => void;
  /** Ask before muting a kind of flag (it applies to every session). */
  askMute: (flag: string) => void;
  /** Open an MCP server's drawer, when it's in the inventory. */
  openServer?: (name: string) => void;
}
const ToolsCtx = createContext<Tools>({ q: '', mode: 'conversation', mute: () => undefined, askMute: () => undefined });

const matches = (e: Ev, q: string) => !q || `${e.text}\n${e.detail ?? ''}\n${e.output ?? ''}\n${e.server ?? ''}`.toLowerCase().includes(q);

/* ---------------- rows ---------------- */

type Row = { ev: Ev; ctx?: boolean } | { gap: number };

/** Flagged view: each flagged step with the prompt before it and the few steps that led up to it. Full view: everything in the chosen groups. */
function rowsFor(events: Ev[], mode: 'flagged' | 'all', groups: Set<GroupId>): Row[] {
  if (mode === 'all') {
    const kinds = new Set(GROUPS.filter((g) => groups.has(g.id)).flatMap((g) => g.kinds as readonly string[]));
    return events.filter((e) => e.flag || kinds.has(e.kind)).map((ev) => ({ ev }));
  }
  const show = new Map<number, boolean>();
  events.forEach((e, i) => {
    if (!e.flag) return;
    show.set(i, false);
    let back = 0;
    for (let j = i - 1; j >= 0; j--) {
      if (events[j].kind === 'prompt') {
        if (!show.has(j)) show.set(j, true);
        break;
      }
      if (back < CONTEXT && !show.has(j)) {
        show.set(j, true);
        back++;
      }
    }
  });
  const rows: Row[] = [];
  let last = -1;
  for (const i of [...show.keys()].sort((a, b) => a - b)) {
    if (last >= 0 && i > last + 1) rows.push({ gap: i - last - 1 });
    rows.push({ ev: events[i], ctx: show.get(i) });
    last = i;
  }
  return rows;
}

function Output({ e }: { e: Ev }) {
  if (e.outputHidden) return <p className="meta out-note">Output isn’t shown for commands that touch credentials.</p>;
  if (!e.output) return null;
  return (
    <div className="out">
      <span className="prompt-label">Output{e.failed && <span className="tag bad-tag">failed</span>}</span>
      <pre>{e.output}</pre>
    </div>
  );
}

function Why({ e }: { e: Ev }) {
  const { askMute, mute } = useContext(ToolsCtx);
  if (!e.flag || !e.why) return null;
  const flag = e.flag;
  // Rules are stored as strings of at most ~600 characters; a very long match is only offered as a whole kind.
  const exact = e.match && `${flag}::match::${e.match}`.length < 500 ? e.match : undefined;
  return (
    <div className="why">
      <p><strong>Why it’s flagged.</strong> {e.why}</p>
      {e.after && <p>It came soon after <strong>{e.after}</strong> returned text addressed to the AI model.</p>}
      {e.auto && <p>{AUTO[e.auto][0]}: {AUTO[e.auto][1]} No approval prompt would have stopped this.</p>}
      <div className="why-actions" role="group" aria-label="What to do about this flag">
        {e.at && <button className="linklike" onClick={() => mute(`${flag}::step::${e.at}`, true)} title="Keep this one step as it is and stop flagging it. Other steps of this kind are still flagged. Undo from the “Not flagged” tag on the step.">Accept this risk</button>}
        <span className="meta">Stop flagging:</span>
        {exact && <button className="linklike" onClick={() => mute(`${flag}::match::${exact}`, true)} aria-label={`Stop flagging only “${exact}”`} title="Stop flagging just this one: every step that matches it, in any session.">only “{exact.length > 30 ? `${exact.slice(0, 30)}…` : exact}”</button>}
        <button className="linklike" onClick={() => askMute(flag)} aria-label={`Stop flagging this kind: ${flag}`} title="Stop flagging this whole kind of step. You’ll be asked to confirm, and can turn it back on from “Muted flags”.">this kind</button>
        <span className="meta">Snooze this kind:</span>
        <button className="linklike" onClick={() => mute(flag, true, 7)}>7 days</button>
        <button className="linklike" onClick={() => mute(flag, true, 30)}>30 days</button>
      </div>
    </div>
  );
}

function EventRow({ e, ctx }: { e: Ev; ctx?: boolean }) {
  const { q, mode, mute, openServer } = useContext(ToolsCtx);
  const cls = `${e.flag ? 'flag' : ''}${ctx ? ' ctx' : ''}${e.sub ? ' sub' : ''}`.trim();
  const marks = [{ term: e.flag ? e.match : undefined, cls: 'flag-mark' }, { term: q, cls: 'q-mark' }];
  if (e.kind === 'prompt' || e.kind === 'response') {
    const reply = e.kind === 'response';
    return (
      <li className={`${reply ? 'reply-row' : 'prompt'} ${cls}`.trim()}>
        <span className="mono t">{time(e.at)}</span>
        <div className="prompt-body">
          <span className="prompt-label">{reply ? 'Agent' : 'You'}</span>
          {e.detail ? (
            <details open={!!q && e.detail.toLowerCase().includes(q)}>
              <summary>{highlight(e.text, marks)}</summary>
              {reply ? <Markdown text={e.detail} className="md-reply" mark={q} plainHeadings /> : <pre>{highlight(e.detail, marks)}</pre>}
            </details>
          ) : (
            <span className="prompt-text">{highlight(e.text, marks)}</span>
          )}
        </div>
      </li>
    );
  }
  const expandable = !!(e.detail || e.output || e.outputHidden || (e.flag && e.why));
  const server = e.kind === 'mcp' && e.server && openServer ? e.server : undefined;
  const open = (mode === 'flagged' && !!e.flag) || (!!q && `${e.detail ?? ''}${e.output ?? ''}`.toLowerCase().includes(q));
  return (
    <li className={cls}>
      <span className="mono t">{time(e.at)}</span>
      {expandable ? (
        <details className="what" open={open}>
          <summary>
            {e.sub && <span className="tag sub-tag">subagent</span>}
            {highlight(e.text, marks)}
            {e.failed && <span className="tag bad-tag">failed</span>}
          </summary>
          <Why e={e} />
          {e.detail && <pre>{highlight(e.detail, marks)}</pre>}
          <Output e={e} />
        </details>
      ) : (
        <span className="what">
          {e.sub && <span className="tag sub-tag">subagent</span>}
          {highlight(e.text, marks)}
          {server && <button className="linklike inline" onClick={() => openServer?.(server)}>View server</button>}
        </span>
      )}
      {e.flag && (
        <span className="row-flags">
          {e.auto && <span className="tag auto-tag" title={AUTO[e.auto][1]}>{AUTO[e.auto][0]}</span>}
          <span className="pill bad">{e.flag}</span>
        </span>
      )}
      {!e.flag && e.mutedFlag && (
        <button className="tag muted-tag" onClick={() => mute(e.mutedKey ?? e.mutedFlag!, false)} title="You stopped flagging this step. Click to flag it again.">Not flagged · {e.mutedFlag}</button>
      )}
    </li>
  );
}

/* ---------------- conversation ---------------- */

interface Turn {
  prompt?: Ev;
  /** Everything between the prompt and the final reply, in order. */
  steps: Ev[];
  reply?: Ev;
}

/** One turn per prompt: your message, what the agent did, and its final written reply. */
function turnsOf(events: Ev[]): Turn[] {
  const turns: Turn[] = [];
  let cur: Turn | undefined;
  for (const e of events) {
    if (e.kind === 'prompt') turns.push((cur = { prompt: e, steps: [] }));
    else {
      if (!cur) turns.push((cur = { steps: [] }));
      cur.steps.push(e);
    }
  }
  for (const t of turns) {
    const last = t.steps.map((e) => e.kind).lastIndexOf('response');
    if (last >= 0) t.reply = t.steps.splice(last, 1)[0];
  }
  return turns;
}

const TurnCard = memo(function TurnCard({ t, agent }: { t: Turn; agent: string }) {
  const { q } = useContext(ToolsCtx);
  const actions = t.steps.filter((e) => e.kind !== 'response').length;
  const notes = t.steps.length - actions;
  const findings = t.steps.filter((e) => e.flag).length;
  const bySub = t.steps.filter((e) => e.sub && e.kind !== 'response').length;
  const stepHit = !!q && t.steps.some((e) => matches(e, q));
  const hl = (s: string) => highlight(s, [{ term: q, cls: 'q-mark' }]);
  return (
    <article className={`turn${findings ? ' has-flags' : ''}`}>
      {t.prompt && (
        <div className="turn-prompt">
          <div className="turn-head"><span className="prompt-label">You</span><span className="mono t">{time(t.prompt.at)}</span>{t.prompt.auto && <span className="tag auto-tag" title={AUTO[t.prompt.auto][1]}>{AUTO[t.prompt.auto][0]}</span>}</div>
          {t.prompt.detail ? (
            <details open={!!q && t.prompt.detail.toLowerCase().includes(q)}>
              <summary>{hl(t.prompt.text)}</summary>
              <pre>{hl(t.prompt.detail)}</pre>
            </details>
          ) : (
            <p>{hl(t.prompt.text)}</p>
          )}
        </div>
      )}
      {t.steps.length > 0 && (
        <details className="turn-actions" open={stepHit}>
          <summary>
            <svg className="chev" width="10" height="10" viewBox="0 0 10 10" aria-hidden><path d="M3 1.5l4 3.5-4 3.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
            <span>{actions > 0 ? `${actions} action${actions === 1 ? '' : 's'}${bySub ? ` (${bySub} by subagents)` : ''}` : `${notes} earlier message${notes === 1 ? '' : 's'}`}</span>
            {findings > 0 && <span className="pill bad">{findings} finding{findings === 1 ? '' : 's'}</span>}
          </summary>
          <ol className="timeline">{t.steps.map((e, i) => <EventRow key={i} e={e} />)}</ol>
        </details>
      )}
      {t.reply && (
        <div className="turn-reply">
          <div className="turn-head"><span className="prompt-label">{agent}</span><span className="mono t">{time(t.reply.at)}</span></div>
          <Markdown text={t.reply.detail ?? t.reply.text} className="md-reply" mark={q} plainHeadings />
        </div>
      )}
    </article>
  );
});

function DataTrail({ x, project }: { x: Exposure; project?: string }) {
  const hosts = x.contacts.filter((c) => c.type === 'host');
  const tools = x.contacts.filter((c) => c.type === 'tool');
  const after = x.sensitive.length > 0 && hosts.some((c) => c.after);
  const parts = [x.sensitive.length > 0 && `${x.sensitive.length} sensitive file${x.sensitive.length === 1 ? '' : 's'}`, hosts.length > 0 && `${hosts.length} host${hosts.length === 1 ? '' : 's'} contacted`, tools.length > 0 && `${tools.length} tool server${tools.length === 1 ? '' : 's'}`].filter(Boolean);
  return (
    <details className={`trail${after ? ' warn' : ''}`}>
      <summary>
        Data trail <span className="meta">· {parts.join(' · ')}</span>
        {after && <span className="pill bad">reached the network after a sensitive file</span>}
      </summary>
      <div className="trail-grid">
        <div>
          <h4>Sensitive files touched</h4>
          {x.sensitive.length === 0 ? <p className="meta">None.</p> : (
            <ul>{x.sensitive.map((s) => <li key={s.what}><span className="mono">{s.what}</span><span className="meta">{s.count > 1 ? `×${s.count} · ` : ''}{time(s.at)}</span></li>)}</ul>
          )}
        </div>
        <div>
          <h4>Reached</h4>
          {x.contacts.length === 0 ? <p className="meta">Nothing outside this computer.</p> : (
            <ul>
              {x.contacts.map((c) => (
                <li key={`${c.type}|${c.name}`} className={c.after && x.sensitive.length > 0 ? 'after' : ''}>
                  <span className="mono">{c.name}{c.type === 'tool' && <span className="tag">tool</span>}</span>
                  <span className="meta">{c.count > 1 ? `×${c.count} · ` : ''}{time(c.last)}{c.after && x.sensitive.length > 0 ? ' · after' : ''}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
      <p className="meta">{x.sensitive.length > 0 && x.contacts.length > 0 ? 'These happened in the same session, so a sensitive file’s contents could have been sent. AI-BOM can’t see what was actually transmitted. ' : ''}Hosts come from commands, web fetches and tool arguments{project ? ` in ${project.split('/').pop()}` : ''}.</p>
    </details>
  );
}

function FilesTouched({ s }: { s: Session }) {
  const { q } = useContext(ToolsCtx);
  const strip = (p: string) => (s.project && p.startsWith(s.project + '/') ? p.slice(s.project.length + 1) : p);
  const list = q ? s.touched.filter((t) => t.path.toLowerCase().includes(q)) : s.touched;
  if (!s.touched.length) return null;
  const changed = s.touched.filter((t) => t.wrote || t.edited).length;
  return (
    <details className="touched" open={!!q && list.length > 0}>
      <summary>
        Files touched ({s.touched.length}){changed > 0 && <span className="meta"> · {changed} created or edited</span>}
      </summary>
      <ul>
        {list.slice(0, 200).map((t) => (
          <li key={t.path}>
            <span className="mono path">{highlight(strip(t.path), [{ term: q, cls: 'q-mark' }])}</span>
            <span className="tags">
              {t.wrote > 0 && <span className="tag strong">created{t.wrote > 1 ? ` ×${t.wrote}` : ''}</span>}
              {t.edited > 0 && <span className="tag strong">edited{t.edited > 1 ? ` ×${t.edited}` : ''}</span>}
              {t.read > 0 && <span className="tag">read{t.read > 1 ? ` ×${t.read}` : ''}</span>}
            </span>
          </li>
        ))}
      </ul>
      <p className="meta">Only files the agent opened or changed with its own file tools. Changes made by shell commands (like <code>rm</code> or <code>sed</code>) show up as commands instead.</p>
    </details>
  );
}

function SessionCard({ s, mode, groups, q }: { s: Session; mode: Mode; groups: Set<GroupId>; q: string }) {
  const [more, setMore] = useState(0);
  const conversation = mode === 'conversation';
  const limit = (conversation ? TURNS : PAGE) + more;
  const turns = useMemo(() => (conversation ? turnsOf(s.events) : []), [conversation, s.events]);
  const shownTurns = q ? turns.filter((t) => [t.prompt, t.reply, ...t.steps].some((e) => e && matches(e, q))) : turns;
  const rows = useMemo(() => {
    if (conversation) return [];
    const r = rowsFor(s.events, mode as 'flagged' | 'all', groups);
    return q ? r.filter((x): x is { ev: Ev; ctx?: boolean } => 'ev' in x && matches(x.ev, q)) : r;
  }, [conversation, s.events, mode, groups, q]);
  const total = conversation ? shownTurns.length : rows.length;
  const root = useRef<HTMLDetailsElement>(null);
  const [jump, setJump] = useState(0);
  // Open the session, make sure the first flagged step is on the page (it may be past "Show more"), then scroll to it.
  const goToFinding = (ev: React.MouseEvent) => {
    ev.preventDefault();
    ev.stopPropagation();
    if (root.current) root.current.open = true;
    const at = conversation ? shownTurns.findIndex((t) => t.steps.some((e) => e.flag)) : rows.findIndex((r) => 'ev' in r && r.ev.flag);
    if (at >= limit) setMore(more + at + 1 - limit);
    setJump((n) => n + 1);
  };
  useEffect(() => {
    if (!jump || !root.current) return;
    const first = root.current.querySelector<HTMLElement>('li.flag');
    for (let el: Element | null | undefined = first; el && el !== root.current; el = el.parentElement) if (el instanceof HTMLDetailsElement) el.open = true;
    (first ?? root.current).scrollIntoView({ block: 'center', behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
    first?.querySelector('summary')?.focus({ preventScroll: true });
  }, [jump]);
  const empty = q ? 'Nothing here matches your search.' : mode === 'flagged' ? 'Nothing flagged in this session.' : conversation ? 'No steps recorded.' : 'No steps match these filters.';
  return (
    <details ref={root} className={`panel session${s.flagged ? ' has-flags' : ''}`} open={!!q || (mode === 'flagged' ? s.flagged > 0 : conversation && s.flagged > 0)}>
      <summary>
        <strong>{AGENT[s.agent] ?? s.agent}</strong>
        <span className="meta">{s.project ?? 'unknown folder'}</span>
        <span className="spacer" />
        {s.followed > 0 && <span className="pill bad" title="Steps taken soon after a tool result contained instructions for the model">{s.followed} after injected text</span>}
        {s.modes.slice(0, 2).map((m) => <span key={m} className="tag auto-tag" title={AUTO[m][1]}>{AUTO[m][0]}</span>)}
        {s.flagged > 0 && <span className="pill bad">{s.flagged} flagged</span>}
        <span className="meta" title={s.start ? new Date(s.start).toLocaleString() : undefined}>{s.start ? ago(s.start) : ''}</span>
      </summary>
      <div className="session-meta meta">
        {s.flagged > 0 && <button className="btn small quiet" onClick={goToFinding}>{s.flagged > 1 ? 'Go to first finding' : 'Go to finding'}</button>}
        {Object.entries(s.counts).map(([k, n]) => plural(n, k)).join(' · ')}
        {s.hosts.length > 0 && <> · contacted <span className="mono">{s.hosts.slice(0, 6).join(', ')}</span></>}
      </div>
      {s.exposure && <DataTrail x={s.exposure} project={s.project} />}
      <FilesTouched s={s} />
      {total === 0 ? (
        <div className="meta session-empty">{empty}</div>
      ) : conversation ? (
        <div className="turns">{shownTurns.slice(0, limit).map((t, i) => <TurnCard key={i} t={t} agent={AGENT[s.agent] ?? s.agent} />)}</div>
      ) : (
        <ol className="timeline">
          {rows.slice(0, limit).map((r, i) =>
            'gap' in r ? (
              <li key={i} className="gap meta" aria-hidden>⋯ {r.gap} other step{r.gap === 1 ? '' : 's'}</li>
            ) : (
              <EventRow key={i} e={r.ev} ctx={r.ctx} />
            ),
          )}
        </ol>
      )}
      {total > limit && <button className="btn small more" onClick={() => setMore(more + (conversation ? TURNS : PAGE))}>Show {Math.min(conversation ? TURNS : PAGE, total - limit)} more {conversation ? 'turns' : 'steps'}</button>}
      {mode !== 'flagged' && s.omitted > 0 && <div className="meta session-empty">{s.omitted} more routine step{s.omitted === 1 ? '' : 's'} in this very long session aren’t listed. Every flagged step and prompt is.</div>}
    </details>
  );
}

const sessionHit = (s: Session, q: string) =>
  !q || s.events.some((e) => matches(e, q)) || s.touched.some((t) => t.path.toLowerCase().includes(q)) || (s.project ?? '').toLowerCase().includes(q);

/** What agents actually did, per session, from their own logs (read locally). */
export function ActivityView({
  onIncident,
  query = '',
  onQuery,
  openServer,
}: {
  onIncident: () => void;
  /** Search text carried in from elsewhere (for example "See in Activity" on a server). */
  query?: string;
  onQuery?: (q: string) => void;
  openServer?: (name: string) => void;
}) {
  const [days, setDays] = useState(7);
  const [list, setList] = useState<Session[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>('conversation');
  const [groups, setGroups] = useState<Set<GroupId>>(new Set(GROUPS.map((g) => g.id)));
  const [text, setText] = useState(query);
  const [muted, setMuted] = useState<string[]>([]);
  const [until, setUntil] = useState<Record<string, string>>({});
  const [showMuted, setShowMuted] = useState(false);
  const [reload, setReload] = useState(0);
  const q = useDeferredValue(text.trim().toLowerCase());
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => setText(query), [query]);
  useEffect(() => {
    setList(null);
    fetch(`/api/activity?days=${days}`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then(setList)
      .catch((e) => setError((e as Error).message));
  }, [days, reload]);
  useEffect(() => {
    fetch('/api/activity/mutes').then((r) => r.json()).then((r: { muted: string[]; until?: Record<string, string> }) => { setMuted(r.muted); setUntil(r.until ?? {}); }).catch(() => undefined);
  }, [reload]);
  const mute = (flag: string, on: boolean, days?: number) => {
    post<{ muted: string[] }>('/api/activity/mute', { flag, muted: on, days })
      .then((r) => { setMuted(r.muted); setReload((n) => n + 1); })
      .catch((e) => setError((e as Error).message));
  };
  const [confirming, setConfirming] = useState<string | null>(null);
  const tools = useMemo<Tools>(() => ({ q, mode, mute, askMute: setConfirming, openServer }), [q, mode, openServer]);
  const affected = useMemo(() => {
    const hits = (list ?? []).flatMap((s) => s.events.filter((e) => e.flag === confirming).map((e) => ({ e, s })));
    return { steps: hits.length, sessions: new Set(hits.map((h) => h.s.session)).size, examples: hits.slice(0, 3).map((h) => h.e.text) };
  }, [list, confirming]);
  const visible = list?.filter((s) => sessionHit(s, q));
  const flagged = visible?.reduce((n, s) => n + s.flagged, 0) ?? 0;
  /** Up / Down move between the disclosure rows (sessions, "n actions", files, data trail). */
  const onKeys = (e: KeyboardEvent) => {
    if ((e.key !== 'ArrowDown' && e.key !== 'ArrowUp') || (e.target as HTMLElement).tagName !== 'SUMMARY') return;
    const all = [...(root.current?.querySelectorAll<HTMLElement>('summary') ?? [])].filter((el) => el.offsetParent !== null);
    const i = all.indexOf(e.target as HTMLElement);
    const next = all[i + (e.key === 'ArrowDown' ? 1 : -1)];
    if (i >= 0 && next) {
      e.preventDefault();
      next.focus();
    }
  };
  const toggle = (id: GroupId) =>
    setGroups((g) => {
      const n = new Set(g);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  return (
    <ToolsCtx.Provider value={tools}>
      <div className="activity" ref={root} onKeyDown={onKeys}>
        <div className="panel pad activity-head">
          <div>
            <h3 className="section-title">What your agents did</h3>
            <p className="meta">Each prompt and the agent’s reply, with everything it did in between one click away. From Claude Code, Codex and Gemini CLI logs on this machine; risky steps are flagged and nothing leaves your computer.</p>
          </div>
          <div className="activity-controls">
            <div className="segmented" role="radiogroup" aria-label="What to show">
              {([['conversation', 'Conversation'], ['all', 'Every step'], ['flagged', 'Flagged only']] as const).map(([id, label]) => (
                <label key={id} className={mode === id ? 'on' : ''}>
                  <input type="radio" name="mode" checked={mode === id} onChange={() => setMode(id)} />
                  {label}
                </label>
              ))}
            </div>
            <div className="segmented" role="radiogroup" aria-label="Time range">
              {[1, 7, 30].map((d) => (
                <label key={d} className={days === d ? 'on' : ''}>
                  <input type="radio" name="days" checked={days === d} onChange={() => setDays(d)} />
                  {d === 1 ? '24 h' : `${d} days`}
                </label>
              ))}
            </div>
            <button className="btn danger small" onClick={onIncident} title="Pause servers, list keys to rotate, write a report">Respond to an incident…</button>
          </div>
          <div className="activity-search">
            <input
              className="input"
              type="search"
              value={text}
              onChange={(e) => { setText(e.target.value); onQuery?.(e.target.value); }}
              placeholder="Search prompts, replies, commands, files…"
              aria-label="Search activity"
            />
            {muted.length > 0 && (
              <button className="btn small" aria-expanded={showMuted} onClick={() => setShowMuted(!showMuted)}>Muted flags ({muted.length})</button>
            )}
          </div>
          {showMuted && muted.length > 0 && (
            <ul className="muted-list">
              {muted.map((m) => (
                <li key={m}>
                  <span>{muteLabel(m)}{until[m] && <span className="meta"> · back {new Date(until[m]).toLocaleDateString()}</span>}</span>
                  <button className="linklike" onClick={() => mute(m, false)}>Flag again</button>
                </li>
              ))}
            </ul>
          )}
          {mode === 'all' && (
            <div className="activity-filters" role="group" aria-label="Show these steps">
              {GROUPS.map((g) => (
                <label key={g.id} className="check"><input type="checkbox" checked={groups.has(g.id)} onChange={() => toggle(g.id)} /> {g.label}</label>
              ))}
            </div>
          )}
        </div>
        {error && <div className="panel empty" role="alert">Couldn’t read session logs: {error}. Try again, or run <code>ai-bom doctor</code> in a terminal.</div>}
        {!list && !error && <div className="panel empty"><span className="spinner" aria-hidden /> Reading session logs…</div>}
        {list && !list.length && <div className="panel empty">No agent sessions in this period.</div>}
        {list && list.length > 0 && !visible?.length && <div className="panel empty">No session matches “{text.trim()}”.</div>}
        {visible && visible.length > 0 && (
          <p className="meta">
            {visible.length} session{visible.length === 1 ? '' : 's'}{q && list && visible.length !== list.length && ` of ${list.length}`} · {flagged} flagged step{flagged === 1 ? '' : 's'}
            {mode === 'flagged' && ' · each with your prompt and the steps just before it, so you can see why'}
          </p>
        )}
        {visible?.map((s) => <SessionCard key={`${s.agent}|${s.session}`} s={s} mode={mode} groups={groups} q={q} />)}
      </div>
      {confirming && createPortal(
        <Sheet
          title="Stop flagging this kind of step?"
          onClose={() => setConfirming(null)}
          footer={
            <>
              <span className="spacer" />
              <button className="btn" onClick={() => setConfirming(null)} data-autofocus>Cancel</button>
              <button className="btn primary" onClick={() => { mute(confirming, true); setConfirming(null); }}>Stop flagging</button>
            </>
          }
        >
          <p><strong>{confirming}</strong></p>
          <p>
            Steps like this won’t be flagged any more, in any session, in the Activity tab or in <code>ai-bom timeline</code>. They still appear in the timeline, marked “Not flagged”.
            {affected.steps > 0 && <> Right now that’s {affected.steps} step{affected.steps === 1 ? '' : 's'} in {affected.sessions} session{affected.sessions === 1 ? '' : 's'}.</>}
          </p>
          {affected.examples.length > 0 && <ul className="plain mono mute-examples">{affected.examples.map((x, i) => <li key={i}>{x}</li>)}</ul>}
          <p className="meta">Only mute this if it’s routine for you. You can turn it back on any time from “Muted flags”.</p>
        </Sheet>,
        // Sheets must be direct children of .app so the page behind them can be made inert.
        document.querySelector('.app') ?? document.body,
      )}
    </ToolsCtx.Provider>
  );
}
