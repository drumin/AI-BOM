import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import {
  CAPABILITY_LABEL,
  clientName,
  FIX_LABEL,
  formatBytes,
  KIND_LABEL,
  relativeTime,
  SCOPE_LABEL,
  SENSITIVE_CAPS,
  SEV_VAR,
  type Asset,
  type Finding,
  type FixKind,
  type Inventory,
} from '../lib';
import { FindingCard, type TriageAction } from './FindingCard';
import { KindMark } from './KindMark';
import { Sev } from './Severity';
import { DepsSection, LiveInspect } from './ServerExtras';
import { IconTile, SevPill } from './ui';

const EXPLAINABLE = new Set(['skill', 'agent', 'command', 'instructions', 'hook', 'mcp-server']);

const TRUST_LEVEL = { good: ['Good signals', 'ok'], mixed: ['Mixed signals', 'warn'], poor: ['Poor signals', 'bad'], unknown: ['Not enough data', ''] } as const;

type SectionId = 'overview' | 'findings' | 'details' | 'where';

export function AssetPane({
  inv,
  asset,
  onClose,
  onSelect,
  onConnectorAction,
  onFix,
  onAssetFix,
  onTriage,
  onExplain,
  onViewSource,
  onViewActivity,
  onUpgrade,
  onInventory,
  onAtlas,
  previous,
  onBack,
  position,
  onStep,
}: {
  inv: Inventory;
  asset: Asset;
  onClose: () => void;
  onSelect: (id: string) => void;
  onConnectorAction: (a: Asset, action: 'review' | 'remove') => void;
  onFix: (f: Finding) => void;
  onAssetFix: (a: Asset, kinds: FixKind[]) => void;
  onTriage: (f: Finding, a: TriageAction) => void;
  onExplain: (a: Asset) => void;
  onViewSource: (a: Asset) => void;
  onViewActivity: (a: Asset) => void;
  onUpgrade: (a: Asset) => void;
  onInventory: (inv: Inventory) => void;
  onAtlas?: (id: string) => void;
  /** The asset you came from, when you followed a link inside the pane. */
  previous?: Asset;
  onBack: () => void;
  /** Place in the list the asset was opened from, for ‹ ›. */
  position?: { index: number; total: number };
  onStep: (dir: -1 | 1) => void;
}) {
  const pane = useRef<HTMLElement>(null);
  const body = useRef<HTMLDivElement>(null);
  const title = useRef<HTMLHeadingElement>(null);
  const returnFocus = useRef<Element | null>(null);
  const [section, setSection] = useState<SectionId>('overview');

  // A non-modal side panel: the page stays live. Focus moves in once when it opens, and goes back to
  // whatever opened it when it closes.
  useLayoutEffect(() => {
    returnFocus.current = document.activeElement;
    title.current?.focus({ preventScroll: true });
    return () => {
      const el = returnFocus.current as HTMLElement | null;
      if (el && el.isConnected) el.focus?.({ preventScroll: true });
    };
  }, []);

  useEffect(() => {
    body.current?.scrollTo({ top: 0 });
    setSection('overview');
  }, [asset.id]);

  const close = useCallback(() => onClose(), [onClose]);
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape' && !e.defaultPrevented) {
      e.preventDefault();
      close();
    }
  };

  const show = (id: SectionId) => {
    setSection(id);
    body.current?.scrollTo({ top: 0 });
  };

  const findings = inv.findings.filter((f) => f.assetId === asset.id || f.related?.includes(asset.id)).sort((x, y) => Number(!!x.muted) - Number(!!y.muted));
  const byId = new Map(inv.assets.map((a) => [a.id, a]));
  const parents = [...new Set(asset.occurrences.map((o) => o.via).filter(Boolean))].map((id) => byId.get(id!)).filter(Boolean) as Asset[];
  const children = (asset.children ?? []).map((id) => byId.get(id)).filter(Boolean) as Asset[];
  const m = asset.mcp;
  const upgradable = !!m?.package && (m.package.ecosystem === 'npm' || m.package.ecosystem === 'pypi') && asset.occurrences.some((o) => o.scope !== 'managed');
  const viewable = !asset.connector && (!!asset.path || asset.occurrences.length > 0);
  const usable = asset.kind === 'mcp-server' || asset.kind === 'skill';
  const s = asset.skill;
  const c = asset.connector;
  const activeFindings = findings.filter((f) => !f.muted).length;
  const childIds = new Set(asset.children ?? []);
  const bundled = inv.findings.filter((f) => !f.muted && f.assetId && childIds.has(f.assetId)).length;

  const chips: [SectionId, string][] = [
    ['overview', 'Overview'],
    ['findings', activeFindings ? `Findings ${activeFindings}` : 'Findings'],
    ['details', 'Details'],
    ['where', 'Where'],
  ];

  return (
    <aside className="pane" ref={pane} aria-label={`Details: ${asset.name}`} onKeyDown={onKeyDown}>
      <header className="pane-head">
        <div className="pane-bar">
          {previous ? (
            <button className="btn small quiet pane-back" onClick={onBack} aria-label={`Back to ${previous.name}`} title={`Back to ${previous.name}`}>
              <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden><path d="M7.5 2L3.5 6l4 4" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
              <span className="pane-back-name">{previous.name}</span>
            </button>
          ) : (
            <span className="meta pane-kind">{KIND_LABEL[asset.kind].one}</span>
          )}
          <span className="spacer" />
          {position && position.total > 1 && (
            <>
              <span className="meta pane-pos" aria-live="polite">{position.index + 1} of {position.total}</span>
              <button className="btn icon small quiet" onClick={() => onStep(-1)} disabled={position.index <= 0} aria-label="Previous item" title="Previous ([)">
                <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden><path d="M2.5 7.5L6 4l3.5 3.5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
              </button>
              <button className="btn icon small quiet" onClick={() => onStep(1)} disabled={position.index >= position.total - 1} aria-label="Next item" title="Next (])">
                <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden><path d="M2.5 4.5L6 8l3.5-3.5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
              </button>
            </>
          )}
          <button className="btn icon small quiet" onClick={close} aria-label="Close details" title="Close (Esc)">
            <svg width="12" height="12" viewBox="0 0 14 14" aria-hidden><path d="M3 3l8 8M11 3l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></svg>
          </button>
        </div>
        <div className="pane-title">
          <IconTile kind={asset.kind} />
          <div className="pane-title-text">
            <h2 tabIndex={-1} ref={title}>{asset.name}</h2>
            <div className="pane-badges">
              {previous && <span className="tag">{KIND_LABEL[asset.kind].one}</span>}
              {asset.isNew && <span className="badge-new">NEW</span>}
              <SevPill severity={asset.risk} />
              {!asset.risk && <span className="meta">No issues found</span>}
              {asset.risk && !activeFindings && bundled > 0 && <span className="meta">from {bundled} item{bundled === 1 ? '' : 's'} inside</span>}
            </div>
          </div>
        </div>
        <nav className="pane-sections" aria-label="Sections">
          {chips.map(([id, label]) => (
            <button key={id} className="pane-chip" aria-current={section === id ? 'true' : undefined} onClick={() => show(id)}>{label}</button>
          ))}
        </nav>
      </header>

      <div className="pane-body" ref={body}>
        <section data-sec="overview" hidden={section !== 'overview'} aria-label="Overview">
        {(EXPLAINABLE.has(asset.kind) || viewable || usable || asset.fixes?.length || upgradable) && (
          <div className="pane-actions">
            {EXPLAINABLE.has(asset.kind) && (
              <button className="btn small" onClick={() => onExplain(asset)}>
                <svg width="13" height="13" viewBox="0 0 14 14" aria-hidden><path d="M7 1.2l1.5 3.3 3.3 1.5-3.3 1.5L7 10.8 5.5 7.5 2.2 6l3.3-1.5z" fill="currentColor" /></svg>
                Explain in plain words
              </button>
            )}
            {viewable && (
              <button className="btn small" onClick={() => onViewSource(asset)}>
                <svg width="13" height="13" viewBox="0 0 14 14" aria-hidden><path d="M3.5 1.5h4.6L11 4.4v8.1H3.5z M8 1.6v3h3" stroke="currentColor" strokeWidth="1.3" fill="none" strokeLinejoin="round" /></svg>
                View file
              </button>
            )}
            {usable && <button className="btn small" onClick={() => onViewActivity(asset)}>See in Activity</button>}
            {upgradable && <button className="btn small" onClick={() => onUpgrade(asset)}>Check for update…</button>}
            {asset.fixes?.map((k) => (
              <button key={k} className="btn small" onClick={() => onAssetFix(asset, [k])}>{FIX_LABEL[k]}…</button>
            ))}
          </div>
        )}

        <dl className="glance">
          <div>
            <dt>Used by</dt>
            <dd>{[...new Set(asset.occurrences.map((o) => clientName(inv, o.client)))].join(', ')}</dd>
          </div>
          <div>
            <dt>Scope</dt>
            <dd>
              {[...new Set(asset.occurrences.map((o) => (o.project ? `${SCOPE_LABEL[o.scope]} · ${o.project.split('/').pop()}` : SCOPE_LABEL[o.scope])))].join(', ')}
            </dd>
          </div>
          {m?.package && m.package.ecosystem !== 'binary' && (
            <div>
              <dt>Package</dt>
              <dd className="mono">{m.package.name}{m.package.version ? `@${m.package.version}` : ''}</dd>
            </div>
          )}
          {m && (
            <div>
              <dt>Runs as</dt>
              <dd>{m.url ? 'Remote server' : m.remoteUrl ? 'Local proxy to a remote server' : 'Local process'}</dd>
            </div>
          )}
          <div>
            <dt>Last used</dt>
            <dd>
              {asset.usage
                ? `${relativeTime(asset.usage.lastUsedAt)} · ${asset.usage.count} ${asset.usage.source === 'session-logs' ? (asset.usage.count === 1 ? 'call' : 'calls') : '×'}`
                : inv.sessions && (asset.kind === 'mcp-server' || asset.kind === 'skill') && asset.occurrences.some((o) => o.client === 'claude-code')
                  ? 'Not in your session logs'
                  : asset.kind === 'skill' || asset.kind === 'plugin'
                    ? 'No record'
                    : '—'}
            </dd>
          </div>
          <div>
            <dt>Last changed</dt>
            <dd>{relativeTime(asset.occurrences.map((o) => o.modifiedAt).filter(Boolean).sort().pop())}</dd>
          </div>
          <div>
            <dt>Findings</dt>
            <dd>{findings.length || 'None'}</dd>
          </div>
        </dl>
        </section>

        <section data-sec="findings" hidden={section !== 'findings'} aria-label="Findings">
        <h3>Findings ({findings.length})</h3>
        {findings.length === 0 && <div className="meta">No issues found for this asset itself.{bundled > 0 && ` The ${asset.risk ?? ''} rating comes from ${bundled} finding${bundled === 1 ? '' : 's'} on the items bundled with it (see Bundles under Where).`}</div>}
        {findings.map((f) => (
          <FindingCard
            as="h4"
            onAtlas={onAtlas}
            key={f.id}
            f={f}
            related={f.related?.map((id) => byId.get(id)).filter((a): a is Asset => !!a)}
            onSelect={onSelect}
            onFix={onFix}
            onTriage={onTriage}
          />
        ))}
        </section>

        <section data-sec="details" hidden={section !== 'details'} aria-label="Details">
        {c && (
          <>
            <h3>Connector</h3>
            <dl className="kv">
              <dt>Platform</dt>
              <dd>{c.platform}</dd>
              <dt>Access</dt>
              <dd>{c.access === 'read-write' ? 'Read & write' : c.access === 'read' ? 'Read only' : 'Unknown'}</dd>
              {c.detectedIn ? (
                <>
                  <dt>Found in</dt>
                  <dd>{c.detectedIn}</dd>
                </>
              ) : (
                <>
                  <dt>Added</dt>
                  <dd>{relativeTime(c.addedAt)}</dd>
                  <dt>Last reviewed</dt>
                  <dd>{relativeTime(c.reviewedAt)}</dd>
                </>
              )}
              {c.notes && (<><dt>Notes</dt><dd>{c.notes}</dd></>)}
            </dl>
            {!c.detectedIn && (
              <div className="actions">
                <button className="btn primary" onClick={() => onConnectorAction(asset, 'review')}>Still in use</button>
                <button className="btn" onClick={() => { onConnectorAction(asset, 'remove'); }}>I disconnected it</button>
              </div>
            )}
            <p className="meta">
              {c.detectedIn
                ? `This connector lives in your ${c.platform} account. To remove it, disconnect it in ${c.platform} settings; it disappears here on the next scan.`
                : `AI-BOM can’t see inside your ${c.platform} account. Disconnect it there, then remove it here.`}
            </p>
          </>
        )}

        {m && (
          <>
            <h3>Server</h3>
            <dl className="kv">
              <dt>Transport</dt>
              <dd>{m.transport === 'stdio' ? 'Local process (stdio)' : m.transport.toUpperCase()}</dd>
              {m.url && (<><dt>URL</dt><dd className="mono">{m.url}</dd></>)}
              {m.remoteUrl && (<><dt>Proxies to</dt><dd className="mono">{m.remoteUrl}</dd></>)}
              {m.command && (<><dt>Command</dt><dd className="mono">{[m.command, ...(m.args ?? [])].join(' ')}</dd></>)}
              {m.package && (
                <>
                  <dt>Package</dt>
                  <dd>
                    <span className="mono">{m.package.name}</span> <span className="tag">{m.package.ecosystem}</span>{' '}
                    {m.package.ecosystem !== 'local' && m.package.ecosystem !== 'binary' && (
                      <span className="tag">{m.package.pinned ? `pinned ${m.package.version ?? ''}` : m.package.version ? `floating: ${m.package.version}` : 'unpinned'}</span>
                    )}
                    {m.package.installedVersions && <span className="tag">cached {m.package.installedVersions.join(', ')}</span>}
                    {m.package.latestVersion && !m.package.pinned && <span className="tag">latest {m.package.latestVersion}</span>}
                  </dd>
                </>
              )}
              {m.env && (<><dt>Env vars</dt><dd className="mono">{Object.keys(m.env).join(', ')}</dd></>)}
              {m.headers && (<><dt>Headers</dt><dd className="mono">{Object.keys(m.headers).join(', ')}</dd></>)}
            </dl>
            {m.keychainEnv && m.keychainEnv.length > 0 && <p className="meta">Secrets loaded from the keychain at launch: <span className="mono">{m.keychainEnv.join(', ')}</span></p>}
            {m.tools && m.tools.length > 0 && (
              <>
                <h3>
                  Tools ({m.tools.length})
                  <span className="h3-note">{m.toolsFrom === 'source' ? 'read from its code' : m.toolsFrom === 'manifest+source' ? 'from its manifest, checked against its code' : 'from its manifest'}</span>
                </h3>
                <ul className="tool-list rich">
                  {m.tools.map((t) => {
                    const b = t.behavior;
                    const used = asset.usage?.tools?.[t.name];
                    return (
                      <li key={t.name} className={b?.verdict === 'mismatch' ? 'mismatch' : ''}>
                        <div className="tool-head">
                          <span className="mono">{t.name}</span>
                          {b?.verdict === 'mismatch' && <span className="pill bad">Does more than it says</span>}
                          {b?.verdict === 'matches' && <span className="pill ok">Matches its description</span>}
                          {used !== undefined && <span className="meta">used {used}×</span>}
                        </div>
                        {t.description && <div className="meta">{t.description}</div>}
                        {b && b.reasons.length > 0 && <ul className="reasons">{b.reasons.map((r) => <li key={r}>It {r}.</li>)}</ul>}
                        {b && (b.hosts.length > 0 || b.envVars.length > 0) && (
                          <div className="meta">
                            {b.hosts.length > 0 && <>Talks to <span className="mono">{b.hosts.join(', ')}</span>. </>}
                            {b.envVars.length > 0 && <>Reads <span className="mono">{b.envVars.join(', ')}</span>.</>}
                          </div>
                        )}
                        {b?.location && <div className="loc mono">{b.location}</div>}
                      </li>
                    );
                  })}
                </ul>
                {m.sourceDir && <p className="meta">Code read from <span className="mono">{m.sourceDir}</span>. The server was never started.</p>}
              </>
            )}
            <LiveInspect asset={asset} onInventory={onInventory} />
            <DepsSection asset={asset} />
          </>
        )}

        {asset.hook?.explanation && (
          <div className={`explain-card${asset.hook.explanation.sendsTo.length ? ' egress' : ''}`}>
            <p>{asset.hook.explanation.summary}</p>
            <dl className="kv">
              <dt>When</dt>
              <dd>{asset.hook.explanation.trigger}</dd>
              <dt>Gets</dt>
              <dd>{asset.hook.explanation.receives}</dd>
              {asset.hook.explanation.scripts.length > 0 && (<><dt>Runs</dt><dd className="mono">{asset.hook.explanation.scripts.map((x) => <div key={x}>{x}</div>)}</dd></>)}
              {asset.hook.explanation.sendsTo.length > 0 && (<><dt>Sends to</dt><dd className="mono">{asset.hook.explanation.sendsTo.join(', ')}</dd></>)}
            </dl>
          </div>
        )}

        {asset.hook && (
          <>
            <h3>Hook</h3>
            <dl className="kv">
              <dt>Event</dt>
              <dd>{asset.hook.event}</dd>
              {asset.hook.matcher && (<><dt>Matcher</dt><dd className="mono">{asset.hook.matcher}</dd></>)}
              <dt>Runs</dt>
              <dd><code className="evidence block">{asset.hook.command}</code></dd>
            </dl>
          </>
        )}

        {asset.telemetry && (
          <>
            <h3>Telemetry export</h3>
            <dl className="kv">
              <dt>Sends to</dt>
              <dd className="mono">{asset.telemetry.endpoint ?? 'Local only'}</dd>
              <dt>Includes</dt>
              <dd>
                {[asset.telemetry.logsPrompts && 'the text of your prompts', asset.telemetry.logsToolDetails && 'tool parameters (file paths, commands)', 'usage metrics (sessions, tokens, cost, tool names)'].filter(Boolean).join('; ')}
              </dd>
              {asset.telemetry.protocol && (<><dt>Protocol</dt><dd>{asset.telemetry.protocol}</dd></>)}
              <dt>Auth headers</dt>
              <dd>{asset.telemetry.headersSet ? 'Set (values hidden)' : 'None'}</dd>
              {asset.telemetry.managed && (<><dt>Set by</dt><dd>Your organization’s managed policy</dd></>)}
            </dl>
          </>
        )}

        {asset.model && (
          <>
            <h3>Model</h3>
            <dl className="kv">
              <dt>Runtime</dt>
              <dd>{asset.model.runtime}</dd>
              {asset.model.format && (<><dt>Format</dt><dd>{asset.model.format}{asset.model.pickle && ' (pickle: loading it can run code)'}</dd></>)}
              {asset.model.sizeBytes && (<><dt>Size</dt><dd>{formatBytes(asset.model.sizeBytes)}</dd></>)}
              {asset.path && (<><dt>Location</dt><dd className="mono">{asset.path}</dd></>)}
            </dl>
          </>
        )}

        {asset.apiKey && (
          <>
            <h3>API key</h3>
            <dl className="kv">
              <dt>Provider</dt>
              <dd>{asset.apiKey.provider}</dd>
              <dt>Variable</dt>
              <dd className="mono">{asset.apiKey.variable}</dd>
              <dt>Value</dt>
              <dd className="mono">{asset.apiKey.masked}</dd>
            </dl>
            {asset.occurrences.length > 1 && <p className="meta">The same key is written in {asset.occurrences.length} places.</p>}
          </>
        )}

        {asset.app && (
          <>
            <h3>App</h3>
            <dl className="kv">
              {asset.app.version && (<><dt>Version</dt><dd>{asset.app.version}</dd></>)}
              {asset.app.bundleId && (<><dt>Bundle ID</dt><dd className="mono">{asset.app.bundleId}</dd></>)}
              {asset.path && (<><dt>Location</dt><dd className="mono">{asset.path}</dd></>)}
            </dl>
          </>
        )}

        {asset.browserExtension && (
          <>
            <h3>Browser extension</h3>
            <dl className="kv">
              <dt>Browser</dt>
              <dd>{asset.browserExtension.browser}</dd>
              {asset.browserExtension.version && (<><dt>Version</dt><dd>{asset.browserExtension.version}</dd></>)}
              <dt>Site access</dt>
              <dd>{asset.browserExtension.allSites ? 'Every site you visit' : asset.browserExtension.hostPermissions.join(', ') || 'None'}</dd>
              {asset.browserExtension.permissions.length > 0 && (<><dt>Permissions</dt><dd className="mono">{asset.browserExtension.permissions.join(', ')}</dd></>)}
              <dt>ID</dt>
              <dd className="mono">{asset.browserExtension.extensionId}</dd>
            </dl>
          </>
        )}

        {asset.reach && (asset.reach.files.length || asset.reach.network.length || asset.reach.credentials.length || asset.reach.commands || asset.reach.accounts.length) ? (
          <>
            <h3>What it can reach</h3>
            <dl className="kv reach">
              {asset.reach.files.length > 0 && (<><dt>Files</dt><dd className="mono">{asset.reach.files.join(', ')}</dd></>)}
              {asset.reach.network.length > 0 && (<><dt>Network</dt><dd className="mono">{asset.reach.network.join(', ')}</dd></>)}
              {asset.reach.credentials.length > 0 && (<><dt>Credentials</dt><dd className="mono">{asset.reach.credentials.join(', ')}</dd></>)}
              {asset.reach.accounts.length > 0 && (<><dt>Accounts</dt><dd>{asset.reach.accounts.join(', ')}</dd></>)}
              {asset.reach.commands && (<><dt>Commands</dt><dd>Can run programs on this computer</dd></>)}
            </dl>
            {asset.reach.suggestions.length > 0 && (
              <ul className="suggestions">{asset.reach.suggestions.map((x) => <li key={x}>{x}</li>)}</ul>
            )}
          </>
        ) : null}

        {asset.trust && (
          <>
            <h3>
              Publisher & package
              {asset.trust.level !== 'unknown' && <span className={`pill ${TRUST_LEVEL[asset.trust.level][1]}`}>{TRUST_LEVEL[asset.trust.level][0]}</span>}
            </h3>
            {asset.trust.officialRegistry && (
              <p className="registry">
                <svg width="13" height="13" viewBox="0 0 14 14" aria-hidden><path d="M7 1l1.6 1.2 2-.1.6 1.9 1.6 1.2-.6 1.9.6 1.9-1.6 1.2-.6 1.9-2-.1L7 13l-1.6-1.2-2 .1-.6-1.9L1.2 8.8l.6-1.9-.6-1.9 1.6-1.2.6-1.9 2 .1z" fill="var(--status-good)" /><path d="M4.6 7.1l1.6 1.6 3.3-3.4" stroke="#fff" strokeWidth="1.4" fill="none" strokeLinecap="round" /></svg>
                Listed in the official MCP Registry as <span className="mono">{asset.trust.officialRegistry.name}</span>
              </p>
            )}
            <ul className="plain">{asset.trust.notes.filter((n) => !n.startsWith('Listed in the official')).map((n) => <li key={n}>{n}</li>)}</ul>
            {asset.trust.repository && <a href={asset.trust.repository} target="_blank" rel="noopener noreferrer">{asset.trust.repository.replace(/^https?:\/\//, '')}</a>}
          </>
        )}

        {s && (s.capabilities?.length || s.domains?.length) ? (
          <>
            <h3>What it can do</h3>
            {s.capabilities && s.capabilities.length > 0 ? (
              <div className="tags">
                {s.capabilities.map((cap) => (
                  <span key={cap} className={`tag cap${SENSITIVE_CAPS.has(cap) ? ' strong' : ''}`}>{CAPABILITY_LABEL[cap]}</span>
                ))}
              </div>
            ) : (
              <p className="meta">No executable behavior found — instructions only.</p>
            )}
            {s.domains && s.domains.length > 0 && (
              <p className="meta">Talks to: <span className="mono">{s.domains.join(', ')}</span></p>
            )}
          </>
        ) : null}

        {s && (s.description || s.allowedTools || s.version || (s.files && s.files.length > 1)) && (
          <>
            <h3>Details</h3>
            <dl className="kv">
              {s.description && (<><dt>Description</dt><dd>{s.description}</dd></>)}
              {s.version && (<><dt>Version</dt><dd>{s.version}</dd></>)}
              {s.author && (<><dt>Author</dt><dd>{s.author}</dd></>)}
              {s.allowedTools && (<><dt>Pre-approved tools</dt><dd className="mono">{s.allowedTools.join(', ')}</dd></>)}
              {asset.path && (<><dt>Location</dt><dd className="mono">{asset.path}</dd></>)}
              {s.files && s.files.length > 1 && (
                <><dt>Files</dt><dd className="mono">{s.files.slice(0, 30).map((f) => <div key={f}>{f}</div>)}{s.files.length > 30 && <div>… {s.files.length - 30} more</div>}</dd></>
              )}
            </dl>
          </>
        )}
        </section>

        <section data-sec="where" hidden={section !== 'where'} aria-label="Where it comes from">
        {!c && (
          <>
            <h3>Configured in ({asset.occurrences.length})</h3>
            {asset.occurrences.map((o, i) => (
              <div className="occ" key={i}>
                <div className="occ-head">
                  <strong>{clientName(inv, o.client)}</strong>
                  <span>· {SCOPE_LABEL[o.scope]}</span>
                  {o.project && <span>· {o.project.split('/').pop()}</span>}
                  {o.name !== asset.name && <span>· as “{o.name}”</span>}
                  {o.enabled === false && <span className="tag">off</span>}
                  <span className="spacer" />
                  {o.modifiedAt && <span className="meta" title={new Date(o.modifiedAt).toLocaleString()}>changed {relativeTime(o.modifiedAt)}</span>}
                </div>
                {o.note && <div className="occ-note">{o.note}</div>}
                <div className="path mono">{o.source}</div>
              </div>
            ))}
          </>
        )}

        {parents.length > 0 && (
          <>
            <h3>Installed by</h3>
            {parents.map((p) => (
              <div key={p.id}><button className="linklike" onClick={() => onSelect(p.id)}>{KIND_LABEL[p.kind].one}: {p.name}</button></div>
            ))}
          </>
        )}

        {children.length > 0 && (
          <>
            <h3>Bundles ({children.length})</h3>
            {children.map((ch) => (
              <div key={ch.id} className="child-row">
                <KindMark kind={ch.kind} />
                <button className="linklike" onClick={() => onSelect(ch.id)}>{ch.name}</button>
                <span className="meta">{KIND_LABEL[ch.kind].one}</span>
                {ch.risk && <Sev severity={ch.risk} />}
              </div>
            ))}
          </>
        )}
        </section>
      </div>
    </aside>
  );
}
