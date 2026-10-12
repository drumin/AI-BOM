import path from 'node:path';
import { promises as fs } from 'node:fs';
import type { Collector } from '../collector.js';
import type { Asset, Capability, DeclaredTool, ToolBehavior } from '../types.js';
import type { Findings } from '../checks/index.js';
import { CREDENTIAL_PATHS, SUSPICIOUS_HOSTS } from '../checks/capabilities.js';
import { normalizePypi } from '../vulns/installed.js';
import { compareVersions } from '../vulns/semver.js';
import { isDir, listDir } from '../util/fs.js';
import { calledNames, firstString, functionBodies, identifiers, langOf, matchBracket, pyBlock, stringConstants, stringExpr, type Lang } from './code.js';

/**
 * "Does the tool do what it says?"
 *
 * MCP servers are never started. Instead, the server's code is located on
 * disk (npx / uv / pipx caches, global installs, desktop-extension and plugin
 * folders, local scripts), each tool registration is found statically
 * (`server.tool(...)`, `registerTool`, `addTool`, `@mcp.tool()`, low-level
 * list/call handlers), and the handler plus the helper functions it calls
 * are read for network destinations, credential access, environment reads,
 * process execution and file writes. That behavior is then compared with the
 * tool's own name and description.
 */

export interface SourceFile {
  file: string;
  lang: Lang;
  text: string;
}

const MAX_FILES = 400;
const MAX_BYTES = 12 * 1024 * 1024;
const SKIP = new Set(['node_modules', '.git', '__pycache__', 'test', 'tests', '__tests__', 'examples', 'docs', '.venv', 'venv', 'site-packages']);

/** Source files of a server (JS/TS/Python), including build output such as dist/. */
export async function readSources(root: string): Promise<SourceFile[]> {
  const out: SourceFile[] = [];
  let bytes = 0;
  const visit = async (p: string, depth: number) => {
    if (out.length >= MAX_FILES || bytes >= MAX_BYTES) return;
    let st;
    try {
      st = await fs.stat(p);
    } catch {
      return;
    }
    if (st.isFile()) {
      const lang = langOf(p);
      if (!lang || /\.(min\.js|map)$/.test(p) || st.size > 2 * 1024 * 1024) return;
      try {
        const text = await fs.readFile(p, 'utf8');
        bytes += text.length;
        out.push({ file: p, lang, text });
      } catch {
        /* unreadable */
      }
      return;
    }
    if (!st.isDirectory() || depth > 6) return;
    for (const n of (await listDir(p)).sort()) {
      if (SKIP.has(n) || n.startsWith('.')) continue;
      await visit(path.join(p, n), depth + 1);
    }
  };
  await visit(root, 0);
  return out;
}

/* ---------------- Finding the code ---------------- */

async function npmCandidates(home: string, name: string): Promise<{ dir: string; version: string }[]> {
  const roots: string[] = [];
  const npx = path.join(home, '.npm', '_npx');
  for (const h of await listDir(npx)) roots.push(path.join(npx, h, 'node_modules'));
  roots.push('/usr/local/lib/node_modules', '/opt/homebrew/lib/node_modules', path.join(home, '.npm-global', 'lib', 'node_modules'));
  const nvm = path.join(home, '.nvm', 'versions', 'node');
  for (const v of await listDir(nvm)) roots.push(path.join(nvm, v, 'lib', 'node_modules'));
  const out: { dir: string; version: string }[] = [];
  for (const r of roots) {
    const dir = path.join(r, name);
    try {
      const pkg = JSON.parse(await fs.readFile(path.join(dir, 'package.json'), 'utf8'));
      out.push({ dir, version: String(pkg.version ?? '0') });
    } catch {
      /* not here */
    }
  }
  return out;
}

async function pypiCandidates(home: string, name: string): Promise<{ dir: string; version: string }[]> {
  const envs: string[] = [];
  const uv = path.join(home, '.cache', 'uv', 'archive-v0');
  for (const h of await listDir(uv)) envs.push(path.join(uv, h));
  for (const base of [path.join(home, '.local', 'share', 'uv', 'tools'), path.join(home, '.local', 'pipx', 'venvs'), path.join(home, '.local', 'share', 'pipx', 'venvs')]) {
    for (const t of await listDir(base)) envs.push(path.join(base, t));
  }
  const want = normalizePypi(name);
  const out: { dir: string; version: string }[] = [];
  for (const env of envs) {
    for (const lib of ['lib', 'Lib']) {
      for (const py of await listDir(path.join(env, lib))) {
        const sp = path.join(env, lib, py, 'site-packages');
        for (const d of await listDir(sp)) {
          const m = d.match(/^(.+?)-(\d[^-]*)\.dist-info$/);
          if (!m || normalizePypi(m[1]) !== want) continue;
          // top_level.txt / RECORD tell us which package folders belong to the distribution.
          let tops: string[] = [];
          try {
            tops = (await fs.readFile(path.join(sp, d, 'top_level.txt'), 'utf8')).split('\n').map((s) => s.trim()).filter(Boolean);
          } catch {
            try {
              const rec = await fs.readFile(path.join(sp, d, 'RECORD'), 'utf8');
              tops = [...new Set(rec.split('\n').map((l) => l.split('/')[0].split(',')[0]).filter((t) => t && !t.endsWith('.dist-info') && !t.includes('..')))];
            } catch {
              tops = [m[1].replace(/-/g, '_')];
            }
          }
          for (const t of tops) {
            const dir = path.join(sp, t);
            if ((await isDir(dir)) || (await isDir(path.dirname(dir)))) out.push({ dir: (await isDir(dir)) ? dir : `${dir}.py`, version: m[2] });
          }
        }
      }
    }
  }
  return out;
}

const INTERPRETERS = /^(node|nodejs|bun|deno|tsx|ts-node|python3?|python3\.\d+|uv|pipenv)$/;

/** Where the code an MCP server runs lives on disk, if we can tell. */
export async function locateSource(col: Collector, a: Asset): Promise<string | undefined> {
  const m = a.mcp;
  if (!m?.command) return undefined;
  const home = col.ctx.home;
  const pkg = m.package;
  if (pkg?.ecosystem === 'npm' || pkg?.ecosystem === 'pypi') {
    const found = pkg.ecosystem === 'npm' ? await npmCandidates(home, pkg.name) : await pypiCandidates(home, pkg.name);
    if (!found.length) return undefined;
    // Prefer the pinned version, else the newest copy on disk (what an unpinned call most likely reuses).
    const exact = pkg.pinned ? found.find((f) => f.version === pkg.version) : undefined;
    return (exact ?? found.sort((x, y) => compareVersions(y.version, x.version))[0]).dir;
  }
  const parent = a.occurrences.map((o) => (o.via ? col.assets.get(o.via) : undefined)).find((x): x is Asset => !!x);
  const vars = (s: string) =>
    s
      .replace(/\$\{?CLAUDE_PLUGIN_ROOT\}?/g, parent && parent.path ? parent.path : '\0')
      .replace(/\$\{?HOME\}?|^~(?=\/)/g, home);
  const bin = path.basename(m.command);
  const candidates = INTERPRETERS.test(bin) ? (m.args ?? []).filter((x) => !x.startsWith('-')) : [m.command];
  for (const c of candidates.slice(0, 3)) {
    const p = vars(c);
    if (p.includes('\0') || !path.isAbsolute(p)) continue;
    try {
      const st = await fs.stat(p);
      if (st.isFile() && langOf(p)) {
        // A script inside a package folder: read the folder so helpers are found too.
        const dir = path.dirname(p);
        const base = path.basename(dir);
        return ['dist', 'build', 'lib', 'src', 'server', 'bin'].includes(base) ? path.dirname(dir) : dir;
      }
      if (st.isDirectory()) return p;
    } catch {
      /* not a path */
    }
  }
  if (parent?.path && (parent.kind === 'extension' || parent.kind === 'plugin')) return parent.path;
  return undefined;
}

/* ---------------- Finding the tools ---------------- */

interface FoundTool {
  name: string;
  description?: string;
  body: string;
  file: string;
  line: number;
  lang: Lang;
}

const lineAt = (text: string, idx: number) => text.slice(0, idx).split('\n').length;

function jsTools(src: SourceFile): FoundTool[] {
  const out: FoundTool[] = [];
  const { text } = src;
  // server.tool("name", "desc", schema, handler) / server.registerTool("name", { description }, handler)
  for (const m of text.matchAll(/\.(tool|registerTool|addTool)\s*\(/g)) {
    const open = m.index! + m[0].length - 1;
    const close = matchBracket(text, open);
    if (close < 0) continue;
    const region = text.slice(open + 1, close - 1);
    let name = firstString(region);
    let description: string | undefined;
    if (name) {
      const afterName = region.replace(/^\s*(["'`])[\s\S]*?(?<!\\)\1\s*,/, '');
      description = stringExpr(afterName) ?? stringExpr(afterName.match(/\bdescription\s*:\s*([\s\S]{0,2000})/)?.[1] ?? '');
    } else {
      // addTool({ name: "x", description: "…", execute })
      name = region.match(/\bname\s*:\s*(["'`])([\w.:-]+)\1/)?.[2];
      description = stringExpr(region.match(/\bdescription\s*:\s*([\s\S]{0,2000})/)?.[1] ?? '');
    }
    if (!name || !/^[\w.:-]{1,80}$/.test(name)) continue;
    out.push({ name, description, body: region, file: src.file, line: lineAt(text, m.index!), lang: 'js' });
  }
  // Low-level servers: tool objects listed for tools/list, handled in a switch or if-chain.
  if (/ListToolsRequestSchema|tools\/list/.test(text)) {
    for (const m of text.matchAll(/\{\s*name\s*:\s*(["'`])([\w.:-]{1,80})\1\s*,\s*description\s*:\s*([\s\S]{0,3000})/g)) {
      const name = m[2];
      if (out.some((t) => t.name === name)) continue;
      const description = stringExpr(m[3]);
      const caseRe = new RegExp(`case\\s*(["'\`])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\1\\s*:`, 'g');
      const ifRe = new RegExp(`===?\\s*(["'\`])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\1\\s*\\)\\s*\\{`, 'g');
      let body = '';
      const c = caseRe.exec(text);
      if (c) {
        const rest = text.slice(c.index + c[0].length);
        const next = rest.search(/\n\s*(case\s+["'`]|default\s*:)/);
        body = rest.slice(0, next < 0 ? 4000 : next);
      } else {
        const i = ifRe.exec(text);
        if (i) {
          const open = i.index + i[0].length - 1;
          const close = matchBracket(text, open);
          if (close > 0) body = text.slice(open, close);
        }
      }
      out.push({ name, description, body, file: src.file, line: lineAt(text, m.index!), lang: 'js' });
    }
  }
  return out;
}

function pyTools(src: SourceFile): FoundTool[] {
  const out: FoundTool[] = [];
  const { text } = src;
  // @mcp.tool() / @server.tool(name=..., description=...) / @tool
  for (const m of text.matchAll(/^[ \t]*@(?:[\w.]+\.)?tool\b(\([^)]*\))?\s*\n(?:[ \t]*@[^\n]*\n)*[ \t]*(?:async\s+)?def\s+(\w+)\s*\(/gm)) {
    const args = m[1] ?? '';
    const name = args.match(/name\s*=\s*["']([\w.:-]+)["']/)?.[1] ?? m[2];
    const body = pyBlock(text, m.index! + m[0].lastIndexOf('def'));
    const descArg = args.match(/description\s*=\s*([\s\S]+)/)?.[1];
    const docstring = body.replace(/^[\s\S]*?\)\s*(->[^:]+)?:\s*\n/, '').match(/^\s*[rbuf]{0,2}("""|''')([\s\S]*?)\1/)?.[2]?.trim();
    out.push({ name, description: (descArg && stringExpr(descArg)) ?? docstring, body, file: src.file, line: lineAt(text, m.index!), lang: 'py' });
  }
  // Low-level: types.Tool(name="x", description="…") + `if name == "x":` in call_tool
  for (const m of text.matchAll(/\bTool\s*\(\s*name\s*=\s*["']([\w.:-]+)["']\s*,\s*description\s*=\s*([\s\S]{0,3000})/g)) {
    const name = m[1];
    if (out.some((t) => t.name === name)) continue;
    const ifm = new RegExp(`(?:if|elif)\\s+\\w+\\s*==\\s*["']${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']\\s*:`).exec(text);
    out.push({ name, description: stringExpr(m[2]), body: ifm ? pyBlock(text, ifm.index) : '', file: src.file, line: lineAt(text, m.index!), lang: 'py' });
  }
  return out;
}

/* ---------------- Reading behavior ---------------- */

const NET_JS = /\bfetch\s*\(|\baxios\b|\bgot\s*\(|\bhttps?\.(request|get)\s*\(|\bundici\b|\bXMLHttpRequest\b|\bWebSocket\s*\(|\bnet\.connect\(|\bky\s*\(|\bsuperagent\b/;
const NET_PY = /\brequests\.(get|post|put|patch|delete|request|Session)\b|\bhttpx\.|\baiohttp\b|urllib\.request|urlopen\(|http\.client|\bsocket\.(socket|create_connection)|\bsmtplib\b/;
const SUBPROC = /\bchild_process\b|\bexecSync\s*\(|\bexec\s*\(|\bexecFile(Sync)?\s*\(|\bspawn(Sync)?\s*\(|\bsubprocess\.|\bos\.(system|popen|exec\w*)\s*\(|\bBun\.spawn|\bDeno\.Command/;
const FILE_WRITE = /\bwriteFile(Sync)?\s*\(|\bappendFile(Sync)?\s*\(|\bunlink(Sync)?\s*\(|\brm(Sync)?\s*\(|\brmdir(Sync)?\s*\(|\brename(Sync)?\s*\(|createWriteStream\(|\bopen\([^)\n]*["'][wax]\+?b?["']|shutil\.(rmtree|move|copy)|\bos\.(remove|unlink|rename|rmdir)\(|\.write_(text|bytes)\(/;
const CODE_CRED = [/["'`]\.ssh["'`/]|\bid_(rsa|ed25519|ecdsa)\b/, /["'`]\.aws["'`/]|\.aws\/credentials/, /["'`]\.kube["'`/]/, /["'`]\.gnupg["'`/]/, /\bLogin Data\b|\bCookies\b.*(Chrome|Brave|Edge)|Local State/, /find-generic-password|find-internet-password|keytar\.getPassword|keyring\.get_password/, /["'`]\.npmrc["'`]|["'`]\.netrc["'`]|["'`]\.pypirc["'`]/, /["'`]\.docker["'`/]config|\.config\/gh\b/];
const CRED_LABEL = ['SSH keys', 'AWS credentials', 'Kubernetes config', 'GPG keys', 'browser passwords/cookies', 'the keychain', 'package-registry tokens', 'Docker/GitHub CLI credentials'];
const ENV_ALL_JS = /process\.env(?![\s]*[.[?])|\{\s*\.\.\.process\.env\s*\}|Object\.(entries|keys|values)\(\s*process\.env\s*\)/;
const ENV_ALL_PY = /os\.environ\.copy\(\)|dict\(\s*os\.environ\s*\)|os\.environ(?!\s*[.[]|\.get)|json\.dumps\(\s*os\.environ/;
const SECRET_ENV = /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)/i;
const COMMON_INFRA = /(^|\.)(localhost|githubusercontent\.com|github\.com|googleapis\.com|gstatic\.com|amazonaws\.com|cloudflare\.com|jsdelivr\.net|unpkg\.com|npmjs\.(org|com)|pypi\.org|schema\.org|w3\.org|json-schema\.org|modelcontextprotocol\.io|example\.(com|org)|mozilla\.org|python\.org|nodejs\.org|sentry\.io)$/;
const RAW_IP = /^\d{1,3}(\.\d{1,3}){3}$/;
const PRIVATE_IP = /^(10|127|192\.168|172\.(1[6-9]|2\d|3[01]))\./;

interface Behavior {
  capabilities: Set<Capability>;
  hosts: Set<string>;
  envVars: Set<string>;
  envAll: boolean;
  creds: Set<string>;
}

function readBehavior(code: string, lang: Lang, consts: Map<string, string>): Behavior {
  const b: Behavior = { capabilities: new Set(), hosts: new Set(), envVars: new Set(), envAll: false, creds: new Set() };
  if ((lang === 'js' ? NET_JS : NET_PY).test(code)) b.capabilities.add('network');
  if (SUBPROC.test(code)) b.capabilities.add('subprocess');
  if (FILE_WRITE.test(code)) b.capabilities.add('file-write');
  // URLs written in the handler, or in constants it references.
  const texts = [code];
  for (const id of identifiers(code)) {
    const v = consts.get(id);
    if (v) texts.push(v);
  }
  for (const t of texts) {
    for (const m of t.matchAll(/(?:https?|wss?):\/\/([A-Za-z0-9.-]+\.[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?/g)) b.hosts.add(m[1].toLowerCase());
  }
  if (b.hosts.size && !b.capabilities.has('network') && /\b(url|endpoint|base)/i.test(code)) b.capabilities.add('network');
  for (const m of code.matchAll(lang === 'js' ? /process\.env(?:\.(\w+)|\[\s*["'`](\w+)["'`]\s*\])/g : /os\.(?:environ(?:\.get)?\s*[([]\s*|getenv\s*\(\s*)["'](\w+)["']/g)) {
    b.envVars.add((m[1] ?? m[2])!);
  }
  if ((lang === 'js' ? ENV_ALL_JS : ENV_ALL_PY).test(code)) b.envAll = true;
  if (b.envVars.size || b.envAll) b.capabilities.add('reads-env');
  CODE_CRED.forEach((re, i) => re.test(code) && b.creds.add(CRED_LABEL[i]));
  for (const re of CREDENTIAL_PATHS) if (re.test(code)) b.creds.add(re.source.includes('ssh') ? 'SSH keys' : re.source.includes('aws') ? 'AWS credentials' : 'credential files');
  if (b.creds.size) b.capabilities.add('credential-access');
  return b;
}

/** Handler plus the local helpers it calls (two levels), so exfiltration hidden in a helper is seen. */
function expandBody(t: FoundTool, fns: Map<string, string>): string {
  let code = t.body;
  const seen = new Set<string>();
  let frontier = calledNames(t.body);
  for (let depth = 0; depth < 2; depth++) {
    const next = new Set<string>();
    for (const n of frontier) {
      if (seen.has(n) || n === t.name) continue;
      seen.add(n);
      const body = fns.get(n);
      if (!body || code.length > 80_000) continue;
      code += '\n' + body;
      for (const c of calledNames(body)) next.add(c);
    }
    frontier = next;
  }
  return code;
}

/* ---------------- Comparing with the description ---------------- */

const words = (s: string) =>
  s
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((w) => w.length >= 3);

const STOP = new Set(['www', 'api', 'com', 'org', 'net', 'io', 'dev', 'app', 'the', 'and', 'for', 'mcp', 'server', 'tool', 'tools', 'get', 'set', 'http', 'https', 'data', 'cloud', 'service', 'services', 'v1', 'v2']);
const NETWORKY = /fetch|search|web|url|http|api|download|upload|online|internet|weather|forecast|news|price|stock|github|gitlab|slack|jira|linear|notion|mail|send|post|publish|query|lookup|remote|translate|browse|scrape|crawl|request|sync|issue|repo|channel|message|calendar|drive|database|sql|index|embed|model|llm|chat|tweet|webhook|notify|deploy/;
const LOCALY = /calculat|format|convert|parse|count|sort|math|time|date|uuid|random|hash|encode|decode|lint|validate|diff|echo|add|sum|compute|regex/;
const EXECY = /run|exec|command|shell|terminal|script|build|test|git|install|process|launch|start|open|compile|docker|kubectl|npm|pip|python|node|bash|lint|format|browser|playwright|puppeteer|screenshot|convert|render|ffmpeg/;
const WRITEY = /write|save|creat|delet|remov|updat|edit|move|renam|modif|upload|download|cache|store|insert|append|patch|put|post|set|make|generat|export|install|commit|push|screenshot|record/;
const READONLY = /^(get|read|list|search|fetch|find|show|lookup|query|describe|check|count|view|inspect|retrieve)/;
const CREDY = /ssh|key|credential|secret|aws|cloud|kube|docker|git|auth|keychain|cert|config|password|login|cookie|browser|token|vault|profile|account/;

function hostRelated(host: string, vocab: Set<string>): boolean {
  const labels = host.split(/[.-]/).filter((l) => l.length >= 3 && !STOP.has(l));
  return labels.some((l) => vocab.has(l) || [...vocab].some((w) => w.length >= 4 && (l.includes(w) || w.includes(l))));
}

function compare(tool: FoundTool, b: Behavior, serverVocab: Set<string>, configured: Set<string>): { reasons: string[]; severity: 'high' | 'medium' | undefined } {
  const said = `${tool.name.replace(/[_-]/g, ' ')} ${tool.description ?? ''}`.toLowerCase();
  const reasons: string[] = [];
  let high = false;
  const net = b.capabilities.has('network');
  if (b.creds.size && !CREDY.test(said)) {
    reasons.push(`reads ${[...b.creds].join(', ')}, which the description never mentions`);
    high = true;
  }
  if (b.envAll && net) {
    reasons.push('reads your entire environment (all variables, including secrets) and makes network requests');
    high = true;
  }
  const secretEnv = [...b.envVars].filter((v) => SECRET_ENV.test(v) && !configured.has(v) && !said.includes(v.toLowerCase().split('_')[0]));
  if (secretEnv.length && net) reasons.push(`reads ${secretEnv.slice(0, 3).join(', ')}, which is not configured for this server`);
  const bad = [...b.hosts].filter((h) => SUSPICIOUS_HOSTS.test(h) || (RAW_IP.test(h) && !PRIVATE_IP.test(h)));
  if (bad.length) {
    reasons.push(`sends requests to ${bad.join(', ')}`);
    high = true;
  }
  const named = [...b.hosts].filter((h) => !COMMON_INFRA.test(h) && !bad.includes(h));
  // Relatedness is judged against the server's own name, not the tool description (which an attacker writes).
  const related = named.filter((h) => hostRelated(h, serverVocab));
  const unrelated = named.filter((h) => !hostRelated(h, serverVocab));
  if (related.length && unrelated.length) reasons.push(`also sends requests to ${unrelated.join(', ')}, unrelated to what it describes (${related.join(', ')})`);
  else if (unrelated.length && (!NETWORKY.test(said) || (LOCALY.test(said) && !NETWORKY.test(said)))) reasons.push(`makes network requests to ${unrelated.join(', ')}, though it describes local work`);
  if (b.capabilities.has('subprocess') && !EXECY.test(said)) reasons.push('starts other programs, which the description never mentions');
  if (b.capabilities.has('file-write') && READONLY.test(tool.name.toLowerCase()) && !WRITEY.test(said)) reasons.push('writes or deletes files although it reads as a read-only tool');
  return { reasons, severity: reasons.length ? (high ? 'high' : 'medium') : undefined };
}

/* ---------------- Entry point ---------------- */

export async function analyzeTools(col: Collector, f: Findings, tilde: (p: string) => string): Promise<void> {
  const cache = new Map<string, { tools: FoundTool[]; fns: Map<string, string>; consts: Map<string, string>; langs: Map<string, Lang> }>();
  for (const a of col.assets.values()) {
    if (a.kind !== 'mcp-server' || !a.mcp || a.mcp.url) continue;
    // A preset sourceDir (a downloaded package being vetted) wins over looking on disk.
    const dir = a.mcp.sourceDir ?? (await locateSource(col, a));
    if (!dir) continue;
    let parsed = cache.get(dir);
    if (!parsed) {
      const srcs = await readSources(dir);
      const tools: FoundTool[] = [];
      const fns = new Map<string, string>();
      const consts = new Map<string, string>();
      for (const s of srcs) {
        tools.push(...(s.lang === 'js' ? jsTools(s) : pyTools(s)));
        for (const [k, v] of functionBodies(s.text, s.lang)) if (!fns.has(k)) fns.set(k, v);
        for (const [k, v] of stringConstants(s.text)) if (!consts.has(k)) consts.set(k, v);
      }
      // Compiled output often duplicates the source (src/ + dist/); keep the first of each name.
      const unique = [...new Map(tools.map((t) => [t.name, t])).values()];
      parsed = { tools: unique.slice(0, 200), fns, consts, langs: new Map() };
      cache.set(dir, parsed);
    }
    a.mcp.sourceDir = dir;
    if (!parsed.tools.length) continue;

    const vocab = new Set([...words(a.name), ...words(a.mcp.package?.name ?? '')].filter((w) => !STOP.has(w)));
    const configured = new Set([...Object.keys(a.mcp.env ?? {}), ...(a.mcp.keychainEnv ?? [])]);
    const manifest = new Map((a.mcp.tools ?? []).map((t) => [t.name, t]));
    const merged: DeclaredTool[] = [];
    for (const t of parsed.tools) {
      const code = expandBody(t, parsed.fns);
      const b = readBehavior(code, t.lang, parsed.consts);
      const declared = manifest.get(t.name);
      const description = declared?.description ?? t.description;
      const { reasons, severity } = compare({ ...t, description }, b, vocab, configured);
      const behavior: ToolBehavior = {
        location: `${tilde(t.file)}:${t.line}`,
        capabilities: [...b.capabilities].sort(),
        hosts: [...b.hosts].sort().slice(0, 20),
        envVars: [...b.envVars].sort().slice(0, 20),
        credentialPaths: [...b.creds],
        verdict: !t.body ? 'unknown' : reasons.length ? 'mismatch' : 'matches',
        reasons,
      };
      if (b.envAll) behavior.envVars.unshift('(all variables)');
      merged.push({ name: t.name, description, behavior });
      if (severity) {
        f.add('TOOL-BEHAVIOR-MISMATCH', severity, {
          asset: a,
          location: `${t.file}:${t.line}`,
          title: `${a.name} → ${t.name} does more than it says`,
          evidence: `${t.name}: "${(description ?? '').slice(0, 80)}" — ${reasons.join('; ')}`,
          detail: `The tool ${reasons.join('; ')}.`,
        });
      }
    }
    // Keep manifest-only tools, and flag code that registers tools the manifest hides.
    for (const [name, t] of manifest) if (!merged.some((m) => m.name === name)) merged.push(t);
    if (manifest.size) {
      const hidden = parsed.tools.filter((t) => !manifest.has(t.name)).map((t) => t.name);
      if (hidden.length) f.add('TOOL-UNDECLARED', 'medium', { asset: a, location: a.occurrences[0]?.source, evidence: hidden.slice(0, 10).join(', ') });
    }
    a.mcp.tools = merged;
    a.mcp.toolsFrom = manifest.size ? 'manifest+source' : 'source';
  }
}
