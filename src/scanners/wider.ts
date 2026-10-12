import path from 'node:path';
import { promises as fs } from 'node:fs';
import type { Collector } from '../collector.js';
import type { Scanner } from './index.js';
import { exists, isDir, listDir, readSmallText } from '../util/fs.js';
import { shortHash } from '../util/hash.js';
import { classifySecret, maskValue } from '../util/secrets.js';
import { readShellExports, parseExports } from './shell.js';

/**
 * The wider AI footprint beyond agent config: local model weights, AI
 * provider API keys, AI desktop apps and AI browser extensions. Model files
 * are only stat()ed, never read; key values are masked and only a short hash
 * is kept so the same key found in several places is shown once.
 */

/* ---------------- Local models ---------------- */

const PICKLE = /\.(bin|pt|pth|pkl|pickle|ckpt)$/i;
const WEIGHTS = /\.(gguf|ggml|safetensors|bin|pt|pth|pkl|ckpt|onnx|mlmodel|npz)$/i;

async function sizeOf(p: string): Promise<number> {
  try {
    return (await fs.stat(p)).size;
  } catch {
    return 0;
  }
}

async function weightFiles(dir: string, depth = 3): Promise<string[]> {
  const out: string[] = [];
  const visit = async (d: string, n: number) => {
    for (const name of await listDir(d)) {
      const p = path.join(d, name);
      if (await isDir(p)) {
        if (n < depth) await visit(p, n + 1);
      } else if (WEIGHTS.test(name)) out.push(p);
      if (out.length > 200) return;
    }
  };
  await visit(dir, 0);
  return out;
}

function addModel(col: Collector, client: Parameters<Collector['client']>[0], runtime: string, name: string, dir: string, files: string[], size: number) {
  const exts = new Set(files.map((f) => path.extname(f).toLowerCase().slice(1)));
  const safe = exts.has('safetensors') || exts.has('gguf');
  const pickle = files.some((f) => PICKLE.test(f)) && !safe;
  col.client(client, runtime, dir);
  col.add({
    kind: 'model',
    name,
    key: `model:${runtime}:${name}`,
    path: dir,
    model: { runtime, format: [...exts].sort().join(', ') || undefined, sizeBytes: size || undefined, pickle, files: files.length || undefined },
    occurrence: { client, scope: 'user', source: dir, name },
  });
}

async function ollama(col: Collector) {
  const root = path.join(col.ctx.home, '.ollama', 'models', 'manifests');
  for (const registry of await listDir(root)) {
    for (const ns of await listDir(path.join(root, registry))) {
      for (const model of await listDir(path.join(root, registry, ns))) {
        for (const tag of await listDir(path.join(root, registry, ns, model))) {
          const file = path.join(root, registry, ns, model, tag);
          let size = 0;
          try {
            const m = JSON.parse((await readSmallText(file)) ?? '{}');
            for (const l of m.layers ?? []) size += typeof l.size === 'number' ? l.size : 0;
          } catch {
            continue;
          }
          const name = `${ns === 'library' ? '' : `${ns}/`}${model}:${tag}`;
          col.client('ollama', 'Ollama', root);
          col.add({
            kind: 'model',
            name,
            key: `model:ollama:${registry}/${name}`,
            path: file,
            model: { runtime: 'Ollama', format: 'gguf', sizeBytes: size || undefined },
            occurrence: { client: 'ollama', scope: 'user', source: file, name, note: registry === 'registry.ollama.ai' ? undefined : `From ${registry}` },
          });
        }
      }
    }
  }
}

async function lmStudio(col: Collector) {
  for (const root of [path.join(col.ctx.home, '.lmstudio', 'models'), path.join(col.ctx.home, '.cache', 'lm-studio', 'models')]) {
    for (const pub of await listDir(root)) {
      for (const repo of await listDir(path.join(root, pub))) {
        const dir = path.join(root, pub, repo);
        if (!(await isDir(dir))) continue;
        const files = await weightFiles(dir, 2);
        if (!files.length) continue;
        let size = 0;
        for (const f of files) size += await sizeOf(f);
        addModel(col, 'lm-studio', 'LM Studio', `${pub}/${repo}`, dir, files, size);
      }
    }
  }
}

async function huggingFace(col: Collector) {
  const root = path.join(col.ctx.home, '.cache', 'huggingface', 'hub');
  for (const d of await listDir(root)) {
    const m = d.match(/^models--(.+)$/);
    if (!m) continue;
    const snaps = path.join(root, d, 'snapshots');
    const revs = await listDir(snaps);
    const files: string[] = [];
    for (const r of revs) files.push(...(await weightFiles(path.join(snaps, r), 3)));
    let size = 0;
    for (const f of files) size += await sizeOf(f);
    addModel(col, 'huggingface', 'Hugging Face cache', m[1].replace(/--/g, '/'), path.join(root, d), files, size);
  }
}

async function fileModels(col: Collector, client: 'gpt4all' | 'jan' | 'llama-cpp', runtime: string, dirs: string[]) {
  for (const dir of dirs) {
    for (const name of await listDir(dir)) {
      const p = path.join(dir, name);
      if (await isDir(p)) {
        const files = await weightFiles(p, 2);
        if (!files.length) continue;
        let size = 0;
        for (const f of files) size += await sizeOf(f);
        addModel(col, client, runtime, name, p, files, size);
      } else if (WEIGHTS.test(name)) {
        addModel(col, client, runtime, name.replace(/\.[^.]+$/, ''), p, [p], await sizeOf(p));
      }
    }
  }
}

/**
 * Model servers that have no config file to read, found by the folder or program they leave behind. Each
 * shows up as an app, because a running model server is something other programs on the machine can talk to.
 */
const RUNTIMES: { id: 'llama-cpp' | 'vllm' | 'localai' | 'open-webui'; name: string; marks: (col: Collector) => string[] }[] = [
  {
    id: 'llama-cpp',
    name: 'llama.cpp',
    marks: (c) => [path.join(c.ctx.home, '.cache', 'llama.cpp'), path.join(c.ctx.home, 'Library', 'Caches', 'llama.cpp'), path.join(c.ctx.localAppData, 'llama.cpp'), ...['opt/homebrew/bin', 'usr/local/bin'].map((d) => path.join(c.ctx.systemRoot, d, 'llama-server'))],
  },
  {
    id: 'vllm',
    name: 'vLLM',
    marks: (c) => [path.join(c.ctx.home, '.cache', 'vllm'), path.join(c.ctx.home, '.local', 'pipx', 'venvs', 'vllm'), path.join(c.ctx.home, '.local', 'share', 'uv', 'tools', 'vllm')],
  },
  {
    id: 'localai',
    name: 'LocalAI',
    marks: (c) => [path.join(c.ctx.home, '.localai'), path.join(c.ctx.home, 'localai'), path.join(c.ctx.home, '.local', 'bin', 'local-ai'), ...['opt/homebrew/bin', 'usr/local/bin'].map((d) => path.join(c.ctx.systemRoot, d, 'local-ai'))],
  },
  {
    id: 'open-webui',
    name: 'Open WebUI',
    marks: (c) => [path.join(c.ctx.home, '.open-webui'), path.join(c.ctx.home, '.local', 'pipx', 'venvs', 'open-webui'), path.join(c.ctx.home, '.local', 'share', 'uv', 'tools', 'open-webui'), path.join(c.ctx.appSupport, 'Open WebUI')],
  },
];

async function modelRuntimes(col: Collector) {
  for (const r of RUNTIMES) {
    let found: string | undefined;
    for (const m of r.marks(col)) {
      if (await exists(m)) {
        found = m;
        break;
      }
    }
    if (!found) continue;
    col.client(r.id, r.name, found);
    col.add({ kind: 'app', name: r.name, key: `app:${r.id}`, path: found, app: {}, occurrence: { client: r.id, scope: 'user', source: found, name: r.name, note: 'Local model server, found by the folder or program it leaves behind' } });
  }
  // Models llama.cpp downloaded itself (-hf): GGUF files in its cache.
  await fileModels(col, 'llama-cpp', 'llama.cpp', [path.join(col.ctx.home, '.cache', 'llama.cpp'), path.join(col.ctx.home, 'Library', 'Caches', 'llama.cpp'), path.join(col.ctx.localAppData, 'llama.cpp')]);
}

export const localModels: Scanner = {
  id: 'ollama',
  async scanUser(col) {
    await ollama(col);
    await lmStudio(col);
    await huggingFace(col);
    await modelRuntimes(col);
    const as = col.ctx.appSupport;
    await fileModels(col, 'gpt4all', 'GPT4All', [...new Set([path.join(as, 'nomic.ai', 'GPT4All'), path.join(col.ctx.localAppData, 'nomic.ai', 'GPT4All'), path.join(col.ctx.home, '.local', 'share', 'nomic.ai', 'GPT4All')])]);
    await fileModels(col, 'jan', 'Jan', [path.join(col.ctx.home, 'jan', 'models'), path.join(as, 'Jan', 'data', 'models')]);
  },
};

/* ---------------- API keys ---------------- */

export const AI_KEY_VARS: Record<string, string> = {
  OPENAI_API_KEY: 'OpenAI',
  ANTHROPIC_API_KEY: 'Anthropic',
  CLAUDE_API_KEY: 'Anthropic',
  GEMINI_API_KEY: 'Google Gemini',
  GOOGLE_API_KEY: 'Google',
  GOOGLE_GENERATIVE_AI_API_KEY: 'Google Gemini',
  GROQ_API_KEY: 'Groq',
  MISTRAL_API_KEY: 'Mistral',
  COHERE_API_KEY: 'Cohere',
  CO_API_KEY: 'Cohere',
  HF_TOKEN: 'Hugging Face',
  HUGGING_FACE_HUB_TOKEN: 'Hugging Face',
  HUGGINGFACEHUB_API_TOKEN: 'Hugging Face',
  REPLICATE_API_TOKEN: 'Replicate',
  TOGETHER_API_KEY: 'Together AI',
  PERPLEXITY_API_KEY: 'Perplexity',
  PPLX_API_KEY: 'Perplexity',
  DEEPSEEK_API_KEY: 'DeepSeek',
  XAI_API_KEY: 'xAI',
  OPENROUTER_API_KEY: 'OpenRouter',
  FIREWORKS_API_KEY: 'Fireworks',
  AZURE_OPENAI_API_KEY: 'Azure OpenAI',
  VOYAGE_API_KEY: 'Voyage AI',
  PINECONE_API_KEY: 'Pinecone',
  LANGSMITH_API_KEY: 'LangSmith',
  LANGCHAIN_API_KEY: 'LangSmith',
  ELEVENLABS_API_KEY: 'ElevenLabs',
  TAVILY_API_KEY: 'Tavily',
  EXA_API_KEY: 'Exa',
  FIRECRAWL_API_KEY: 'Firecrawl',
  CEREBRAS_API_KEY: 'Cerebras',
};

export function addKey(col: Collector, name: string, value: string, file: string, line: number, project?: string, gitignored?: boolean) {
  const provider = AI_KEY_VARS[name];
  col.client('shell', 'Shell profiles & .env files', file);
  return col.add({
    kind: 'api-key',
    name: `${provider} key`,
    key: `api-key:${shortHash(value)}`,
    apiKey: { provider, variable: name, masked: maskValue(value), gitignored },
    path: file,
    occurrence: {
      client: 'shell',
      scope: project ? 'project' : 'user',
      source: file,
      name: `${name} (line ${line})`,
      project,
      note: gitignored === false ? NOT_IGNORED : gitignored ? 'Ignored by git.' : undefined,
    },
  });
}

/** Tiny .gitignore matcher: basename patterns and root-anchored names, with negation. */
export function gitignores(gitignore: string, file: string): boolean {
  let ignored = false;
  for (const raw of gitignore.split('\n')) {
    let p = raw.trim();
    if (!p || p.startsWith('#')) continue;
    const neg = p.startsWith('!');
    if (neg) p = p.slice(1);
    p = p.replace(/^\//, '').replace(/\/$/, '');
    if (p.includes('/') && !p.startsWith('**/')) continue;
    p = p.replace(/^\*\*\//, '');
    const re = new RegExp(`^${p.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`);
    if (re.test(file)) ignored = !neg;
  }
  return ignored;
}

export const NOT_IGNORED = 'Not covered by .gitignore: git would commit this file.';

const ENV_FILES = ['.env', '.env.local', '.env.development', '.env.development.local', '.env.production', '.env.test'];

export const apiKeys: Scanner = {
  id: 'shell',
  async scanUser(col) {
    for (const e of await readShellExports(col.ctx.home)) {
      if (!AI_KEY_VARS[e.name] || e.computed || !classifySecret(e.name, e.value)) continue;
      addKey(col, e.name, e.value, e.file, e.line);
    }
  },
  async scanProject(col, dir) {
    if (path.resolve(dir) === path.resolve(col.ctx.home)) return;
    const git = await exists(path.join(dir, '.git'));
    const ignore = git ? ((await readSmallText(path.join(dir, '.gitignore'))) ?? '') : '';
    for (const name of ENV_FILES) {
      const file = path.join(dir, name);
      const text = await readSmallText(file);
      if (!text) continue;
      for (const e of parseExports(file, text)) {
        if (!AI_KEY_VARS[e.name] || e.computed || !classifySecret(e.name, e.value)) continue;
        addKey(col, e.name, e.value, file, e.line, dir, git ? gitignores(ignore, name) : undefined);
      }
    }
  },
};

/* ---------------- AI apps ---------------- */

const AI_APPS = [
  'ChatGPT', 'ChatGPT Atlas', 'Claude', 'Cursor', 'Windsurf', 'Perplexity', 'Comet', 'Dia', 'Ollama', 'LM Studio', 'Jan', 'GPT4All',
  'Msty', 'Copilot', 'Microsoft Copilot', 'Gemini', 'Kiro', 'Trae', 'Zed', 'Warp', 'Poe', 'DiffusionBee', 'Draw Things',
  'Antigravity', 'Superwhisper', 'MacWhisper', 'Granola', 'Raycast', 'Codex', 'Goose', 'Cline', 'Void', 'PearAI', 'AnythingLLM', 'Enchanted',
];

/** Windows per-user installs: %LOCALAPPDATA%\Programs\<folder> (or a vendor folder). */
const WIN_APPS: [string, string[]][] = [
  ['Claude', ['AnthropicClaude', 'Programs/Claude']], ['ChatGPT', ['Programs/ChatGPT']], ['Cursor', ['Programs/cursor']], ['Windsurf', ['Programs/Windsurf']],
  ['Ollama', ['Programs/Ollama']], ['LM Studio', ['Programs/LM Studio', 'Programs/lm-studio']], ['Zed', ['Programs/Zed']], ['Jan', ['Programs/jan', 'Programs/Jan']],
  ['GPT4All', ['Programs/GPT4All']], ['Perplexity', ['Programs/Perplexity']], ['Kiro', ['Programs/Kiro']], ['Msty', ['Programs/Msty']], ['Trae', ['Programs/Trae']], ['Antigravity', ['Programs/Antigravity']],
];

export const aiApps: Scanner = {
  id: 'applications',
  async scanUser(col) {
    if (col.ctx.platform === 'win32') {
      for (const [app, dirs] of WIN_APPS) {
        for (const d of dirs) {
          const dir = path.join(col.ctx.localAppData, ...d.split('/'));
          if (!(await isDir(dir))) continue;
          col.client('applications', 'Applications', path.join(col.ctx.localAppData, 'Programs'));
          col.add({ kind: 'app', name: app, key: `app:${app}`, path: dir, app: {}, occurrence: { client: 'applications', scope: 'user', source: dir, name: app } });
          break;
        }
      }
      return;
    }
    if (col.ctx.platform !== 'darwin') return;
    for (const root of [path.join(col.ctx.systemRoot, 'Applications'), path.join(col.ctx.home, 'Applications')]) {
      const names = new Set(await listDir(root));
      for (const app of AI_APPS) {
        const bundle = path.join(root, `${app}.app`);
        if (!names.has(`${app}.app`)) continue;
        const plist = (await readSmallText(path.join(bundle, 'Contents', 'Info.plist'))) ?? '';
        const val = (k: string) => (plist.startsWith('bplist') ? undefined : plist.match(new RegExp(`<key>${k}</key>\\s*<string>([^<]{1,100})</string>`))?.[1]);
        col.client('applications', 'Applications', root);
        col.add({
          kind: 'app',
          name: app,
          key: `app:${val('CFBundleIdentifier') ?? app}`,
          path: bundle,
          app: { version: val('CFBundleShortVersionString'), bundleId: val('CFBundleIdentifier') },
          occurrence: { client: 'applications', scope: 'user', source: bundle, name: app },
        });
      }
    }
  },
};

/* ---------------- Browser extensions ---------------- */

const AI_EXT = /\b(AI|GPT|ChatGPT|Claude|Copilot|Gemini|Perplexity|LLM|Monica|Sider|Merlin|MaxAI|HARPA|Grammarly|Wiseone|Glasp|Liner|Bard|Anthropic|OpenAI|chatbot|Poe|DeepSeek|Grok|Comet)\b/i;
const ALL_SITES = new Set(['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*']);

const BROWSERS: { id: 'chrome' | 'brave' | 'edge' | 'arc'; name: string; mac: string; linux?: string; win?: string }[] = [
  { id: 'chrome', name: 'Google Chrome', mac: 'Google/Chrome', linux: 'google-chrome', win: 'Google/Chrome/User Data' },
  { id: 'brave', name: 'Brave', mac: 'BraveSoftware/Brave-Browser', linux: 'BraveSoftware/Brave-Browser', win: 'BraveSoftware/Brave-Browser/User Data' },
  { id: 'edge', name: 'Microsoft Edge', mac: 'Microsoft Edge', linux: 'microsoft-edge', win: 'Microsoft/Edge/User Data' },
  { id: 'arc', name: 'Arc', mac: 'Arc/User Data', win: 'Packages/TheBrowserCompany.Arc_ttt1ap7aakyb4/LocalCache/Local/Arc/User Data' },
];

async function localized(dir: string, manifest: Record<string, unknown>, v: unknown): Promise<string | undefined> {
  if (typeof v !== 'string') return undefined;
  const m = v.match(/^__MSG_(\w+)__$/);
  if (!m) return v;
  const loc = typeof manifest.default_locale === 'string' ? manifest.default_locale : 'en';
  for (const l of [loc, 'en', 'en_US']) {
    try {
      const msgs = JSON.parse((await readSmallText(path.join(dir, '_locales', l, 'messages.json'))) ?? '');
      const key = Object.keys(msgs).find((k) => k.toLowerCase() === m[1].toLowerCase());
      if (key && typeof msgs[key]?.message === 'string') return msgs[key].message;
    } catch {
      /* next locale */
    }
  }
  return undefined;
}

export const browserExtensions: Scanner = {
  id: 'chrome',
  async scanUser(col) {
    for (const b of BROWSERS) {
      const p = col.ctx.platform;
      const root = p === 'darwin' ? path.join(col.ctx.appSupport, b.mac) : p === 'win32' ? (b.win ? path.join(col.ctx.localAppData, b.win) : undefined) : b.linux ? path.join(col.ctx.xdgConfig, b.linux) : undefined;
      if (!root || !(await isDir(root))) continue;
      for (const profile of await listDir(root)) {
        if (profile !== 'Default' && !/^Profile \d+$/.test(profile)) continue;
        const extRoot = path.join(root, profile, 'Extensions');
        for (const id of await listDir(extRoot)) {
          const versions = (await listDir(path.join(extRoot, id))).filter((v) => !v.startsWith('.')).sort();
          const ver = versions.pop();
          if (!ver) continue;
          const dir = path.join(extRoot, id, ver);
          let manifest: Record<string, unknown>;
          try {
            manifest = JSON.parse((await readSmallText(path.join(dir, 'manifest.json'))) ?? '');
          } catch {
            continue;
          }
          const name = await localized(dir, manifest, manifest.name);
          const desc = await localized(dir, manifest, manifest.description);
          if (!name || !AI_EXT.test(`${name} ${desc ?? ''}`)) continue;
          const perms = (Array.isArray(manifest.permissions) ? manifest.permissions : []).filter((p): p is string => typeof p === 'string');
          const scripts = Array.isArray(manifest.content_scripts) ? manifest.content_scripts.flatMap((c: { matches?: unknown }) => (Array.isArray(c?.matches) ? c.matches : [])) : [];
          const hosts = [...new Set([...(Array.isArray(manifest.host_permissions) ? manifest.host_permissions : []), ...perms.filter((p) => p.includes('://') || p === '<all_urls>'), ...scripts])].filter((p): p is string => typeof p === 'string');
          col.client(b.id, b.name, root);
          col.add({
            kind: 'browser-extension',
            name,
            key: `browser-ext:${b.id}:${id}`,
            path: dir,
            skill: { description: desc, version: typeof manifest.version === 'string' ? manifest.version : undefined },
            browserExtension: {
              browser: b.name,
              extensionId: id,
              version: typeof manifest.version === 'string' ? manifest.version : ver,
              permissions: perms.filter((p) => !p.includes('://') && p !== '<all_urls>').slice(0, 30),
              hostPermissions: hosts.slice(0, 30),
              allSites: hosts.some((h) => ALL_SITES.has(h)),
            },
            occurrence: { client: b.id, scope: 'user', source: path.join(root, profile), name: `${name} (${profile})` },
          });
        }
      }
    }
  },
};

/* ---------------- Editor tasks that run on folder open ---------------- */

/** VS Code / Cursor tasks with runOptions.runOn = "folderOpen" run as soon as a folder is opened. */
export const autorunTasks: Scanner = {
  id: 'vscode',
  async scanProject(col, dir) {
    const file = path.join(dir, '.vscode', 'tasks.json');
    const text = await readSmallText(file);
    if (!text) return;
    let data: { tasks?: unknown };
    try {
      data = JSON.parse(text.replace(/^\s*\/\/.*$/gm, '').replace(/,(\s*[}\]])/g, '$1'));
    } catch {
      return;
    }
    if (!Array.isArray(data.tasks)) return;
    data.tasks.forEach((t: Record<string, unknown>, i: number) => {
      const run = t?.runOptions as Record<string, unknown> | undefined;
      if (run?.runOn !== 'folderOpen') return;
      const command = [t.command, ...(Array.isArray(t.args) ? t.args : [])].filter((x) => typeof x === 'string').join(' ');
      if (!command) return;
      const name = typeof t.label === 'string' ? t.label : `task ${i + 1}`;
      col.client('vscode', 'VS Code');
      col.add({
        kind: 'hook',
        name: `folderOpen [${name}]`,
        key: `${file}|${i}|${command}`,
        hook: { event: 'folderOpen', command },
        path: file,
        occurrence: { client: 'vscode', scope: 'project', source: file, name, project: dir, jsonPath: ['tasks', i] },
      });
    });
  },
};

export const widerScanners: Scanner[] = [localModels, apiKeys, aiApps, browserExtensions, autorunTasks];
