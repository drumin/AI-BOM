import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { randomUUID } from 'node:crypto';
import type { ConnectorAccess } from './types.js';
import { dataDir } from './util/store.js';

/**
 * Cloud connectors (claude.ai, ChatGPT, Gemini…) live in your online account,
 * not on disk, and no platform offers an API to list them. AI-BOM keeps a
 * small user-maintained registry so they appear in the same inventory,
 * graph and review cycle as local assets.
 */

export interface ConnectorRecord {
  id: string;
  platform: string;
  name: string;
  access: ConnectorAccess;
  notes?: string;
  addedAt: string;
  reviewedAt?: string;
}

interface RegistryFile {
  version: 1;
  connectors: ConnectorRecord[];
}

export const DEFAULT_CONNECTORS_FILE = path.join(dataDir(), 'connectors.json');

export const PLATFORMS = ['claude.ai', 'ChatGPT', 'Gemini', 'Microsoft Copilot', 'Perplexity', 'Other'];

/** Suggestions for the "add connector" UI. Purely a convenience list. */
export const COMMON_CONNECTORS = [
  'Gmail', 'Google Drive', 'Google Calendar', 'Outlook', 'OneDrive', 'SharePoint', 'Microsoft Teams',
  'Slack', 'GitHub', 'GitLab', 'Notion', 'Linear', 'Jira', 'Confluence', 'Asana', 'Figma', 'Canva',
  'Dropbox', 'Box', 'HubSpot', 'Salesforce', 'Stripe', 'Zapier',
];

/** Days after which an unreviewed connector is flagged. */
export const REVIEW_DAYS = 90;

export async function loadConnectors(file: string): Promise<ConnectorRecord[]> {
  let text: string;
  try {
    text = await fs.readFile(file, 'utf8');
  } catch {
    return [];
  }
  const data = JSON.parse(text) as Partial<RegistryFile>;
  if (!Array.isArray(data.connectors)) throw new Error(`${path.basename(file)}: "connectors" must be an array`);
  return data.connectors.filter((c) => c && typeof c.name === 'string' && typeof c.platform === 'string');
}

async function save(file: string, connectors: ConnectorRecord[]): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const body: RegistryFile = { version: 1, connectors };
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(body, null, 2) + '\n', { mode: 0o600 });
  await fs.rename(tmp, file); // atomic replace: a crash never leaves a half-written registry
}

const ACCESS: ConnectorAccess[] = ['read', 'read-write', 'unknown'];

export function validateInput(input: unknown): Omit<ConnectorRecord, 'id' | 'addedAt'> {
  const o = (input ?? {}) as Record<string, unknown>;
  const str = (v: unknown, max: number) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
  const name = str(o.name, 80);
  const platform = str(o.platform, 40);
  if (!name) throw new Error('name is required');
  if (!platform) throw new Error('platform is required');
  const access = ACCESS.includes(o.access as ConnectorAccess) ? (o.access as ConnectorAccess) : 'unknown';
  const notes = str(o.notes, 500) || undefined;
  return { name, platform, access, notes };
}

export async function addConnector(file: string, input: unknown): Promise<ConnectorRecord> {
  const clean = validateInput(input);
  const list = await loadConnectors(file);
  const now = new Date().toISOString();
  const rec: ConnectorRecord = { id: randomUUID(), ...clean, addedAt: now, reviewedAt: now };
  list.push(rec);
  await save(file, list);
  return rec;
}

export async function removeConnector(file: string, id: string): Promise<boolean> {
  const list = await loadConnectors(file);
  const next = list.filter((c) => c.id !== id);
  if (next.length === list.length) return false;
  await save(file, next);
  return true;
}

export async function markReviewed(file: string, id: string): Promise<boolean> {
  const list = await loadConnectors(file);
  const rec = list.find((c) => c.id === id);
  if (!rec) return false;
  rec.reviewedAt = new Date().toISOString();
  await save(file, list);
  return true;
}
