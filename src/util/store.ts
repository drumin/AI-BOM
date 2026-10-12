import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';

/** Where AI-BOM keeps its own state (~/.ai-bom); overridable for tests with AI_BOM_HOME. */
export function dataDir(): string {
  return process.env.AI_BOM_HOME || path.join(os.homedir(), '.ai-bom');
}

/** Write a file atomically (temp file + rename) with owner-only permissions. */
export async function writeAtomic(file: string, content: string, mode = 0o600): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(tmp, content, { mode });
  try {
    await fs.rename(tmp, file);
  } catch (e) {
    await fs.rm(tmp, { force: true });
    throw e;
  }
}

export async function readJsonFile<T>(file: string): Promise<T | undefined> {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8')) as T;
  } catch {
    return undefined;
  }
}

export async function writeJsonFile(file: string, value: unknown): Promise<void> {
  await writeAtomic(file, JSON.stringify(value, null, 2) + '\n');
}
