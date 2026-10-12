import type { AssetKind } from './types.js';

/** Display names for asset kinds, shared by the terminal summary and the reports. */
export const KIND_NAMES: Record<AssetKind, string> = {
  'mcp-server': 'MCP servers',
  skill: 'Skills',
  plugin: 'Plugins',
  extension: 'Extensions',
  agent: 'Subagents',
  command: 'Commands / prompts',
  hook: 'Hooks',
  instructions: 'Instruction files',
  connector: 'Connectors',
  telemetry: 'Telemetry exports',
  model: 'Local models',
  'api-key': 'AI API keys',
  app: 'AI apps',
  'browser-extension': 'AI browser extensions',
};
