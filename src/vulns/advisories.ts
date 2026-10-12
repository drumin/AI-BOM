import type { Severity } from '../types.js';

/**
 * Bundled advisories for MCP-related packages, checked offline on every scan.
 * Kept deliberately small and high-confidence; the online OSV lookup
 * (`--online`) covers the long tail. Update with each release.
 */
export interface Advisory {
  id: string;
  ecosystem: 'npm' | 'pypi';
  package: string;
  /** Affected range; omit both bounds for "every version" (malicious packages). */
  introduced?: string;
  /** First fixed version; one per scheme when the package used both semver and date versions. */
  fixed?: string | string[];
  severity: Severity;
  cvss?: { score: number; version?: string };
  malicious?: boolean;
  summary: string;
  references: string[];
}

export const ADVISORIES: Advisory[] = [
  {
    id: 'CVE-2025-6514',
    ecosystem: 'npm',
    package: 'mcp-remote',
    introduced: '0.0.5',
    fixed: '0.1.16',
    severity: 'critical',
    cvss: { score: 9.6, version: '3.1' },
    summary: 'OS command injection: a malicious remote MCP server can run arbitrary commands on your machine through the OAuth authorization URL.',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2025-6514'],
  },
  {
    id: 'CVE-2025-49596',
    ecosystem: 'npm',
    package: '@modelcontextprotocol/inspector',
    fixed: '0.14.1',
    severity: 'critical',
    cvss: { score: 9.4, version: '4.0' },
    summary: 'MCP Inspector proxy lacks authentication; a web page you visit can reach it and execute commands (remote code execution).',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2025-49596'],
  },
  {
    id: 'CVE-2025-53110',
    ecosystem: 'npm',
    package: '@modelcontextprotocol/server-filesystem',
    fixed: ['0.6.4', '2025.7.1'],
    severity: 'high',
    summary: 'Directory containment bypass: paths sharing a prefix with an allowed directory (e.g. /allowed_evil) are accessible.',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2025-53110'],
  },
  {
    id: 'CVE-2025-53109',
    ecosystem: 'npm',
    package: '@modelcontextprotocol/server-filesystem',
    fixed: ['0.6.4', '2025.7.1'],
    severity: 'high',
    summary: 'Symlink bypass: a crafted symlink lets the server read and write files outside the allowed directories.',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2025-53109'],
  },
  {
    id: 'AIBOM-MAL-2025-0001',
    ecosystem: 'npm',
    package: 'postmark-mcp',
    introduced: '1.0.16',
    severity: 'critical',
    malicious: true,
    summary:
      'Malicious package impersonating a Postmark email MCP server: from 1.0.16 it silently BCCs every email it sends to an attacker-controlled address. It is not the official Postmark server.',
    references: ['https://osv.dev/list?q=postmark-mcp'],
  },
];
