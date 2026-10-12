import path from 'node:path';
import type { Collector, SettingsDoc } from '../collector.js';
import type { Asset, Finding, Severity } from '../types.js';
import { asString, asStringArray, isObject, readSmallText, readTextChecked, SKILL_FILE_CAP } from '../util/fs.js';
import { codeOnly, findPersistence } from './persistence.js';
import { findHiddenInstructions } from './hidden.js';
import { describeScan, scanHidden, showHidden, type HiddenScan } from '../analysis/hidden.js';
import { findBinaries } from './binaries.js';
import { imitates, isFloatingNpm, isFloatingPy, KNOWN_NPM, KNOWN_PY, KNOWN_SKILLS, parsePackageJson, parseRequirements, type Dep } from './skillsupply.js';
import { shortHash } from '../util/hash.js';
import { analyzeFile, CREDENTIAL_PATHS, newReport } from './capabilities.js';
import type { VulnHit } from '../vulns/index.js';
import { egressHooks } from '../analysis/hooks.js';
import { pinnedCommand, upgradeTarget } from '../vulns/fix.js';
import { REVIEW_DAYS } from '../connectors.js';
import { atlasFor } from '../frameworks/atlas.js';
import { classifySecret, findTokenPattern, maskValue, redactText, redactUrl } from '../util/secrets.js';

/**
 * Offline static checks. Each rule maps to the OWASP Top 10 for LLM
 * Applications (2025, "LLMxx") and the OWASP Top 10 for Agentic
 * Applications ("ASIxx") where one applies.
 */
export const OWASP: Record<string, string> = {
  LLM01: 'LLM01:2025 Prompt Injection',
  LLM02: 'LLM02:2025 Sensitive Information Disclosure',
  LLM03: 'LLM03:2025 Supply Chain',
  LLM06: 'LLM06:2025 Excessive Agency',
  ASI01: 'ASI01 Agent Goal Hijack',
  ASI02: 'ASI02 Tool Misuse and Exploitation',
  ASI03: 'ASI03 Identity and Privilege Abuse',
  ASI04: 'ASI04 Agentic Supply Chain Vulnerabilities',
  ASI05: 'ASI05 Unexpected Code Execution',
};

interface RuleMeta {
  title: string;
  description: string;
  remediation: string;
  owasp: string[];
}

export const RULES: Record<string, RuleMeta> = {
  'MCP-SECRET': {
    title: 'Plain-text secret in MCP server config',
    description: 'An API key or token is written directly into the config file. Anyone or anything that can read the file (backups, dotfile repos, other tools, malware) gets the credential.',
    remediation: 'Move the value to your OS keychain or a secret manager and reference it (e.g. "${env:MY_TOKEN}" / an environment variable exported by your shell). Rotate the exposed key.',
    owasp: ['LLM02', 'ASI03'],
  },
  'MCP-UNPINNED': {
    title: 'MCP server package is not pinned to a version',
    description: 'The server is downloaded and executed on every start without a fixed version. A compromised or hijacked release is picked up automatically (this is how several malicious MCP packages spread).',
    remediation: 'Pin an exact version (npx pkg@1.2.3, uvx pkg==1.2.3) or an image digest (image@sha256:...), and review changes before upgrading.',
    owasp: ['LLM03', 'ASI04'],
  },
  'MCP-INSECURE-TRANSPORT': {
    title: 'Remote MCP server over unencrypted HTTP',
    description: 'Traffic to this server, including tool inputs/outputs and any auth headers, is sent in clear text and can be read or modified in transit.',
    remediation: 'Use an https:// endpoint. Only use http:// for servers bound to localhost.',
    owasp: ['LLM02', 'ASI02'],
  },
  'MCP-BROAD-FS': {
    title: 'MCP server has access to a very broad filesystem scope',
    description: 'The server is given your whole disk or home directory. Any prompt injection that reaches it can read SSH keys, cloud credentials and browser data.',
    remediation: 'Limit the server to the specific project folders it needs.',
    owasp: ['LLM06', 'ASI02'],
  },
  'MCP-CONTAINER-PRIVILEGED': {
    title: 'Containerized MCP server runs with host-level privileges',
    description: 'Flags like --privileged, --network host or mounting the Docker socket / host root remove the isolation the container was supposed to provide.',
    remediation: 'Drop the privileged flags and mount only the directories the server needs, read-only where possible.',
    owasp: ['LLM06', 'ASI05'],
  },
  'MCP-SHELL-COMMAND': {
    title: 'MCP server is launched through a shell command',
    description: 'The server is started via "sh -c" / "bash -c". Shell wrappers hide what is actually executed and are a common way to chain downloads or extra commands.',
    remediation: 'Invoke the server binary or package runner directly with explicit arguments.',
    owasp: ['ASI05'],
  },
  'PERM-BYPASS': {
    title: 'Permission prompts are disabled',
    description: 'The agent is configured to run tools without asking you (bypassPermissions). A single prompt injection can then execute commands, edit files or call MCP tools unattended.',
    remediation: 'Remove "defaultMode": "bypassPermissions" and use targeted allow rules instead.',
    owasp: ['LLM06', 'ASI02'],
  },
  'PERM-BROAD-ALLOW': {
    title: 'Broad command execution pre-approved',
    description: 'An allow rule lets the agent run any shell command (or a general-purpose interpreter / network tool) without confirmation.',
    remediation: 'Replace wildcard rules with specific commands, e.g. Bash(npm test:*), and keep curl/wget/interpreters behind a prompt.',
    owasp: ['LLM06', 'ASI02'],
  },
  'PERM-AUTO-PROJECT-MCP': {
    title: 'All project MCP servers are auto-approved',
    description: 'enableAllProjectMcpServers makes the agent start every server defined in any repository\'s .mcp.json. Cloning a malicious repo is enough to run its code.',
    remediation: 'Turn it off and approve project MCP servers individually.',
    owasp: ['LLM03', 'ASI04'],
  },
  'SETTINGS-SECRET': {
    title: 'Plain-text secret in agent settings',
    description: 'A credential is stored in clear text inside an AI tool settings file.',
    remediation: 'Load the value from your OS keychain or shell environment instead, and rotate the exposed key.',
    owasp: ['LLM02', 'ASI03'],
  },
  'HOOK-EXEC': {
    title: 'Hook runs a command automatically',
    description: 'Hooks execute on agent events without asking. They are easy to forget and run with your full user permissions.',
    remediation: 'Keep hooks you recognize; remove ones you did not add yourself.',
    owasp: ['ASI05'],
  },
  'HOOK-NETWORK': {
    title: 'Hook sends data over the network or downloads code',
    description: 'A hook calls curl/wget/nc or a URL. Hooks receive tool inputs (file contents, commands) and can silently exfiltrate them.',
    remediation: 'Verify where the data goes. Remove the hook if you do not know why it exists.',
    owasp: ['LLM02', 'ASI05'],
  },
  'CONTENT-NOT-INSPECTED': {
    title: 'Part of this was not inspected',
    description: 'AI-BOM could not read all of this content (a file over 1 MB, or more files than it lists), so it cannot vouch for it. Padding a file past the limit is also a way to hide instructions.',
    remediation: 'Open the file yourself or trim it. Until then, treat the clean result as incomplete.',
    owasp: [],
  },
  'CONTENT-PERSISTENCE': {
    title: 'Sets itself up to keep running or changes your AI settings',
    description: 'A script or code block writes to a place that runs things later (shell startup files, cron, background services, git hooks, SSH keys) or rewrites an AI tool\'s settings. A skill should do its job and leave; this is how one stays behind.',
    remediation: 'Read the command. If you did not expect the skill to change this, do not install it. Anything it already changed can be undone from that file.',
    owasp: ['LLM06', 'ASI05'],
  },
  'CONTENT-HIDDEN-INSTRUCTION': {
    title: 'Instructions hidden where a reader would not see them',
    description: 'The text hides directions for the model in a comment, spells them out letter by letter, encodes them (base64), or tries to switch off the model\'s safety behaviour. A person skimming the file sees nothing odd; the model reads all of it.',
    remediation: 'Read the flagged passage. If you do not know why it is there, do not use the file. If it is a security example, mute the finding.',
    owasp: ['LLM01', 'ASI01'],
  },
  'CONTENT-HIDDEN-UNICODE': {
    title: 'Hidden Unicode characters in agent instructions',
    description: 'Zero-width, bidirectional-override or Unicode tag characters are invisible to you but read by the model. They are a known way to smuggle instructions into skills and rules files.',
    remediation: 'Inspect the file with a hex viewer and remove the characters. Treat the source of the file as untrusted.',
    owasp: ['LLM01', 'ASI01'],
  },
  'CONTENT-PROMPT-INJECTION': {
    title: 'Instruction-override language in agent content',
    description: 'The text tells the model to ignore prior instructions, hide actions from the user, or similar. This is a common prompt-injection pattern.',
    remediation: 'Review the passage. Legitimate skills rarely need to override the system prompt or keep things from the user.',
    owasp: ['LLM01', 'ASI01'],
  },
  'CONTENT-DOWNLOAD-EXEC': {
    title: 'Downloads and executes remote code',
    description: 'The content pipes a download into a shell/interpreter or decodes and runs an obfuscated payload.',
    remediation: 'Do not run it. Vendor the script, review it, and pin it to a checksum.',
    owasp: ['LLM03', 'ASI05'],
  },
  'CONTENT-SENSITIVE-PATHS': {
    title: 'References credential stores or sensitive files',
    description: 'The content references SSH keys, cloud credentials, browser data or the keychain. Legitimate skills rarely need these; exfiltration attacks do.',
    remediation: 'Confirm why the skill needs this access. Remove it if the reason is unclear.',
    owasp: ['LLM02', 'ASI03'],
  },
  'CONTENT-SECRET': {
    title: 'Credential embedded in agent content',
    description: 'A token matching a known credential format is embedded in a skill, rule or command file.',
    remediation: 'Remove the token from the file and rotate it.',
    owasp: ['LLM02'],
  },
  'SKILL-EXFIL-PATTERN': {
    title: 'Reads credentials and makes network requests',
    description: 'The same script or code block both touches a credential store (SSH keys, cloud credentials, keychain, browser data) and sends network requests. That is the shape of credential theft.',
    remediation: 'Read the script before using this skill. Remove it unless you know exactly why it needs both.',
    owasp: ['LLM02', 'ASI03'],
  },
  'SKILL-SUSPICIOUS-ENDPOINT': {
    title: 'Talks to a data-collection or tunneling endpoint',
    description: 'The content references a request-capture, paste, tunneling or raw-IP endpoint (webhook.site, ngrok, pastebin, a bare IP…). These are rarely needed by legitimate skills and are commonly used to receive stolen data.',
    remediation: 'Check what is sent there. Replace it with the service\'s official API host or remove the skill.',
    owasp: ['LLM02', 'ASI02'],
  },
  'MCP-TOOL-POISONING': {
    title: 'Hidden instructions in an MCP tool description',
    description: 'A tool description declared by this server contains invisible characters or instruction-override language. The model reads tool descriptions on every turn, so this is a way to hijack the agent without you seeing it.',
    remediation: 'Disable the server and report it to its publisher.',
    owasp: ['LLM01', 'ASI01', 'ASI04'],
  },
  'VULN-KNOWN': {
    title: 'Known vulnerability in MCP server package',
    description: 'The package this MCP server runs has a published security advisory.',
    remediation: 'Upgrade to a fixed version and pin it (e.g. npx pkg@<fixed>). If no fix exists, disable the server.',
    owasp: ['LLM03', 'ASI04'],
  },
  'VULN-POSSIBLE': {
    title: 'Possibly related vulnerability',
    description: 'The NVD lists a vulnerability for a product with this name, but the match or the affected version could not be confirmed.',
    remediation: 'Open the advisory and compare it with the package and version this server runs.',
    owasp: ['LLM03', 'ASI04'],
  },
  'VULN-MALICIOUS': {
    title: 'Malicious package',
    description: 'This MCP server runs a package flagged as malware.',
    remediation: 'Remove the server from every config now, uninstall the package, and rotate any credentials it could reach.',
    owasp: ['LLM03', 'ASI04'],
  },
  'CONNECTOR-REVIEW': {
    title: 'Cloud connector not reviewed recently',
    description: 'You have not confirmed in 90+ days that you still use this connector. Forgotten connectors keep their access to your data.',
    remediation: 'Open the platform\'s connector settings; disconnect it if unused, otherwise mark it reviewed.',
    owasp: ['LLM06', 'ASI03'],
  },
  'TOOLCALL-SECRET-SENT': {
    title: 'A credential was sent to an MCP tool',
    description: 'Your session logs show a tool call whose arguments contained a credential. Whoever runs that server (and anything it forwards to) now has it.',
    remediation: 'Rotate the credential. If the call was not something you asked for, treat it as a prompt-injection incident and review what else the session did.',
    owasp: ['LLM02', 'ASI02'],
  },
  'TOOLCALL-INJECTION': {
    title: 'Tool output contained instructions for the model',
    description: 'A result returned by this MCP tool contained instruction-override language or invisible characters. Tool output is read by the model like any other text, so this is how indirect prompt injection reaches your agent.',
    remediation: 'Check what content the tool fetched and what the agent did next. Prefer servers that return data from trusted sources, and keep approval prompts on for tools that can act.',
    owasp: ['LLM01', 'ASI01'],
  },
  'TOOLCALL-SUSPICIOUS-DEST': {
    title: 'A tool call sent data to a data-collection or tunneling endpoint',
    description: 'Your session logs show a tool call addressed to a request-capture, paste, tunneling or raw-IP endpoint. These are rarely needed for real work and are common exfiltration targets.',
    remediation: 'Find out why the agent made this call. If you did not ask for it, rotate credentials the session could reach.',
    owasp: ['LLM02', 'ASI02'],
  },
  'USAGE-UNUSED': {
    title: 'Configured but never used',
    description: 'This MCP server is set up in Claude Code but your session logs show no calls to it. Unused servers still start, still hold credentials, and still add their tool descriptions to every conversation.',
    remediation: 'Remove it if you no longer need it (ai-bom fix can do this reversibly).',
    owasp: ['LLM06', 'ASI03'],
  },
  'TOOL-BEHAVIOR-MISMATCH': {
    title: 'Tool does more than its description says',
    description: 'The code behind this MCP tool does something its name and description do not mention. The model (and you, when approving) only see the description.',
    remediation: 'Read the tool\'s code before using the server. Remove it if the extra behavior is not explained by its documentation.',
    owasp: ['LLM03', 'ASI02', 'ASI04'],
  },
  'TOOL-UNDECLARED': {
    title: 'Server code registers tools its manifest does not list',
    description: 'The extension manifest declares a set of tools, but the server\'s code registers more. Undeclared tools are easy to miss when reviewing what an extension can do.',
    remediation: 'Review the extra tools listed in the evidence.',
    owasp: ['LLM03', 'ASI04'],
  },
  'HOOK-DATA-EGRESS': {
    title: 'Hook sends your session data off this machine',
    description: 'This hook receives data from your agent (prompts, tool inputs, file contents or the whole transcript) and its command or script sends data over the network.',
    remediation: 'Confirm you know and trust the destination. Remove the hook if you did not set it up yourself.',
    owasp: ['LLM02', 'ASI02'],
  },
  'TELEMETRY-PROMPTS': {
    title: 'Your prompts are exported to a telemetry collector',
    description: 'OpenTelemetry export is on and configured to include the text of your prompts (or tool parameters such as file paths and commands).',
    remediation: 'If you did not set this up, remove the OTEL_* settings. Otherwise make sure the collector belongs to you or your employer and is meant to receive prompt text.',
    owasp: ['LLM02'],
  },
  'TELEMETRY-EXPORT': {
    title: 'Usage telemetry is exported to a collector',
    description: 'This AI tool is configured to send OpenTelemetry metrics/events (session counts, token usage, tool names, costs) to the endpoint shown.',
    remediation: 'Keep it if the collector is yours or your employer\'s; remove the settings otherwise.',
    owasp: ['LLM02'],
  },
  'TELEMETRY-INSECURE': {
    title: 'Telemetry is sent over unencrypted HTTP',
    description: 'The OpenTelemetry endpoint is plain http:// on a non-local host, so exported events (and any auth headers) travel in clear text.',
    remediation: 'Use an https:// endpoint.',
    owasp: ['LLM02'],
  },
  'SETTINGS-API-REDIRECT': {
    title: 'API traffic is redirected to a different host',
    description: 'A settings file sets ANTHROPIC_BASE_URL/OPENAI_BASE_URL (or similar) to a non-default host. Every request, including your API key and prompts, goes there. In a project settings file this is a known way for a malicious repository to steal keys.',
    remediation: 'Remove the setting unless it points to a proxy you run.',
    owasp: ['LLM02', 'ASI03'],
  },
  'SETTINGS-ENV-INJECTION': {
    title: 'A setting loads someone\'s code into every program the agent starts',
    description: 'The settings file sets an environment variable (LD_PRELOAD, DYLD_INSERT_LIBRARIES, NODE_OPTIONS with --require/--import, BASH_ENV, PYTHONSTARTUP…) that makes programs load extra code when they start. Set in a project, it is a way for a repository to run code the moment the agent runs any command.',
    remediation: 'Remove the variable unless you put it there and know what it loads.',
    owasp: ['ASI05', 'LLM06'],
  },
  'SETTINGS-TRAFFIC-INTERCEPT': {
    title: 'Network traffic goes through a proxy, or its encryption checks are off',
    description: 'The settings file sets a proxy (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY), turns off certificate checking, or trusts an extra certificate authority. Whoever runs that proxy or holds that certificate can read the agent\'s traffic, including keys and prompts.',
    remediation: 'Remove the setting unless it points to a proxy or certificate you run yourself.',
    owasp: ['LLM02', 'ASI03'],
  },
  'PERM-BROAD-DIRS': {
    title: 'The agent is allowed into a very wide or sensitive folder',
    description: 'permissions.additionalDirectories includes your whole home folder, the filesystem root, or a folder that holds credentials (~/.ssh, ~/.aws…). The agent can then read everything there without asking.',
    remediation: 'List only the project folders the agent really needs.',
    owasp: ['LLM06', 'ASI03'],
  },
  'TRUST-TYPOSQUAT-SKILL': {
    title: 'Name imitates a well-known skill or plugin',
    description: 'The name is one character away from a widely used skill or plugin. Attackers publish look-alikes hoping to be installed by mistake.',
    remediation: 'Check where it came from. If you meant the well-known one, remove this and install that instead.',
    owasp: ['LLM03', 'ASI04'],
  },
  'SKILL-DEP-TYPOSQUAT': {
    title: 'A dependency imitates a popular package',
    description: 'A skill lists a package whose name is one character away from a popular one (reqeusts for requests). Look-alike packages are a common way to get code installed.',
    remediation: 'Compare the name with the real package. If it is a typo, fix it; if not, do not install it.',
    owasp: ['LLM03', 'ASI04'],
  },
  'SKILL-DEP-UNPINNED': {
    title: 'Dependencies are not pinned to a version',
    description: 'The skill lists packages without a fixed version. Whatever is newest on the registry gets installed, so a later malicious release reaches you automatically.',
    remediation: 'Pin versions (requests==2.32.3) before installing, and review what changes when you update.',
    owasp: ['LLM03', 'ASI04'],
  },
  'SKILL-BINARY': {
    title: 'Ships compiled code that cannot be read',
    description: 'The skill contains a program, compiled bytecode or a macro-enabled document. A text scan cannot see what these do, and a program renamed to look like a text or image file is a known way to smuggle one in.',
    remediation: 'Only keep it if you trust the author and know why it is there. Prefer skills that ship readable source.',
    owasp: ['LLM03', 'ASI04', 'ASI05'],
  },
  'AUTORUN-TASK': {
    title: 'Runs a command as soon as the folder is opened',
    description: 'An editor task in this project is set to run automatically when the folder opens (runOn: folderOpen). Opening an untrusted repository is enough to execute it.',
    remediation: 'Review the command. Remove the runOptions or keep the folder in restricted mode.',
    owasp: ['LLM03', 'ASI05'],
  },
  'COMBO-LETHAL-TRIFECTA': {
    title: 'Private data + untrusted content + a way out',
    description: 'The same agent can read your private data, is exposed to content written by others, and can send data out. With all three, a single prompt-injected page, email or issue can make it leak your data (the "lethal trifecta").',
    remediation: 'Remove one leg: disable the tool that reads untrusted content, the one with private data, or the one that can send data out, in this agent. Keep approval prompts on for all three.',
    owasp: ['LLM01', 'LLM02', 'ASI01', 'ASI02'],
  },
  'COMBO-SHELL-UNTRUSTED': {
    title: 'Command execution + untrusted content',
    description: 'The same agent can run shell commands and reads content written by others. A prompt injection in that content can turn into code execution on your machine.',
    remediation: 'Keep command approval prompts on, or split the two into separate agents/projects.',
    owasp: ['LLM01', 'ASI05'],
  },
  'TRUST-TYPOSQUAT': {
    title: 'Package name looks like a well-known one',
    description: 'The package name is one or two characters away from a popular MCP package. Lookalike names are a common way to trick people into installing malware.',
    remediation: 'Check you meant this package and not the well-known one shown in the evidence.',
    owasp: ['LLM03', 'ASI04'],
  },
  'TRUST-INSTALL-SCRIPTS': {
    title: 'Package runs install scripts',
    description: 'The package declares preinstall/install/postinstall scripts, which run code on your machine at install time, before you ever start the server.',
    remediation: 'Review the scripts, or install with --ignore-scripts.',
    owasp: ['LLM03', 'ASI04'],
  },
  'TRUST-NEW-PACKAGE': {
    title: 'Very new package',
    description: 'The package was first published less than 30 days ago. Most malicious packages are removed within days, so brand-new packages carry more risk.',
    remediation: 'Wait, or review the source before using it.',
    owasp: ['LLM03', 'ASI04'],
  },
  'TRUST-DEPRECATED': {
    title: 'Package is deprecated',
    description: 'The publisher marked this version deprecated; it may no longer get security fixes.',
    remediation: 'Switch to the replacement named in the deprecation message.',
    owasp: ['LLM03'],
  },
  'TRUST-NO-REPO': {
    title: 'Package has no source repository',
    description: 'The package does not link to its source code, so you cannot easily review what it does.',
    remediation: 'Prefer servers with public source, or inspect the published package contents.',
    owasp: ['LLM03'],
  },
  'MODEL-SERVER-EXPOSED': {
    title: 'A local model server is reachable from other computers',
    description: 'A model server (Ollama, llama.cpp, LM Studio and similar) is listening on a network address, not only on this computer. These servers usually have no login, so anyone who can reach the port can send it prompts and use your hardware.',
    remediation: 'Make it listen on localhost only (for Ollama, unset OLLAMA_HOST or set it to 127.0.0.1), or put it behind a firewall or a proxy that requires a login.',
    owasp: ['LLM02', 'ASI03'],
  },
  'MCP-UNLISTED-RUNNING': {
    title: 'A program that looks like an MCP server is running but is not in any config',
    description: 'A running process has the name or launch command of an MCP server, but none of the config files AI-BOM reads list it. It may belong to an app AI-BOM does not cover, a script, or something started by hand.',
    remediation: 'Find out what started it. If you do not recognize it, stop it and check which app or script launched it.',
    owasp: ['LLM03', 'ASI04'],
  },
  'MCP-TOOL-SHADOWING': {
    title: 'A server reuses tool names from another server',
    description: 'Two MCP servers expose a tool with the same name, so a request for that tool can reach the wrong server. A look-alike server only has to reuse a trusted tool\'s name to be called in its place ("tool shadowing").',
    remediation: 'Remove the server you do not recognize, or disable the overlapping tool on it. Prefer servers listed in the official MCP Registry.',
    owasp: ['LLM03', 'ASI04'],
  },
  'TRUST-TOOLS-CHANGED': {
    title: 'Tool descriptions changed since the last scan',
    description: 'The tools this server exposes changed since AI-BOM last looked. A server that silently rewrites its tool descriptions after you approved it is known as a "rug pull".',
    remediation: 'Review the changed tools listed in the evidence.',
    owasp: ['LLM03', 'ASI04'],
  },
  'MODEL-PICKLE': {
    title: 'Model weights in pickle format',
    description: 'These weights are stored as Python pickle (.bin/.pt/.pkl/.ckpt). Loading a pickle file can execute arbitrary code, and malicious models on public hubs have used this.',
    remediation: 'Prefer .safetensors or GGUF versions of the model, or only load pickles from publishers you trust.',
    owasp: ['LLM03'],
  },
  'APIKEY-PLAINTEXT': {
    title: 'AI API key stored in plain text',
    description: 'A provider API key is written into a shell profile or .env file. Every program you run can read it, and dotfiles often end up in backups or public repos.',
    remediation: 'Load it from the keychain instead (e.g. export OPENAI_API_KEY="$(security find-generic-password -s openai -w)"), and set a spending limit on the key.',
    owasp: ['LLM02'],
  },
  'APIKEY-NOT-GITIGNORED': {
    title: 'API key in a .env file that git would commit',
    description: 'This .env file holds a provider API key and is not covered by .gitignore, so it can be committed and pushed.',
    remediation: 'Add the file to .gitignore and rotate the key if it was ever committed.',
    owasp: ['LLM02'],
  },
  'EXT-ALL-SITES': {
    title: 'AI browser extension can read every website',
    description: 'The extension has access to all sites, so it can read pages you visit (email, banking, internal tools) and send their contents to its AI backend.',
    remediation: 'In the browser\'s extension settings, set site access to "On click" or specific sites.',
    owasp: ['LLM02', 'LLM06'],
  },
  'DEP-VULN': {
    title: 'Vulnerable dependency inside an MCP server',
    description: 'A package this MCP server depends on (and loads when it runs) has a published advisory.',
    remediation: 'Upgrade the server to a release that ships a fixed dependency, or clear its npx/uv cache so the next start resolves fixed versions.',
    owasp: ['LLM03', 'ASI04'],
  },
  'DEP-LICENSE': {
    title: 'Dependency license worth checking',
    description: 'The server pulls in dependencies under a strong copyleft license (GPL/AGPL…) or without any declared license.',
    remediation: 'Fine for personal use; check the terms before shipping or bundling this server in something you distribute.',
    owasp: ['LLM03'],
  },
  'LIVE-HIDDEN-TOOLS': {
    title: 'Running server exposes tools its code does not show',
    description: 'In the sandboxed run, the server listed tools that reading its code did not find. Tools built at runtime can change without any code you could review.',
    remediation: 'Review the extra tools listed in the evidence before using the server.',
    owasp: ['LLM03', 'ASI04'],
  },
  'LIVE-DYNAMIC-DESCRIPTIONS': {
    title: 'Tool descriptions are generated at runtime',
    description: 'The descriptions the running server reports differ from the ones in its code, so what the model reads can change without a code change.',
    remediation: 'Compare the descriptions in the evidence with the code; be wary of servers that fetch their own tool text.',
    owasp: ['LLM01', 'ASI04'],
  },
  'LIVE-NETWORK-AT-START': {
    title: 'Server tried to reach the network while starting',
    description: 'In the sandbox (network off), the server attempted a network connection before any tool was called: often telemetry, an update check, or downloading more code.',
    remediation: 'Find out what it contacts; block it or choose a server that does not phone home.',
    owasp: ['LLM02', 'ASI04'],
  },
  'SKILL-UNRESTRICTED-TOOLS': {
    title: 'Pre-approves unrestricted shell access',
    description: 'The frontmatter grants the Bash tool without a command pattern, so everything the skill/agent runs skips your approval.',
    remediation: 'Restrict allowed-tools to specific commands, e.g. Bash(git status:*).',
    owasp: ['LLM06', 'ASI02'],
  },
};

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
export const severityRank = (s: Severity) => SEVERITY_ORDER.indexOf(s);

export class Findings {
  readonly list: Finding[] = [];
  private seen = new Set<string>();

  add(
    ruleId: string,
    severity: Severity,
    opts: {
      asset?: Asset;
      location?: string;
      evidence?: string;
      detail?: string;
      title?: string;
      references?: string[];
      advisory?: string;
      remediation?: string;
      vuln?: Finding['vuln'];
      related?: string[];
    },
  ) {
    const meta = RULES[ruleId];
    const evidence = opts.evidence ? truncate(redactText(opts.evidence), 180) : undefined;
    const id = shortHash(ruleId, opts.asset?.id ?? '', opts.location ?? '', evidence ?? '', opts.title ?? '');
    if (this.seen.has(id)) return;
    this.seen.add(id);
    this.list.push({
      id,
      ruleId,
      severity,
      title: opts.title ?? meta.title,
      description: opts.detail ? `${meta.description} ${opts.detail}` : meta.description,
      remediation: opts.remediation ?? meta.remediation,
      assetId: opts.asset?.id,
      location: opts.location,
      evidence,
      owasp: meta.owasp.map((k) => OWASP[k]),
      atlas: atlasFor(ruleId),
      references: opts.references,
      advisory: opts.advisory,
      vuln: opts.vuln,
      related: opts.related,
    });
  }
}

function truncate(s: string, n: number): string {
  const one = s.replace(/\s+/g, ' ').trim();
  return one.length > n ? `${one.slice(0, n - 1)}…` : one;
}

/* ---------------- MCP servers ---------------- */

function isLocalHost(url: string): boolean {
  try {
    const h = new URL(url).hostname;
    return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]' || h.endsWith('.localhost');
  } catch {
    return false;
  }
}

function checkMcp(f: Findings, a: Asset, home: string) {
  const m = a.mcp!;
  const loc = a.occurrences[0]?.source;

  for (const o of a.occurrences) {
    for (const [k, v] of Object.entries({ ...o.env, ...o.headers })) {
      const why = classifySecret(k, v);
      if (why) f.add('MCP-SECRET', 'high', { asset: a, location: o.source, evidence: `${k}=${maskValue(v)}`, detail: `Detected: ${why}.` });
    }
  }
  const args = m.args ?? [];
  args.forEach((arg, i) => {
    const tok = findTokenPattern(arg);
    if (tok) {
      f.add('MCP-SECRET', 'high', { asset: a, location: loc, evidence: arg, detail: `Detected: ${tok} in command-line arguments.` });
      return;
    }
    // --api-key <literal> / --token=<literal>
    const [flag, inline] = arg.split(/=(.*)/s);
    const value = inline ?? (SECRET_FLAG.test(arg) ? args[i + 1] : undefined);
    if (SECRET_FLAG.test(flag) && value && !value.startsWith('-') && classifySecret('api_key', value)) {
      f.add('MCP-SECRET', 'high', { asset: a, location: loc, evidence: `${flag} ${maskValue(value)}`, detail: 'Detected: literal credential passed as a command-line flag (also visible to other processes via ps).' });
    }
  });

  // Tool poisoning: instructions hidden in declared tool descriptions are read by the model on every turn.
  for (const t of m.tools ?? []) {
    const text = `${t.name} ${t.description ?? ''}`;
    const hid = scanHidden(text);
    if (hid || INJECTION.some((re) => re.test(text))) {
      f.add('MCP-TOOL-POISONING', 'high', { asset: a, location: loc, evidence: describeHidden(`${t.name}: ${t.description ?? ''}`), detail: hid ? hiddenDetail(hid) : undefined });
    }
  }
  for (const u of new Set([m.url, m.remoteUrl, ...a.occurrences.map((o) => o.url)])) {
    if (!u) continue;
    try {
      const parsed = new URL(u);
      for (const [k, v] of parsed.searchParams) {
        if (classifySecret(k, v)) f.add('MCP-SECRET', 'high', { asset: a, location: loc, evidence: redactUrl(u), detail: 'Detected: credential in URL query string.' });
      }
      if (parsed.protocol === 'http:' && !isLocalHost(u)) {
        f.add('MCP-INSECURE-TRANSPORT', 'high', { asset: a, location: loc, evidence: redactUrl(u) });
      }
    } catch {
      /* not a URL */
    }
  }

  const pkg = m.package;
  if (pkg && (pkg.ecosystem === 'npm' || pkg.ecosystem === 'pypi' || pkg.ecosystem === 'docker') && !pkg.pinned) {
    const v = pkg.version;
    const floating = !v || v === 'latest';
    const sev: Severity = pkg.ecosystem === 'docker' && !floating ? 'low' : floating ? 'medium' : 'low';
    const detail = floating
      ? `${pkg.runner ?? pkg.ecosystem} fetches "${pkg.name}" at whatever version is newest.`
      : `"${pkg.name}@${v}" is a range/tag, not an exact version.`;
    f.add('MCP-UNPINNED', sev, { asset: a, location: loc, evidence: [m.command, ...(m.args ?? [])].join(' '), detail });
  }

  if (m.command) {
    const args = m.args ?? [];
    const cmdline = [m.command, ...args].join(' ');
    const bin = path.basename(m.command);
    const broadRoot = args.some((x) => x === '/' || x === 'C:\\' || x === '/Users' || x === '/home');
    const broadHome = args.some((x) => x === '~' || x === '~/' || x === '$HOME' || x === '${HOME}' || x.replace(/\/$/, '') === home);
    if (broadRoot) f.add('MCP-BROAD-FS', 'high', { asset: a, location: loc, evidence: cmdline, detail: 'Scope: entire disk.' });
    else if (broadHome) f.add('MCP-BROAD-FS', 'medium', { asset: a, location: loc, evidence: cmdline, detail: 'Scope: entire home directory.' });

    if ((bin === 'docker' || bin === 'podman') && args[0] === 'run') {
      const joined = args.join(' ');
      const bad = [
        /--privileged\b/,
        /--(network|net)[= ]host\b/,
        /--pid[= ]host\b/,
        /docker\.sock/,
        /(^|\s)(-v|--volume)[= ]\/:/,
        /--cap-add[= ](ALL|SYS_ADMIN)\b/,
      ].filter((re) => re.test(joined));
      if (bad.length) f.add('MCP-CONTAINER-PRIVILEGED', 'high', { asset: a, location: loc, evidence: cmdline });
    }

    if (['sh', 'bash', 'zsh', 'cmd', 'powershell', 'pwsh'].includes(bin.replace(/\.exe$/, ''))) {
      const script = args.join(' ');
      const dl = DOWNLOAD_EXEC.some((re) => re.test(script));
      f.add(dl ? 'CONTENT-DOWNLOAD-EXEC' : 'MCP-SHELL-COMMAND', dl ? 'high' : 'medium', { asset: a, location: loc, evidence: cmdline });
    }
  }
}

/* ---------------- Settings / permissions ---------------- */

const SECRET_FLAG = /^--?[\w-]*(api[-_]?key|token|secret|password|passwd)[\w-]*$/i;

const BROAD_BASH = new Set(['Bash', 'Bash(*)', 'Bash(*:*)', 'Bash(:*)']);
const RISKY_BASH = /^Bash\((curl|wget|nc|ncat|sh|bash|zsh|python3?|node|ruby|perl|eval|sudo|rm|ssh|scp)(\s|:|\*|\))/;

function checkSettings(f: Findings, doc: SettingsDoc, assetsByFile: Map<string, Asset>, assetsById: Map<string, Asset>) {
  const d = doc.data;
  const asset = (doc.assetId && assetsById.get(doc.assetId)) || assetsByFile.get(doc.file);
  const perms = isObject(d.permissions) ? d.permissions : undefined;
  if (perms?.defaultMode === 'bypassPermissions' || d.skipDangerousModePermissionPrompt === true) {
    f.add('PERM-BYPASS', 'high', { asset, location: doc.file, evidence: perms?.defaultMode === 'bypassPermissions' ? '"defaultMode": "bypassPermissions"' : '"skipDangerousModePermissionPrompt": true' });
  }
  for (const rule of asStringArray(perms?.allow) ?? []) {
    if (BROAD_BASH.has(rule.replace(/\s+/g, ''))) f.add('PERM-BROAD-ALLOW', 'high', { asset, location: doc.file, evidence: rule });
    else if (RISKY_BASH.test(rule)) f.add('PERM-BROAD-ALLOW', 'medium', { asset, location: doc.file, evidence: rule });
  }
  if (d.enableAllProjectMcpServers === true) {
    f.add('PERM-AUTO-PROJECT-MCP', 'medium', { asset, location: doc.file, evidence: '"enableAllProjectMcpServers": true' });
  }
  if (isObject(d.env)) {
    for (const k of ['ANTHROPIC_BASE_URL', 'OPENAI_BASE_URL', 'OPENAI_API_BASE', 'GOOGLE_GEMINI_BASE_URL', 'ANTHROPIC_BEDROCK_BASE_URL', 'ANTHROPIC_VERTEX_BASE_URL']) {
      const v = asString(d.env[k]);
      if (!v || isLocalHost(v) || /(^|\.)(anthropic\.com|openai\.com|googleapis\.com|amazonaws\.com)(\/|:|$)/.test(v.replace(/^https?:\/\//, ''))) continue;
      f.add('SETTINGS-API-REDIRECT', doc.scope === 'project' || doc.scope === 'local' ? 'critical' : 'medium', { asset, location: doc.file, evidence: `${k}=${redactUrl(v)}` });
    }
  }
  const wide = doc.scope === 'project' || doc.scope === 'local';
  if (isObject(d.env)) {
    for (const [k, raw] of Object.entries(d.env)) {
      const v = asString(raw);
      if (!v) continue;
      const evidence = `${k}=${redactUrl(v)}`;
      const loadsCode =
        /^(LD_PRELOAD|LD_AUDIT|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH|DYLD_FRAMEWORK_PATH|BASH_ENV|PYTHONSTARTUP)$/.test(k) ||
        (k === 'NODE_OPTIONS' && /(^|\s)(--require|-r|--import|--loader|--experimental-loader)(\s|=)/.test(v)) ||
        (/^(PERL5OPT|RUBYOPT)$/.test(k) && /(^|\s)-[rM]/.test(v));
      if (loadsCode) f.add('SETTINGS-ENV-INJECTION', wide ? 'critical' : 'high', { asset, location: doc.file, evidence });
      const proxy = /^(https?|all|ftp)_proxy$/i.test(k) && !isLocalHost(v);
      const tlsOff = k === 'NODE_TLS_REJECT_UNAUTHORIZED' && v === '0';
      const customCa = /^(NODE_EXTRA_CA_CERTS|SSL_CERT_FILE|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE)$/.test(k);
      if (proxy || tlsOff || customCa) f.add('SETTINGS-TRAFFIC-INTERCEPT', wide ? 'critical' : tlsOff ? 'high' : 'medium', { asset, location: doc.file, evidence });
    }
  }
  const home = /^(~|\$\{?HOME\}?|\/|\/Users|\/home|\/Users\/[^/]+|\/home\/[^/]+|[A-Za-z]:\\?(Users(\\[^\\]+)?)?)[\\/]*$/;
  const sensitive = /(^|[\\/])(\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config[\\/]gcloud|Library[\\/]Keychains)([\\/]|$)/;
  for (const dir of asStringArray(perms?.additionalDirectories) ?? []) {
    if (home.test(dir.trim()) || sensitive.test(dir)) f.add('PERM-BROAD-DIRS', wide ? 'high' : 'medium', { asset, location: doc.file, evidence: dir });
  }
  for (const key of ['env', 'userConfig', 'user_config']) {
    const rec = d[key];
    if (!isObject(rec)) continue;
    for (const [k, v] of Object.entries(rec)) {
      const s = asString(v);
      if (!s) continue;
      const why = classifySecret(k, s);
      if (why) f.add('SETTINGS-SECRET', 'high', { asset, location: doc.file, evidence: `${k}=${maskValue(s)}`, detail: `Detected: ${why}.` });
    }
  }
}

/* ---------------- Hooks ---------------- */

export const DOWNLOAD_EXEC = [
  /(curl|wget|fetch)\b[^|;&\n]*\|\s*(sudo\s+)?(ba|z)?sh\b/i,
  // …| python -c '…' / node -e '…' only processes the download as data.
  /(curl|wget)\b[^|;&\n]*\|\s*(python3?|node|ruby|perl)\b(?!\s+-[ce]\b)/i,
  /base64\s+(-d|--decode)[^|\n]*\|\s*(ba|z)?sh\b/i,
  /eval\s*["'(]?\s*\$\((curl|wget)/i,
  /\b(iex|Invoke-Expression)\b[^\n]*(iwr|Invoke-WebRequest|DownloadString)/i,
  /\beval\s*\(\s*(atob|Buffer\.from)\(/,
];

function checkHook(f: Findings, a: Asset) {
  const cmd = a.hook!.command;
  const loc = a.occurrences[0]?.source;
  if (a.hook!.event === 'folderOpen') {
    f.add('AUTORUN-TASK', DOWNLOAD_EXEC.some((re) => re.test(cmd)) ? 'critical' : 'high', { asset: a, location: loc, evidence: cmd });
  } else if (DOWNLOAD_EXEC.some((re) => re.test(cmd))) {
    f.add('CONTENT-DOWNLOAD-EXEC', 'high', { asset: a, location: loc, evidence: cmd });
  } else if (egressHooks.has(a)) {
    // Already reported as HOOK-DATA-EGRESS, with where the data goes.
  } else if (/\b(curl|wget|nc|ncat|netcat)\b|https?:\/\//.test(cmd)) {
    f.add('HOOK-NETWORK', 'high', { asset: a, location: loc, evidence: cmd });
  } else {
    f.add('HOOK-EXEC', 'low', { asset: a, location: loc, evidence: cmd });
  }
  if (findTokenPattern(cmd)) f.add('SETTINGS-SECRET', 'high', { asset: a, location: loc, evidence: cmd });
}

/* ---------------- Skills, agents, commands, instructions ---------------- */

export const INJECTION = [
  /\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding|system)\s+(instructions|prompts?|rules|messages)/i,
  /\bdo\s+not\s+(tell|inform|mention\s+(this\s+)?to|notify|alert|show)\s+the\s+user\b/i,
  /\bwithout\s+(telling|informing|notifying|asking)\s+the\s+user\b/i,
  /\b(hide|conceal)\s+(this|these|the)\s+(action|actions|step|steps|change|changes)\s+from\s+the\s+user\b/i,
  /\byou\s+are\s+no\s+longer\s+bound\s+by\b/i,
  /\breveal\s+(your|the)\s+system\s+prompt\b/i,
  /<\s*\/?\s*(system|important|admin)[-_ ]?(message|instructions?|override)?\s*>/i,
];

const TEXT_EXT = new Set(['', '.md', '.mdc', '.txt', '.py', '.js', '.mjs', '.cjs', '.ts', '.sh', '.bash', '.zsh', '.json', '.yaml', '.yml', '.toml', '.ps1', '.rb', '.pl', '.html']);

function contentFiles(a: Asset): string[] {
  if (!a.path) return [];
  if (a.kind === 'skill') return (a.skill?.files ?? []).filter((r) => TEXT_EXT.has(path.extname(r).toLowerCase())).map((r) => path.join(a.path!, r));
  return [a.path];
}

function lineOf(text: string, index: number): { line: number; text: string } {
  const start = text.lastIndexOf('\n', index) + 1;
  const end = text.indexOf('\n', index);
  return { line: text.slice(0, index).split('\n').length, text: text.slice(start, end === -1 ? undefined : end) };
}

function describeHidden(s: string): string {
  return showHidden(s);
}

/** The sentence shown under a hidden-character finding, including any message hidden in tag characters. */
export function hiddenDetail(h: HiddenScan): string {
  const msg = h.decoded.trim() ? ` The hidden message reads: “${redactText(h.decoded.trim()).slice(0, 160)}”.` : '';
  return `${describeScan(h)}${msg}`;
}

/** Name look-alikes, and the dependencies a skill ships. */
async function checkSkillSupply(f: Findings, a: Asset) {
  const display = a.name.replace(/@[^@]*$/, '');
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(display);
  const look = !uuid && (a.kind === 'skill' || a.kind === 'plugin') ? imitates(display, KNOWN_SKILLS) : undefined;
  if (look) f.add('TRUST-TYPOSQUAT-SKILL', 'medium', { asset: a, location: a.occurrences[0]?.source, evidence: `${display} ≈ ${look}` });
  if (a.kind !== 'skill' || !a.path) return;
  for (const rel of a.skill?.files ?? []) {
    const base = path.basename(rel);
    if (base !== 'requirements.txt' && base !== 'package.json') continue;
    const text = await readSmallText(path.join(a.path, rel));
    if (!text) continue;
    const py = base === 'requirements.txt';
    const deps: Dep[] = py ? parseRequirements(text) : parsePackageJson(text);
    const file = path.join(a.path, rel);
    for (const d of deps) {
      const fake = imitates(d.name, py ? KNOWN_PY : KNOWN_NPM, { minLength: 5 });
      if (fake) f.add('SKILL-DEP-TYPOSQUAT', 'medium', { asset: a, location: file, evidence: `${d.name} ≈ ${fake}` });
    }
    const loose = deps.filter(py ? isFloatingPy : isFloatingNpm);
    if (loose.length) {
      f.add('SKILL-DEP-UNPINNED', 'low', { asset: a, location: file, evidence: `${loose.length} of ${deps.length} not pinned: ${loose.slice(0, 4).map((d) => d.name).join(', ')}${loose.length > 4 ? '…' : ''}` });
    }
  }
}

/** Programs, bytecode and macro documents among a skill's files, recognised by content rather than name. */
async function checkBinaries(f: Findings, a: Asset) {
  if (!a.path) return;
  const hits = await findBinaries(a.path);
  hits.sort((x, y) => Number(y.disguised) - Number(x.disguised));
  for (const h of hits.slice(0, 5)) {
    const file = path.join(a.path, h.rel);
    f.add('SKILL-BINARY', h.disguised ? 'high' : 'medium', {
      asset: a,
      location: file,
      evidence: h.disguised ? `${h.rel} is really a ${h.format}` : `${h.rel}: ${h.format}`,
      title: h.disguised ? `${a.name}: a file is not what its name says` : `${a.name}: ships ${h.kind === 'machine-code' ? 'a program' : h.kind === 'bytecode' ? 'compiled code' : 'a macro document'} that cannot be read`,
    });
  }
  if (hits.length > 5) f.add('SKILL-BINARY', 'low', { asset: a, location: a.path, evidence: `${hits.length - 5} more compiled files not listed`, title: `${a.name}: more compiled files` });
}

async function checkContent(f: Findings, a: Asset) {
  const report = newReport();
  // The file the agent reads in full is the one that matters most; others (scripts, data) matter less.
  const main = (file: string) => a.kind !== 'skill' || /^skill\.md$/i.test(path.basename(file));
  if (a.kind === 'skill' && a.skill?.truncated) {
    f.add('CONTENT-NOT-INSPECTED', 'low', { asset: a, location: a.path, evidence: `Only the first ${SKILL_FILE_CAP} files of this skill were inspected.` });
  }
  for (const file of contentFiles(a)) {
    const { text: raw, skipped } = await readTextChecked(file);
    if (skipped) f.add('CONTENT-NOT-INSPECTED', main(file) ? 'medium' : 'low', { asset: a, location: file, evidence: skipped });
    if (!raw) continue;
    const text = raw.replace(/^\uFEFF/, ''); // a leading BOM is harmless
    const isCode = /\.(py|js|mjs|cjs|ts|sh|bash|zsh|ps1|rb|pl)$/i.test(file);
    const caps = analyzeFile(file, text, report);
    // Reading credential stores and talking to the network in the same file is the exfiltration shape.
    if (caps.has('credential-access') && caps.has('network')) {
      const m = CREDENTIAL_PATHS.map((re) => re.exec(text)).find(Boolean)!;
      const l = lineOf(text, m.index);
      f.add('SKILL-EXFIL-PATTERN', 'high', { asset: a, location: `${file}:${l.line}`, evidence: l.text });
    }
    const at = (idx: number) => {
      const l = lineOf(text, idx);
      return { location: `${file}:${l.line}`, evidence: l.text };
    };

    const hidden = scanHidden(text);
    if (hidden) {
      const l = at(hidden.index);
      // A decoded message that is itself an instruction, or a long hidden run, is the real thing; a lone zero-width character is a smell.
      const sev = hidden.strength === 'weak' ? 'medium' : INJECTION.some((re) => re.test(hidden.decoded)) || CREDENTIAL_PATHS.some((re) => re.test(hidden.decoded)) ? 'critical' : 'high';
      f.add('CONTENT-HIDDEN-UNICODE', sev, { asset: a, location: l.location, evidence: describeHidden(l.evidence), detail: hiddenDetail(hidden) });
    }
    if (!isCode) {
      for (const re of INJECTION) {
        const m = re.exec(text);
        if (m) f.add('CONTENT-PROMPT-INJECTION', 'medium', { asset: a, ...at(m.index) });
      }
    }
    for (const re of DOWNLOAD_EXEC) {
      const m = re.exec(text);
      if (m) f.add('CONTENT-DOWNLOAD-EXEC', 'high', { asset: a, ...at(m.index) });
    }
    for (const h of findHiddenInstructions(text, { prose: !isCode && /(\.(md|mdc|markdown|txt|html?)|(^|[\\/])[^.\\/]+)$/i.test(file) })) {
      f.add('CONTENT-HIDDEN-INSTRUCTION', h.kind === 'encoded' ? 'high' : 'medium', { asset: a, ...at(h.index), title: h.what });
    }
    for (const h of findPersistence(codeOnly(text, isCode, /\.(md|mdc)$/i.test(file)))) {
      f.add('CONTENT-PERSISTENCE', h.severity, { asset: a, ...at(h.index), title: `${a.name}: ${h.what}` });
    }
    for (const re of CREDENTIAL_PATHS) {
      const m = re.exec(text);
      if (m) {
        f.add('CONTENT-SENSITIVE-PATHS', 'medium', { asset: a, ...at(m.index) });
        break;
      }
    }
    const tok = findTokenPattern(text);
    if (tok) {
      const lines = text.split('\n');
      const idx = lines.findIndex((l) => findTokenPattern(l));
      f.add('CONTENT-SECRET', 'high', { asset: a, location: `${file}:${idx + 1}`, evidence: lines[idx] ?? '', detail: `Detected: ${tok}.` });
    }
  }

  const tools = a.skill?.allowedTools ?? [];
  const broad = tools.find((t) => BROAD_BASH.has(t.replace(/\s+/g, '')));
  if (broad) f.add('SKILL-UNRESTRICTED-TOOLS', 'medium', { asset: a, location: a.path, evidence: `allowed-tools: ${tools.join(', ')}` });

  for (const host of [...report.suspiciousHosts, ...report.rawIpHosts]) {
    f.add('SKILL-SUSPICIOUS-ENDPOINT', 'medium', { asset: a, location: a.path, evidence: host });
  }
  if (a.skill && a.kind !== 'instructions') {
    a.skill.capabilities = [...report.capabilities].sort();
    a.skill.domains = [...report.domains].sort().slice(0, 25);
  } else if (a.skill && report.domains.size) {
    a.skill.domains = [...report.domains].sort().slice(0, 25);
  }
}

/* ---------------- Known vulnerabilities ---------------- */

/** Explain, in plain words, why *this particular call* is affected. */
function describeCall(a: Asset, h: VulnHit): string {
  const pkg = a.mcp!.package!;
  const runner = pkg.runner ?? pkg.ecosystem;
  const parts: string[] = [];
  if (h.versionSource === 'pinned') parts.push(`This call pins ${pkg.name}@${h.version}, an affected version.`);
  else if (h.versionSource === 'installed')
    parts.push(`This call does not pin a version, and ${runner} has ${pkg.name}@${h.version} cached on disk; it can keep reusing that copy instead of updating.`);
  else if (h.versionSource === 'latest') parts.push(`This call does not pin a version; today it would fetch ${pkg.name}@${h.version} (the latest release), which is affected.`);
  else parts.push(`The version this call runs could not be determined${pkg.pinned ? '' : ' (not pinned, not cached locally)'}.`);
  if (h.fixedVersion) parts.push(`Fixed in ${h.fixedVersion}.`);
  const remote = a.mcp!.remoteUrl ?? a.mcp!.url;
  if (remote) parts.push(`It connects to ${redactUrl(remote)}; whoever controls that server is part of the attack surface.`);
  const where = [...new Set(a.occurrences.map((o) => o.source))];
  parts.push(`Configured in ${where.length === 1 ? where[0] : `${where.length} places`}.`);
  return parts.join(' ');
}

/* ---------------- Entry point ---------------- */

export async function runChecks(col: Collector, vulnHits: VulnHit[] = [], f = new Findings()): Promise<Finding[]> {
  const assets = [...col.assets.values()];
  const assetById = new Map(assets.map((a) => [a.id, a]));
  // Unconfirmed matches are one finding per package: a list of advisories to look at, not a wall of rows.
  const possible = new Map<string, VulnHit[]>();
  for (const h of vulnHits) if (!h.malicious && h.confidence === 'possible') possible.set(h.assetId, [...(possible.get(h.assetId) ?? []), h]);
  for (const [assetId, hits] of possible) {
    if (hits.length < 2) continue;
    const a = assetById.get(assetId);
    if (!a?.mcp) continue;
    const pkg = a.mcp.package!;
    const ver = hits[0].version !== 'any' ? `@${hits[0].version}` : '';
    const call = [a.mcp.command, ...(a.mcp.args ?? [])].filter(Boolean).join(' ');
    const shown = hits.slice(0, 8).map((h) => `${h.id}: ${h.summary.replace(/\s+/g, ' ').slice(0, 90)}${h.summary.length > 90 ? '…' : ''}`);
    f.add('VULN-POSSIBLE', 'low', {
      asset: a,
      location: a.occurrences[0]?.source,
      title: `Possibly related advisories: ${pkg.name}${ver}`,
      evidence: call,
      detail: `${hits.length} advisories mention a product with a similar name, and none could be confirmed for this package or version: ${shown.join(' · ')}${hits.length > shown.length ? ` · and ${hits.length - shown.length} more` : ''}. ${describeCall(a, hits[0])}`,
      references: hits.slice(0, 8).map((h) => `https://nvd.nist.gov/vuln/detail/${h.id}`),
      advisory: hits[0].id,
      remediation: `Skim the advisories and check whether any applies to ${pkg.name}${ver}; if one does and no fix exists, disable the server.`,
      vuln: { versionSource: hits[0].versionSource, version: hits[0].version, confidence: 'possible', sources: [...new Set(hits.flatMap((h) => h.sources ?? [h.source]))] },
    });
  }
  for (const h of vulnHits) {
    const a = assetById.get(h.assetId);
    if (!a?.mcp) continue;
    if (!h.malicious && h.confidence === 'possible' && (possible.get(h.assetId)?.length ?? 0) > 1) continue;
    const pkg = a.mcp.package!;
    const call = [a.mcp.command, ...(a.mcp.args ?? [])].filter(Boolean).join(' ');
    const target = upgradeTarget(h.fixedVersion, pkg.latestVersion);
    const fixCommand = !h.malicious && target ? pinnedCommand(a.mcp, target) : undefined;
    const rule = h.malicious ? 'VULN-MALICIOUS' : h.confidence === 'possible' ? 'VULN-POSSIBLE' : 'VULN-KNOWN';
    const ver = h.version !== 'any' ? `@${h.version}` : '';
    f.add(rule, h.malicious ? 'critical' : h.severity, {
      asset: a,
      location: a.occurrences[0]?.source,
      title: h.malicious
        ? `Malicious package: ${pkg.name}`
        : h.confidence === 'possible'
          ? `Possibly affected by ${h.id}: ${pkg.name}${ver}`
          : `${h.id} in ${pkg.name}${ver}`,
      evidence: call,
      detail: `${h.summary.replace(/\.?$/, '.')} ${describeCall(a, h)}`,
      references: h.references,
      advisory: h.id,
      remediation: h.malicious
        ? undefined
        : fixCommand
          ? `Change the call to: ${redactText(fixCommand)}`
          : h.fixedVersion
            ? `Upgrade ${pkg.name} to ${h.fixedVersion} or later and pin that version.`
            : h.confidence === 'possible'
              ? `Check the advisory to see whether it applies to ${pkg.name}${ver}; disable the server if it does and no fix exists.`
              : undefined,
      vuln: {
        cvss: h.cvss,
        versionSource: h.versionSource,
        version: h.version,
        fixedVersion: h.fixedVersion,
        fixCommand: fixCommand && redactText(fixCommand),
        confidence: h.confidence,
        sources: h.sources ?? [h.source],
        cwe: h.cwe?.length ? h.cwe : undefined,
      },
    });
  }
  for (const a of assets) {
    if (a.kind === 'mcp-server' && a.mcp) checkMcp(f, a, col.ctx.home);
    else if (a.kind === 'hook' && a.hook) checkHook(f, a);
    else if (['skill', 'agent', 'command', 'instructions'].includes(a.kind)) {
      await checkContent(f, a);
      if (a.kind === 'skill') {
        await checkSkillSupply(f, a);
        await checkBinaries(f, a);
      }
    } else if (a.kind === 'plugin') await checkSkillSupply(f, a);
    else if (a.kind === 'model' && a.model?.pickle) f.add('MODEL-PICKLE', 'medium', { asset: a, location: a.path, evidence: `${a.name}: ${a.model.format}` });
    else if (a.kind === 'api-key' && a.apiKey) {
      for (const o of a.occurrences) {
        const k = o.name.replace(/ \(line \d+\)$/, '');
        if (o.scope === 'project' && o.note?.startsWith('Not covered by .gitignore')) f.add('APIKEY-NOT-GITIGNORED', 'high', { asset: a, location: o.source, evidence: `${k}=${a.apiKey.masked}` });
        else if (o.scope === 'user') f.add('APIKEY-PLAINTEXT', 'low', { asset: a, location: o.source, evidence: `${k}=${a.apiKey.masked}` });
      }
    } else if (a.kind === 'browser-extension' && a.browserExtension?.allSites) {
      f.add('EXT-ALL-SITES', 'medium', { asset: a, location: a.occurrences[0]?.source, evidence: `${a.browserExtension.browser}: ${a.browserExtension.hostPermissions.slice(0, 3).join(', ')}` });
    } else if (a.kind === 'connector' && a.connector && !a.connector.detectedIn) {
      const last = Date.parse(a.connector.reviewedAt ?? a.connector.addedAt);
      const days = Math.floor((Date.now() - last) / 86_400_000);
      if (days >= REVIEW_DAYS) {
        f.add('CONNECTOR-REVIEW', 'low', { asset: a, location: a.occurrences[0]?.source, evidence: `${a.connector.platform} → ${a.name}: last reviewed ${days} days ago`, title: `Review ${a.name} on ${a.connector.platform}` });
      }
    }
  }
  const byFile = new Map<string, Asset>();
  for (const a of assets) if ((a.kind === 'extension' || a.kind === 'plugin') && a.occurrences[0]) byFile.set(a.occurrences[0].source, a);
  const byId = new Map(assets.map((a) => [a.id, a]));
  for (const doc of col.settings) checkSettings(f, doc, byFile, byId);

  return f.list.sort((x, y) => severityRank(x.severity) - severityRank(y.severity));
}

/**
 * Roll the worst active (not muted) severity up to each asset, then let
 * plugins/extensions inherit from what they bundle.
 */
export function rollupRisk(assets: Asset[], findings: Finding[]): void {
  const byId = new Map(assets.map((a) => [a.id, a]));
  const worse = (x: Severity | undefined, y: Severity) => (!x || severityRank(y) < severityRank(x) ? y : x);
  for (const a of assets) a.risk = undefined;
  for (const finding of findings) {
    if (finding.muted) continue;
    const a = finding.assetId ? byId.get(finding.assetId) : undefined;
    if (a) a.risk = worse(a.risk, finding.severity);
  }
  for (const a of assets) {
    for (const c of a.children ?? []) {
      const child = byId.get(c);
      if (child?.risk) a.risk = worse(a.risk, child.risk);
    }
  }
}
