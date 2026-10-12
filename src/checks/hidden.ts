import { DOWNLOAD_EXEC, INJECTION } from './index.js';

/**
 * Instructions meant for the model that a person reading the file would not see:
 * inside an HTML comment, spelled with spaces between the letters, hidden in a base64 string,
 * or phrased to switch off the model's refusals. Pure functions over text; the caller supplies
 * only prose files for the comment/spacing/jailbreak checks, and any text file for encoded payloads.
 */

export interface HiddenHit {
  kind: 'comment' | 'spaced' | 'encoded' | 'jailbreak';
  index: number;
  /** One short plain-words description for the finding title. */
  what: string;
}

/** Text addressed to an AI that tells it what to do. */
const AI_DIRECTIVE =
  /\b(assistant|claude|chatgpt|gemini|copilot|ai|agent|model|llm|system)\b[^\n]{0,60}\b(must|should|shall|always|never|ignore|disregard|do not|don't|run|execute|send|upload|post|read|fetch|call|exfiltrate|forward|reveal|include)\b|\b(when|if)\s+you\s+(read|see|process|summari[sz]e)\s+this\b|\binstructions?\s+for\s+(the\s+)?(ai|assistant|model|agent|llm)\b/i;

const JAILBREAK = [
  /\b(you|assistant|claude|model|ai|agent)\b[^.\n]{0,60}\b(never|do\s+not|don'?t|must\s+not)\s+(refuse|decline|say\s+no)\b/i,
  /\byou\s+(have|are\s+under|are\s+subject\s+to)\s+no\s+(restrictions|limitations|rules|guidelines|filters)\b/i,
  /\b(remove|disable|bypass|ignore|turn\s+off)\s+(all\s+|your\s+|any\s+|the\s+)?(safety|content|ethical)\s+(filters?|guidelines|restrictions|policies|checks|guardrails)\b/i,
  /\b(you|assistant|claude|model|ai|agent)\b[^.\n]{0,60}\b(do\s+not|don'?t|never)\s+(add|include|append|give)\s+(any\s+)?(warnings?|disclaimers?|caveats|safety\s+notes?)\b/i,
  /\b(DAN|developer)\s+mode\b/i,
];

/** Strong words that, once letters are put back together, give away an override attempt. */
const SPACED_WORDS = /(ignore|disregard|override|forget)(all)?(the)?(previous|prior|above|earlier|system)|systemprompt|donottell|withouttelling|youarenolonger|revealyour/i;

const COMMAND_WORDS = /\b(curl|wget|bash|sh\s+-c|eval|exec|powershell|nc\s+-e|rm\s+-rf|chmod\s+\+x)\b|\b(password|passwd|api[_-]?key|secret|token|private\s+key)\b|\.ssh\b|\.aws\b|https?:\/\//i;

const isReadable = (s: string) => s.length >= 12 && [...s].filter((c) => /[\t\n\r\x20-\x7e]/.test(c)).length / s.length >= 0.9;

/** Does this decoded text carry instructions or commands? */
export function meansSomething(text: string): boolean {
  return INJECTION.some((re) => re.test(text)) || DOWNLOAD_EXEC.some((re) => re.test(text)) || AI_DIRECTIVE.test(text) || COMMAND_WORDS.test(text) || JAILBREAK.some((re) => re.test(text));
}

export function findHiddenInstructions(text: string, opts: { prose: boolean }): HiddenHit[] {
  const hits: HiddenHit[] = [];

  if (opts.prose) {
    // <!-- … --> is invisible when the Markdown is rendered, but the model reads every character.
    for (const m of text.matchAll(/<!--([\s\S]*?)-->/g)) {
      const body = m[1].trim();
      if (body.length >= 15 && (INJECTION.some((re) => re.test(body)) || AI_DIRECTIVE.test(body) || JAILBREAK.some((re) => re.test(body)))) {
        hits.push({ kind: 'comment', index: m.index!, what: 'Instructions hidden in a comment' });
      }
    }
    // "i g n o r e  a l l  p r e v i o u s": single letters separated by one space, eight or more in a row.
    for (const m of text.matchAll(/(?<![A-Za-z])(?:[A-Za-z] ){7,}[A-Za-z](?![A-Za-z])/g)) {
      if (SPACED_WORDS.test(m[0].replace(/\s+/g, ''))) hits.push({ kind: 'spaced', index: m.index!, what: 'Instructions spelled out letter by letter' });
    }
    for (const re of JAILBREAK) {
      const m = re.exec(text);
      if (m) {
        hits.push({ kind: 'jailbreak', index: m.index, what: 'Tries to switch off the model\'s safety behaviour' });
        break;
      }
    }
  }

  // Base64 that decodes to readable instructions or commands: in prose, code, or a data: URI.
  let seen = 0;
  for (const m of text.matchAll(/(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g)) {
    if (++seen > 50) break;
    let decoded: string;
    try {
      decoded = Buffer.from(m[0], 'base64').toString('utf8');
    } catch {
      continue;
    }
    if (isReadable(decoded) && meansSomething(decoded)) hits.push({ kind: 'encoded', index: m.index!, what: 'Instructions or commands hidden in encoded text' });
  }
  return hits;
}
