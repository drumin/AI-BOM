/**
 * Invisible-character detection for text a model will read.
 *
 * Strong signals (almost never legitimate in prose or config):
 *   - Unicode Tag characters (U+E0020..E007E), "ASCII smuggling": each one renders as nothing but
 *     decodes to an ASCII letter, so a whole instruction can hide in plain sight. We decode it.
 *   - bidi overrides and embeddings (U+202A..202E), the "Trojan Source" class.
 *   - a long run of zero-width characters (they can encode binary data).
 * Weak signal:
 *   - a lone zero-width character in Latin text. Zero-width joiners hold emoji together, and zero-width
 *     spaces and non-joiners are required by Thai, Khmer, Persian and Indic scripts, so those are ignored.
 * Ignored on their own: isolates (U+2066..2069, the recommended way to mix left-to-right and right-to-left
 * text), variation selectors, and a byte-order mark at the start.
 *
 * Also recognized in their escaped text form (‮, \U000e0041, &#x202E;), which is how they appear in
 * raw JSON, Python and HTML sources.
 */

export interface HiddenScan {
  strength: 'strong' | 'weak';
  /** Index of the first suspicious character. */
  index: number;
  /** Suspicious characters found (escaped forms count too). */
  count: number;
  tag: number;
  override: number;
  embed: number;
  zeroWidth: number;
  /** Seen only as escaped text (for example inside a JSON string), not as the real character. */
  escaped: boolean;
  /** ASCII hidden in Tag characters, decoded. */
  decoded: string;
  codepoints: string[];
  /** The first suspicious character, as U+XXXX. */
  first: string;
}

const TAG_PRINTABLE = (cp: number) => cp >= 0xe0020 && cp <= 0xe007e;
const TAG_ANY = (cp: number) => cp >= 0xe0000 && cp <= 0xe007f;
const OVERRIDE = (cp: number) => cp === 0x202d || cp === 0x202e;
const EMBED = (cp: number) => cp >= 0x202a && cp <= 0x202c;
const ZERO_WIDTH = (cp: number) => (cp >= 0x200b && cp <= 0x200d) || (cp >= 0x2060 && cp <= 0x2064) || cp === 0x180e || cp === 0xfeff;
const RUN_IS_STEGANOGRAPHY = 8;

const EMOJI = /[\p{Extended_Pictographic}\p{Emoji_Modifier}\u{FE0F}\u{20E3}\u{1F1E6}-\u{1F1FF}]/u;
const COMPLEX_SCRIPT = /[\p{Script=Thai}\p{Script=Lao}\p{Script=Khmer}\p{Script=Myanmar}\p{Script=Arabic}\p{Script=Hebrew}\p{Script=Devanagari}\p{Script=Bengali}\p{Script=Gurmukhi}\p{Script=Gujarati}\p{Script=Oriya}\p{Script=Tamil}\p{Script=Telugu}\p{Script=Kannada}\p{Script=Malayalam}\p{Script=Sinhala}\p{Script=Tibetan}\p{Script=Mongolian}]/u;

const ESCAPED = [
  { re: /\\u(202[a-eA-E])/g, kind: 'bidi' as const, cp: (m: RegExpExecArray) => parseInt(m[1], 16) },
  { re: /&#x(202[a-eA-E]);/g, kind: 'bidi' as const, cp: (m: RegExpExecArray) => parseInt(m[1], 16) },
  { re: /&#(820[2-6]);/g, kind: 'bidi' as const, cp: (m: RegExpExecArray) => parseInt(m[1], 10) },
  { re: /\\U000[eE]00([2-6][0-9a-fA-F]|7[0-9a-eA-E])/g, kind: 'tag' as const, cp: (m: RegExpExecArray) => 0xe0000 + parseInt(m[1], 16) },
  { re: /\\u\{[eE]00([2-6][0-9a-fA-F]|7[0-9a-eA-E])\}/g, kind: 'tag' as const, cp: (m: RegExpExecArray) => 0xe0000 + parseInt(m[1], 16) },
];

type Kind = 'tag' | 'override' | 'embed' | 'zw';

/** Which kind of suspicious invisible character `chars[i]` is, if any. */
function classify(chars: string[], i: number): Kind | undefined {
  const cp = chars[i].codePointAt(0)!;
  if (TAG_ANY(cp)) return 'tag';
  if (OVERRIDE(cp)) return 'override';
  if (EMBED(cp)) return 'embed';
  if (!ZERO_WIDTH(cp)) return undefined;
  if (cp === 0xfeff && i === 0) return undefined;
  const near = [chars[i - 1], chars[i + 1]].filter((c): c is string => !!c);
  // Joiners hold emoji sequences together; spaces and non-joiners are part of several scripts.
  if (cp <= 0x200d && cp >= 0x200b && near.some((c) => EMOJI.test(c) || COMPLEX_SCRIPT.test(c))) return undefined;
  if (near.some((c) => COMPLEX_SCRIPT.test(c)) && cp !== 0xfeff) return undefined;
  return 'zw';
}

const hex = (cp: number) => `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;

export function scanHidden(text: string): HiddenScan | undefined {
  const chars = [...text];
  let offset = 0;
  const scan: HiddenScan = { strength: 'weak', index: -1, count: 0, tag: 0, override: 0, embed: 0, zeroWidth: 0, escaped: false, decoded: '', codepoints: [], first: '' };
  const seen = new Set<string>();
  let run = 0;
  let longestRun = 0;
  const note = (at: number, cp: number) => {
    if (scan.index < 0 || at < scan.index) {
      scan.index = at;
      scan.first = hex(cp);
    }
    seen.add(hex(cp));
    scan.count++;
  };
  for (let i = 0; i < chars.length; i++) {
    const k = classify(chars, i);
    const cp = chars[i].codePointAt(0)!;
    if (k) {
      note(offset, cp);
      if (k === 'tag') {
        scan.tag++;
        if (TAG_PRINTABLE(cp)) scan.decoded += String.fromCharCode(cp - 0xe0000);
      } else if (k === 'override') scan.override++;
      else if (k === 'embed') scan.embed++;
      else scan.zeroWidth++;
    }
    // Any invisible character in a row counts toward the steganography heuristic, joiners included.
    if (ZERO_WIDTH(cp) && !(cp === 0xfeff && i === 0)) {
      run++;
      longestRun = Math.max(longestRun, run);
    } else run = 0;
    offset += chars[i].length;
  }
  let escapedOnly = scan.count === 0;
  for (const e of ESCAPED) {
    for (const m of text.matchAll(e.re)) {
      const cp = e.cp(m as RegExpExecArray);
      note(m.index ?? 0, cp);
      if (e.kind === 'tag') {
        scan.tag++;
        if (TAG_PRINTABLE(cp)) scan.decoded += String.fromCharCode(cp - 0xe0000);
      } else if (OVERRIDE(cp)) scan.override++;
      else scan.embed++;
    }
  }
  if (scan.count === 0) return undefined;
  scan.escaped = escapedOnly;
  scan.codepoints = [...seen].sort();
  scan.strength = scan.tag || scan.override || scan.embed || longestRun >= RUN_IS_STEGANOGRAPHY ? 'strong' : 'weak';
  return scan;
}

/** Show suspicious invisible characters as [U+XXXX]; leave legitimate ones (emoji joiners, Thai spaces) alone. */
export function showHidden(text: string): string {
  const chars = [...text];
  return chars.map((c, i) => (classify(chars, i) ? `[${hex(c.codePointAt(0)!)}]` : c)).join('');
}

/** One plain sentence describing what was found, for a finding's detail. */
export function describeScan(s: HiddenScan): string {
  const parts = [
    s.tag && `${s.tag} Unicode tag character${s.tag === 1 ? '' : 's'} (text that renders as nothing)`,
    s.override && `${s.override} right-to-left override${s.override === 1 ? '' : 's'}`,
    s.embed && `${s.embed} text-direction embedding${s.embed === 1 ? '' : 's'}`,
    s.zeroWidth && `${s.zeroWidth} zero-width character${s.zeroWidth === 1 ? '' : 's'}`,
  ].filter(Boolean);
  const how = s.escaped ? ' written as escape codes in the text' : '';
  return `Found ${parts.join(', ')}${how}.`;
}
