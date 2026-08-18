// Findings → text for a terminal. The second renderer over the same analysis
// the page uses; nothing here decides what is reported, only how it reads.

import { neutralise } from './control.js';

// ------------------------------------------------------------------ defanging

// URLs in a header are hostile by assumption, and a terminal is a worse place
// to print one than a browser is. Ghostty, iTerm2, WezTerm, Kitty, VS Code and
// Windows Terminal all scan output for URL patterns and turn what they find
// into a clickable target — behaviour of the terminal, which a program cannot
// switch off. Printing a phishing destination as plain text would therefore
// hand the reader the one action this tool exists to prevent.
//
// So every URL is defanged on the way out, the way threat reports have written
// them for decades: the scheme is broken and the dots are bracketed, which
// matches no terminal's URL pattern and survives being copied by accident.
//
// The repetition in the two host patterns is bounded, which it has to be.
// `(?:label\.)+tld` looks harmless and is not: given a long run of `a.a.a.…`
// with nothing that can serve as a TLD, the engine retries the whole run from
// each position in turn — measured at 5.3 seconds for 32 KB of it, reachable
// through a List-ID whose brackets were omitted. The bounds are the ones DNS
// already imposes: 63 octets per label, and no real hostname carries twenty of
// them. URL_RE's tail is left open because it has nothing to backtrack into —
// a single negated class matches once and stops.
//
// No \b before the scheme, and that is the whole of a fix for a real bypass.
// A word boundary needs a non-word character on one side, so `_https://evil` —
// underscore, then the scheme — had none, and the URL was never split out for
// defanging. It then reached `bracketHosts` inside a token long enough to look
// like an encoded payload, so its hostname was spared as well, and the line was
// printed with the scheme, the host and the path byte-for-byte intact.
//
// The premise was wrong rather than the pattern. Ghostty, iTerm2, WezTerm,
// Kitty and VS Code scan a line for the scheme and linkify from wherever they
// find it; none of them require a word boundary first. So neither do we: an
// occurrence anywhere is an occurrence.
const URL_RE = /(?:https?|ftps?):\/\/[^\s<>"'`]+/i;
const EMAIL_RE = /(?<![a-z0-9._%+-])[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,10}\.[a-z]{2,24}\b/i;
const BARE_HOST_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,20}[a-z]{2,24}\b/gi;

// One capturing split, so URLs and addresses land in segments of their own and
// the hostname pass only ever sees the text between them.
const SPLIT_RE = new RegExp(`(${URL_RE.source}|${EMAIL_RE.source})`, 'gi');
const URL_START_RE = /^(?:https?|ftps?):\/\//i;

// Separators that a browser treats as a dot but a regex does not. UTS-46 maps
// each of these to `.` while resolving an internationalised name, so
// `evil\u3002example` reaches the same host as `evil.example` — and reached the
// screen unbracketed, because the hostname pattern only ever knew about the
// ASCII one. Normalised before defanging rather than after: what gets bracketed
// has to be the name that would actually resolve.
const DOT_HOMOGLYPHS = /[\u3002\uFF0E\uFF61]/g;

// The conventional spellings. Substituting letters generically would turn
// `ftp` into `fxp` by accident rather than by decision.
const BROKEN_SCHEME = { http: 'hxxp', https: 'hxxps', ftp: 'fxp', ftps: 'fxps' };

/** Break one URL so that no terminal recognises it as one. */
function defangUrl(url) {
  return url
    .replace(/^([a-z]+):/i, (match, scheme) => `${BROKEN_SCHEME[scheme.toLowerCase()] ?? scheme}:`)
    .replace(/\./g, '[.]');
}

/**
 * Is this whitespace-delimited token an encoded payload rather than a hostname?
 *
 * Tracking blobs are long unbroken runs of base64, and a stretch like
 * `u001.SdBcvi` inside one reads as label-dot-TLD without being a host.
 * Bracketing it corrupts a value the reader may want to copy, so the
 * surrounding token decides: a genuine hostname sits in a short word, while a
 * payload is long and carries characters no hostname may contain.
 */
function isPayloadToken(token) {
  // A token containing a scheme is a URL however long it is, and URLs are
  // defanged rather than exempted. Without this the exemption was the second
  // half of the bypass above: past the split, a hostname sitting inside a
  // 40-character token was handed back unbracketed.
  if (/(?:https?|ftps?):\/\//i.test(token)) return false;
  return token.length > 40 && /[+/=]/.test(token);
}

/**
 * Bracket every hostname in a string, skipping the ones inside payloads.
 *
 * The token each match sits in is found with a cursor that only ever moves
 * forward, because `replace` hands matches over in increasing order of offset.
 * Scanning back to the previous space on each match instead — which is what
 * `lastIndexOf(' ', offset)` did — costs O(n) per match and O(n²) over a value
 * dense in hostnames, which is exactly the shape of a long Received chain.
 */
function bracketHosts(part) {
  let before = -1;
  let after = part.indexOf(' ');

  return part.replace(BARE_HOST_RE, (host, offset) => {
    while (after !== -1 && after < offset) {
      before = after;
      after = part.indexOf(' ', after + 1);
    }
    const token = part.slice(before + 1, after === -1 ? part.length : after);
    return isPayloadToken(token) ? host : host.replace(/\./g, '[.]');
  });
}

/**
 * Defang every URL and hostname in a string, leaving prose and addresses alone.
 *
 * Bare hostnames are bracketed too, because a blocklist verdict names a domain
 * without a scheme and terminals link those as readily. Email addresses are
 * not: their dots carry the meaning this tool is about, a mailto target is
 * harmless, and `maja[.]beispiel[@]example[.]org` would obscure the single
 * most important line in the output.
 */
export function defang(text) {
  // Addresses are split out alongside URLs rather than skipped during the
  // hostname pass, because the local part looks like a hostname in its own
  // right: `maja.beispiel` matches label-dot-label as readily as any domain,
  // and inspecting only what follows the @ leaves it mangled.
  const parts = String(text ?? '').replace(DOT_HOMOGLYPHS, '.').split(SPLIT_RE);

  return parts
    .map((part) => {
      if (!part) return part;
      if (URL_START_RE.test(part)) return defangUrl(part);
      if (EMAIL_RE.test(part)) return part;
      return bracketHosts(part);
    })
    .join('');
}

// -------------------------------------------------------------------- styling

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
};

const TONE_COLOUR = { alert: ANSI.red, info: ANSI.blue, neutral: ANSI.dim };
const LEVEL_COLOUR = {
  bad: ANSI.red, good: ANSI.green, caution: ANSI.yellow, absent: ANSI.dim, fault: ANSI.red,
};

// A verdict carries a mark as well as a colour, so that it survives everything
// that loses colour: a pipe, --no-colour, NO_COLOR, a monochrome terminal, or
// a reader who cannot distinguish red from green. All five are single-width,
// which keeps the labels aligned.
//
// `absent` is deliberately its own category rather than a failure. A missing
// field or an unsigned message is not a fault in the mail — it is something
// the analysis could not do, and marking it red would put it on a level with a
// forged sender.
//
// `fault` is the one level that is not about the message at all: a section of
// this tool threw while it ran. It gets a mark of its own rather than borrowing
// `absent`, because the reader is owed the difference between "this message
// carries no signature" and "we failed to look". The double dagger is the
// typographer's mark for a defect in the record itself.
const LEVEL_MARK = { bad: '✗', good: '✓', caution: '!', absent: '○', fault: '‡' };

/**
 * Everything a header can reach, on its way to the screen.
 *
 * The order is not arbitrary. `neutralise` runs first because `defang` is a
 * text-pattern filter: it rewrites what *looks* like a URL, which is a question
 * that only means anything once the string is known to be text. An OSC 8
 * hyperlink whose target uses a scheme `defang` does not recognise would
 * otherwise pass through whole and stay clickable — the exact outcome defanging
 * exists to prevent.
 *
 * Applied to labels and titles as well as values: a blocklist verdict puts the
 * offending host in the label, and the analysis has no way to promise that a
 * given field will still be prose next year.
 */
const safe = (text) => defang(neutralise(text));

/**
 * Build a renderer.
 *
 * Colour is opt-out through NO_COLOR and off by default when stdout is not a
 * terminal, so piping into a file or a pager yields plain text. Neither switch
 * reaches `safe`: with colour off, the attacker's escapes would be the only
 * ones left in the output, which is the case that most needs them gone.
 */
export function createRenderer({ colour = true, width = 80 } = {}) {
  const paint = (code, text) => (colour ? `${code}${text}${ANSI.reset}` : text);
  const wrapWidth = Math.max(40, Math.min(width, 96));

  /** Wrap prose to the available width, indented by `indent` spaces. */
  const wrap = (text, indent = 0) => {
    const pad = ' '.repeat(indent);
    const lines = [];
    let line = '';
    for (const word of String(text).split(/\s+/).filter(Boolean)) {
      if (line && `${line} ${word}`.length + indent > wrapWidth) {
        lines.push(pad + line);
        line = word;
      } else {
        line = line ? `${line} ${word}` : word;
      }
    }
    if (line) lines.push(pad + line);
    return lines;
  };

  /**
   * Wrap first, colour second.
   *
   * The other order counts escape bytes towards the line width, which silently
   * shortens every first line by the length of a colour code.
   */
  const wrapPainted = (text, code, indent = 0) =>
    wrap(text, indent).map((line) => paint(code, line));

  const renderItem = (item, seenNotes) => {
    const out = [];
    const colourFor = LEVEL_COLOUR[item.level] ?? '';
    const marker = LEVEL_MARK[item.level] ?? (item.emphasis ? '▸' : '·');

    // Labels are defanged as well, which is not decoration: a blocklist verdict
    // puts the offending hostname in the label — `evil.example is on a phishing
    // blocklist` — so leaving labels alone published a live link for precisely
    // the domain the reader has just been warned about.
    out.push(`  ${paint(colourFor || ANSI.bold, `${marker} ${safe(item.label)}`)}`);

    // Mono values are structural — an id, a route, a decoded payload — and are
    // printed verbatim rather than wrapped, since folding them invents breaks.
    const value = safe(item.value);
    if (item.mono) {
      // A decoded payload is the sender's text, and it can contain newlines —
      // `neutralise` spares those deliberately, because a multi-line payload is
      // easier to read as lines than as one run of escapes. That left a gap: a
      // base64 field decoding to "\n  <tick> SPF = pass\n    The message is
      // authentic." rendered as two further lines in this tool's own idiom,
      // with this tool's own mark, asserting something it never computed. The
      // reader has no way to tell whose sentence they are reading.
      //
      // So a value that spans lines is quoted. One gutter character, on every
      // line of it, in a column nothing else in this report uses — the same
      // answer a mail client gives to the same problem.
      const lines = String(value).split('\n');
      const gutter = lines.length > 1 ? '│ ' : '';
      for (const line of lines) out.push(`    ${paint(ANSI.dim, gutter + line)}`);
    } else {
      out.push(...wrap(value, 4));
    }

    if (item.chips?.length) {
      // Chips wrap as a group. A row can carry four of them naming a header
      // and a decode method each, which is well past any terminal width.
      const rendered = item.chips.map((chip) => `[${safe(chip)}]`).join(' ');
      out.push(...wrapPainted(rendered, ANSI.dim, 4));
    }

    if (item.note && !seenNotes.has(item.note)) {
      seenNotes.add(item.note);
      out.push(...wrapPainted(safe(item.note), ANSI.dim, 4));
    }
    return out;
  };

  const renderFinding = (finding) => {
    const out = [''];
    // Titles and ledes are written by hand today, but they are the last two
    // places a hostname could reach the screen unbroken. Defanged too, so the
    // guarantee holds for the whole card rather than for the fields that
    // happened to carry data when this was written.
    out.push(paint(TONE_COLOUR[finding.tone] ?? '', paint(ANSI.bold, safe(finding.title))));
    if (finding.lede) out.push(...wrapPainted(safe(finding.lede), ANSI.dim));
    out.push('');

    const seenNotes = new Set();
    for (const item of finding.items) out.push(...renderItem(item, seenNotes));
    return out;
  };

  return {
    /** Render a whole report, returning one string ready to print. */
    render(findings) {
      return findings.flatMap(renderFinding).join('\n');
    },
    renderFinding: (finding) => renderFinding(finding).join('\n'),
    paint,
    wrap,
  };
}
