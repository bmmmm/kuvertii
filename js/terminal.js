// Findings → text for a terminal. The second renderer over the same analysis
// the page uses; nothing here decides what is reported, only how it reads.

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
const URL_RE = /\b(?:https?|ftps?):\/\/[^\s<>"'`]+/i;
const EMAIL_RE = /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/i;
const BARE_HOST_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;

// One capturing split, so URLs and addresses land in segments of their own and
// the hostname pass only ever sees the text between them.
const SPLIT_RE = new RegExp(`(${URL_RE.source}|${EMAIL_RE.source})`, 'gi');
const URL_START_RE = /^(?:https?|ftps?):\/\//i;

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
  const parts = String(text ?? '').split(SPLIT_RE);

  return parts
    .map((part) => {
      if (!part) return part;
      if (URL_START_RE.test(part)) return defangUrl(part);
      if (EMAIL_RE.test(part)) return part;
      return part.replace(BARE_HOST_RE, (host) => host.replace(/\./g, '[.]'));
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
const LEVEL_COLOUR = { bad: ANSI.red, good: ANSI.green, caution: ANSI.yellow };

/**
 * Build a renderer.
 *
 * Colour is opt-out through NO_COLOR and off by default when stdout is not a
 * terminal, so piping into a file or a pager yields plain text.
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
    const marker = item.emphasis || item.level ? '▸' : '·';

    // Labels are defanged as well, which is not decoration: a blocklist verdict
    // puts the offending hostname in the label — `evil.example is on a phishing
    // blocklist` — so leaving labels alone published a live link for precisely
    // the domain the reader has just been warned about.
    out.push(`  ${paint(colourFor || ANSI.bold, `${marker} ${defang(item.label)}`)}`);

    // Mono values are structural — an id, a route, a decoded payload — and are
    // printed verbatim rather than wrapped, since folding them invents breaks.
    const value = defang(item.value);
    if (item.mono) {
      for (const line of String(value).split('\n')) out.push(`    ${paint(ANSI.dim, line)}`);
    } else {
      out.push(...wrap(value, 4));
    }

    if (item.chips?.length) {
      // Chips wrap as a group. A row can carry four of them naming a header
      // and a decode method each, which is well past any terminal width.
      const rendered = item.chips.map((chip) => `[${defang(chip)}]`).join(' ');
      out.push(...wrapPainted(rendered, ANSI.dim, 4));
    }

    if (item.note && !seenNotes.has(item.note)) {
      seenNotes.add(item.note);
      out.push(...wrapPainted(defang(item.note), ANSI.dim, 4));
    }
    return out;
  };

  const renderFinding = (finding) => {
    const out = [''];
    // Titles and ledes are written by hand today, but they are the last two
    // places a hostname could reach the screen unbroken. Defanged too, so the
    // guarantee holds for the whole card rather than for the fields that
    // happened to carry data when this was written.
    out.push(paint(TONE_COLOUR[finding.tone] ?? '', paint(ANSI.bold, defang(finding.title))));
    if (finding.lede) out.push(...wrapPainted(defang(finding.lede), ANSI.dim));
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
