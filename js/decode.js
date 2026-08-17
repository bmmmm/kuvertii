// Decoder chain for obfuscated header values.
//
// Bulk mailers rarely encrypt — they encode, and assume nobody looks. The point
// of this module is to look: try a handful of cheap transforms and keep only
// the results that turn into something a human can read.

const EMAIL_RE = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;
const DOMAIN_RE = /\b[A-Z0-9-]+\.(?:[A-Z]{2,}\.)?[A-Z]{2,}\b/i;
const WORD_RE = /[A-Za-z]{4,}/;

// Reversed text is still a syntactically valid address — `gro.elpmaxe@…` parses
// exactly as well as `…@example.org`. A short list of real TLDs is what breaks
// the tie and tells us which way round we are holding the string.
const COMMON_TLDS = new Set([
  'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'name',
  'de', 'uk', 'fr', 'it', 'es', 'nl', 'be', 'at', 'ch', 'se', 'no', 'dk', 'fi',
  'pl', 'cz', 'pt', 'gr', 'ie', 'ru', 'ua', 'tr', 'jp', 'cn', 'kr', 'in', 'au',
  'nz', 'ca', 'br', 'mx', 'ar', 'za', 'il', 'eu', 'us', 'io', 'co', 'me', 'tv',
  'email', 'app', 'dev', 'cloud', 'online', 'site', 'shop', 'store', 'blog',
  'news', 'live', 'club', 'xyz', 'top', 'digital', 'agency', 'systems',
]);

/** Does this text contain an address or domain ending in a TLD that exists? */
function hasKnownTld(text) {
  const matches = String(text).match(/\.([A-Za-z]{2,12})\b/g) ?? [];
  return matches.some((m) => COMMON_TLDS.has(m.slice(1).toLowerCase()));
}

/** Reverse a string. Named for what it means here, not for what it does. */
const reverse = (s) => [...s].reverse().join('');

/** Decode base64 to a UTF-8 string, tolerating urlsafe alphabet and lost padding. */
function fromBase64(input) {
  const cleaned = String(input).replace(/[\s\r\n]+/g, '');
  if (cleaned.length < 4 || /[^A-Za-z0-9+/\-_=]/.test(cleaned)) return null;
  const normalised = cleaned.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  // A length of 4n+1 cannot come from base64 — bail rather than let atob throw.
  if (normalised.length % 4 === 1) return null;
  const padded = normalised + '='.repeat((4 - (normalised.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch {
    return null;
  }
}

/**
 * How much does this look like information rather than noise?
 *
 * Returns 0..1. Crypto blobs (X-Mantsh, X-Jnj) decode to high-entropy bytes and
 * score near zero; a VERP token carrying an address scores near one. NUL bytes
 * are common as field separators inside these tokens, so they are not penalised.
 */
export function readability(text) {
  if (!text) return 0;
  const chars = [...text];
  const printable = chars.filter((c) => {
    const code = c.codePointAt(0);
    return c === '\0' || code === 9 || code === 10 || (code >= 32 && code !== 127);
  }).length;
  const ratio = printable / chars.length;
  if (ratio < 0.85) return 0;

  // Weights sum to exactly 1.0 so nothing is lost to clamping — the reversed
  // and forward readings of an address differ only in the TLD term, and if the
  // total saturated first, the two would score identically.
  let score = ratio * 0.4;
  if (EMAIL_RE.test(text)) score += 0.3;
  else if (DOMAIN_RE.test(text)) score += 0.15;
  if (WORD_RE.test(text)) score += 0.15;
  if (hasKnownTld(text)) score += 0.15;
  return Math.min(score, 1);
}

/**
 * Run the decoder chain over one value.
 *
 * Returns candidates sorted by readability, each {text, method, score}. Callers
 * decide what threshold is worth showing; nothing here is filtered away except
 * results that failed to decode at all.
 */
export function decodeCandidates(value) {
  const raw = String(value ?? '').trim();
  if (raw.length < 8) return [];
  const out = [];
  const seen = new Set();

  const offer = (text, method) => {
    if (!text || seen.has(text)) return;
    seen.add(text);
    const score = readability(text);
    if (score > 0) out.push({ text, method, score });
  };

  // Both orientations are always offered. Which one is right cannot be decided
  // from a single segment — `newsletter` and `rettelswen` are equally wordlike
  // without a dictionary — so the choice is left to decodeSegments, which can
  // see the whole field.
  const plain = fromBase64(raw);
  if (plain !== null) {
    offer(plain, 'base64');
    // GreenArrow and friends store the plaintext backwards inside a backwards
    // base64 string — decoding once leaves you with `gro.elpmaxe@ecila`.
    offer(reverse(plain), 'base64, content reversed');
  }

  const reversedInput = fromBase64(reverse(raw));
  if (reversedInput !== null) {
    offer(reversedInput, 'reversed base64');
    offer(reverse(reversedInput), 'reversed base64, content reversed');
  }

  // Quoted-printable and RFC 2047 encoded-words: what mail clients already
  // render, but header dumps show raw.
  if (/=\?[^?]+\?[BQbq]\?/.test(raw)) {
    offer(decodeEncodedWords(raw), 'RFC 2047 encoded-word');
  } else if (/=[0-9A-F]{2}/i.test(raw)) {
    offer(decodeQuotedPrintable(raw), 'quoted-printable');
  }

  if (/^(?:[0-9a-f]{2}){6,}$/i.test(raw)) {
    const bytes = raw.match(/../g).map((h) => parseInt(h, 16));
    offer(new TextDecoder('utf-8', { fatal: false }).decode(Uint8Array.from(bytes)), 'hex');
  }

  return out.sort((a, b) => b.score - a.score);
}

/**
 * Decode a value and each of its parts.
 *
 * Composite fields are the norm: `X-Mailer-Info` is dot-separated, its Extra
 * sibling is `id:segment segment`. Handing the whole string to the decoder gets
 * nowhere, because the separators are not part of any base64 alphabet — each
 * piece has to be tried on its own.
 */
export function decodeSegments(value, threshold = 0.5) {
  const pieces = [
    String(value ?? ''),
    ...String(value ?? '').split(/[\s.:;,<>"'()[\]]+/).filter((s) => s.length >= 8),
  ];

  const perPiece = pieces
    .map((piece) => decodeCandidates(piece).filter((c) => c.score >= threshold))
    .filter((candidates) => candidates.length);

  // One segment usually decodes unambiguously — an address settles its own
  // orientation, because only one reading ends in a real TLD. Whichever method
  // wins there is applied to its siblings, which on their own are a coin flip.
  const dominant = perPiece.flat().sort((a, b) => b.score - a.score)[0]?.method;

  const results = [];
  const seen = new Set();
  for (const candidates of perPiece) {
    const pick = candidates.find((c) => c.method === dominant) ?? candidates[0];
    if (seen.has(pick.text)) continue;
    seen.add(pick.text);
    results.push(pick);
  }
  return results.sort((a, b) => b.score - a.score);
}

/** Best decode for a value, or null when nothing readable came out. */
export function bestDecode(value, threshold = 0.5) {
  const [top] = decodeCandidates(value);
  return top && top.score >= threshold ? top : null;
}

export function decodeQuotedPrintable(text) {
  return String(text)
    .replace(/=\r?\n/g, '')
    .replace(/=([0-9A-F]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

export function decodeEncodedWords(text) {
  return String(text).replace(
    /=\?([^?]+)\?([BQbq])\?([^?]*)\?=/g,
    (whole, charset, encoding, payload) => {
      try {
        const bytes =
          encoding.toUpperCase() === 'B'
            ? Uint8Array.from(atob(payload), (c) => c.charCodeAt(0))
            : Uint8Array.from(
                decodeQuotedPrintable(payload.replace(/_/g, ' ')),
                (c) => c.charCodeAt(0),
              );
        return new TextDecoder(charset.toLowerCase(), { fatal: false }).decode(bytes);
      } catch {
        return whole;
      }
    },
  );
}

/** Every email address inside a string, deduplicated, lowercased. */
export function findAddresses(text) {
  const found = String(text ?? '').match(new RegExp(EMAIL_RE.source, 'gi')) ?? [];
  return [...new Set(found.map((a) => a.toLowerCase()))];
}

/** Render NUL-separated token payloads readably. */
export function prettifyNulls(text) {
  return String(text).replace(/\0+/g, ' · ').trim();
}

/**
 * Shorten an opaque value for display.
 *
 * Tracking payloads run to kilobytes of base64. The head and tail are what a
 * reader can act on — enough to recognise the value again, and to see that it
 * is an id rather than a sentence — so the middle is what gets dropped.
 */
export function clip(value, max = 160) {
  const text = String(value ?? '').trim();
  if (text.length <= max) return text;
  const keep = Math.floor((max - 3) / 2);
  return `${text.slice(0, keep)}...${text.slice(-keep)}`;
}
