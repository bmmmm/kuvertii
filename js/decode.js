// Decoder chain for obfuscated header values.
//
// Bulk mailers rarely encrypt — they encode, and assume nobody looks. The point
// of this module is to look: try a handful of cheap transforms and keep only
// the results that turn into something a human can read.

// Every quantifier here is bounded, and the leading lookbehind is what makes
// the bounds hold. Without it the engine retries the local part at every one of
// its own characters, so a single long run of `[A-Za-z0-9._%+-]` costs O(n²) —
// and a header field is allowed to be 100 KB long, which a sender does not need
// anyone's cooperation to exploit. The limits are RFC 5321 §4.5.3.1: 64 octets
// of local part, 63 per label. Ten labels and a 24-character TLD are past
// anything that resolves.
const EMAIL_RE = /(?<![A-Z0-9._%+-])[A-Z0-9._%+-]{1,64}@[A-Z0-9-]{1,63}(?:\.[A-Z0-9-]{1,63}){0,10}\.[A-Z]{2,24}/i;
const DOMAIN_RE = /\b[A-Z0-9-]+\.(?:[A-Z]{2,}\.)?[A-Z]{2,}\b/i;
const WORD_RE = /[A-Za-z]{4,}/;

// A `=XX` escape is quoted-printable only when the byte is one QP is there to
// carry: 0x80..0xFF. RFC 2045 §6.7 leaves printable ASCII (0x21..0x7E, bar `=`)
// bare, so a conformant encoder never writes `=41`, `=2E`, `=5F`, `=2B`. A lone
// one of those is not an encoding — it is base64 padding followed by two hex
// digits, or a literal `=`, sitting inside a message-id or DKIM signature that
// already ends in `@domain`. Reading it as QP rewrites one character of that
// opaque token and leaves the `@domain` — legible all along — in place, so the
// address that falls out is announced as a recipient "recovered by decoding"
// when nothing was hidden. Two of 25 real messages hit this through
// DKIM-Signature. The strictness of `textFromBytes` then still applies: a high
// byte that is not valid UTF-8 (`=8b` in a Gmail id) is refused as before, and
// a genuine `=C3=BC` (0xC3 0xBC = ü) has its high bytes and survives.
const QP_HIGH_BYTE_RE = /=[89A-F][0-9A-F]/i;

// The same trap one branch along, and the same answer. RFC 3986 §2.3 calls
// `ALPHA / DIGIT / - . _ ~` unreserved and says they are never to be encoded,
// so no conformant encoder writes `%41` for `A`. A run of printable escapes is
// therefore not percent-encoding — it is two hex digits following a literal `%`
// inside an opaque tracker id that already ends in `@domain`. Decoding it
// rewrites one character of the id, leaves the `@domain` that was legible all
// along, and the address that falls out is announced as a recipient
// "recoverable only by decoding" in the sharpest words the card has, over a
// token that never encoded anything: `X-Track-ID: abcn%41xy@example.org` was
// enough to produce an alert.
//
// One escape carrying a byte outside that set is enough to count, so the case
// this branch exists for is untouched: `%40` is `@`, and the double-encoded
// `%2540` starts `%25`, which is `%`. Both are reserved.
const PERCENT_ESCAPE_RE = /%([0-9A-F]{2})/gi;
const UNRESERVED_BYTE_RE = /[A-Za-z0-9\-._~]/;

function encodesAReservedByte(text) {
  for (const [, hex] of text.matchAll(PERCENT_ESCAPE_RE)) {
    if (!UNRESERVED_BYTE_RE.test(String.fromCharCode(parseInt(hex, 16)))) return true;
  }
  return false;
}

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
// Exported for js/body.js: a link's visible text only *claims* a destination
// when it ends in a TLD a reader would recognise — `node.js` in a link label
// is a product name, not a domain, and accusing it of going elsewhere would
// put a false warning on ordinary mail.
export function hasKnownTld(text) {
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
 * Decode a short token that turns out to be an encoded identifier.
 *
 * Separate from bestDecode because the readability heuristic cannot help here:
 * an account number decodes to `31859940`, which scores 0.40 as prose — the
 * same as the random bytes a real hostname yields when forced through base64.
 * What separates them is not readability but character class. An identifier
 * decodes to printable ASCII; a false positive decodes to control bytes and
 * replacement characters.
 *
 * Returns the decoded text, or null when the input is not such a token.
 */
export function decodeIdentifier(value, { min = 6, max = 64 } = {}) {
  const token = String(value ?? '').trim();
  if (token.length < min || token.length > max) return null;
  // A dot means a hostname, which is what this is meant to tell apart from one.
  if (/[.@]/.test(token) || !/^[A-Za-z0-9+/\-_]+=*$/.test(token)) return null;

  const decoded = fromBase64(token);
  if (!decoded || decoded.length < 3) return null;
  if (!/^[\x20-\x7E]+$/.test(decoded)) return null;
  // Decoding must actually shorten it; otherwise this is just a rename.
  if (decoded.length >= token.length) return null;

  return decoded;
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
  // U+FFFD is not a character a sender wrote. It is what TextDecoder emits
  // where the bytes were not UTF-8 at all — the decoder's own verdict on its
  // own output, and counting it as printable is how a random blob passed for
  // prose: five replacement characters among twenty-three still left the ratio
  // at 0.91, and the four letters the noise happened to spell carried it over
  // the line. Counted for what it is, that blob scores zero.
  //
  // Counted, not banned outright. A token can be an opaque prefix followed by
  // base64, and decoding the whole of it puts a few misaligned bytes at the
  // head of sixty perfectly readable characters — refusing every decode that
  // contains one loses the recipient's address in the unsubscribe token, which
  // is the exact thing this module exists to find. The proportion is the
  // signal, and 0.85 is where it already sat.
  const printable = chars.filter((c) => {
    if (c === '\uFFFD') return false;
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
  } else if (QP_HIGH_BYTE_RE.test(raw)) {
    offer(textFromBytes(decodeQuotedPrintable(raw)), 'quoted-printable');
  }

  if (encodesAReservedByte(raw)) {
    offer(decodePercent(raw), 'percent-encoded');
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
  const raw = String(value ?? '');
  const readable = (piece) => decodeCandidates(piece).filter((c) => c.score >= threshold);

  // Unfolding removes the line break a long field was wrapped at, not the space
  // that came with it (RFC 5322 §2.2.3) — and a mailer folds at a fixed width,
  // not at its own separators, so the fold lands inside a segment as readily as
  // between two. Splitting on whitespace therefore tore a base64 token in half,
  // and half a token decodes to noise: on a real Klaviyo message the segment
  // holding the recipient's own address was cut by a fold, so the address went
  // unreported and the noise left behind decided how its siblings were read.
  //
  // Each token is read whole, with the fold's whitespace taken back out. The
  // halves are still read too, because a space can also be a genuine separator
  // and nothing here can tell the two apart — but a half is recorded against the
  // token it came out of, so the one case that needs no judgement, a half saying
  // only what the whole already said, can be dropped without comparing every
  // result against every other. That comparison is what a sender would pay for:
  // a field may run to a megabyte, and pairwise it cost 12 seconds where the
  // whole decode had cost 361 milliseconds.
  const entries = [{ candidates: readable(raw), parent: -1 }];
  for (const chunk of raw.split(/[.:;,<>"'()[\]]+/)) {
    if (!/\s/.test(chunk)) {
      entries.push({ candidates: readable(chunk), parent: -1 });
      continue;
    }

    // Whitespace inside a token is either a fold or a separator, and the value
    // itself cannot say which — but what the two readings decode to can. A
    // separator leaves both sides readable on their own; a fold leaves at least
    // one side holding part of a token, which decodes to nothing at all. So the
    // halves keep the field only when every one of them can carry it, and
    // otherwise the token is read whole, as it was before the fold.
    const halves = chunk.split(/\s+/).map((half) => readable(half));
    if (halves.every((candidates) => candidates.length)) {
      for (const candidates of halves) entries.push({ candidates, parent: -1 });
      continue;
    }

    const whole = entries.length;
    entries.push({ candidates: readable(chunk.replace(/\s+/g, '')), parent: -1 });
    for (const candidates of halves) entries.push({ candidates, parent: whole });
  }

  // One segment usually decodes unambiguously — an address settles its own
  // orientation, because only one reading ends in a real TLD. Whichever method
  // wins there is applied to its siblings, which on their own are a coin flip.
  const dominant = entries.flatMap((e) => e.candidates).sort((a, b) => b.score - a.score)[0]?.method;

  const picks = new Array(entries.length).fill(null);
  const results = [];
  const seen = new Set();
  for (const [index, entry] of entries.entries()) {
    if (!entry.candidates.length) continue;
    const pick = entry.candidates.find((c) => c.method === dominant) ?? entry.candidates[0];
    picks[index] = pick;
    // `nual"}}` is the tail of this token's own reading, decoded on its own:
    // not a second finding, the same bytes read worse.
    const parent = entry.parent >= 0 ? picks[entry.parent] : null;
    if (parent && parent.text.includes(pick.text)) continue;
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

/**
 * Bytes back into text, or nothing at all.
 *
 * The strictness is the feature. `decodeQuotedPrintable` produces one character
 * per byte, which is what `decodeEncodedWords` wants — it applies the charset
 * the header declared. Standalone there is no declared charset, and mail
 * headers carry UTF-8, so this asks whether the bytes are UTF-8 and answers
 * null when they are not.
 *
 * That answer is what separates an encoding from a coincidence. An ordinary
 * Gmail message id contains `=8b`, which is a valid quoted-printable escape and
 * decodes to a lone continuation byte — no UTF-8 sequence begins with 0x8B. The
 * old chain decoded it anyway, and the leftover characters read as an address,
 * so the tool announced a hidden recipient that did not exist, with its
 * strongest wording, on ordinary personal mail.
 *
 * The same strictness earns something as well as refusing something: real
 * quoted-printable finally decodes properly. `Gr=C3=BC=C3=9Fe` was rendering as
 * `GrÃ¼Ã<U+009F>e` — the bytes, one per character, never reassembled.
 */
function textFromBytes(latin1) {
  const bytes = Uint8Array.from(latin1, (ch) => ch.charCodeAt(0) & 0xff);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/**
 * Percent-encoding, undone as far as it goes.
 *
 * The form every click tracker writes: `?u=max.mustermann%40example.org`. It
 * was the one encoding the chain did not know, so an address hidden that way —
 * which is to say, the way SendGrid, Mailchimp and HubSpot all hide it — was
 * not counted among the copies the reader was told about. The tool would decode
 * the surrounding base64, print the address in the destination URL, and then
 * report one fewer hidden copy than it had just shown.
 *
 * A second pass because double-encoding is ordinary in a URL that has been
 * through two systems; `decodeURIComponent` throwing on a malformed sequence is
 * the validity check, and a throw means this was not percent-encoding.
 */
function decodePercent(text) {
  try {
    const once = decodeURIComponent(text);
    if (once === text) return null;
    if (!/%[0-9A-F]{2}/i.test(once)) return once;
    try {
      return decodeURIComponent(once);
    } catch {
      return once;
    }
  } catch {
    return null;
  }
}

export function decodeQuotedPrintable(text) {
  return String(text)
    .replace(/=\r?\n/g, '')
    .replace(/=([0-9A-F]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

// --------------------------------------------------- charsets mail still uses

/**
 * The charsets a mail client decodes and `TextDecoder` refuses.
 *
 * `TextDecoder` implements the WHATWG Encoding Standard, which is a
 * specification for *browsers*. It leaves UTF-7 out entirely and maps the
 * ISO-2022-CN/KR family and HZ onto its "replacement" encoding — a deliberate
 * refusal, because a page whose bytes can be re-read under a second encoding is
 * how a `<script>` gets past a filter that only looked at the first reading.
 *
 * None of that reasoning reaches this program. It never renders a body; it
 * describes one. What it inherits from the browser instead is blindness in
 * exactly the place a sender would choose: `charset=utf-7` and a phishing
 * anchor written as `+ADw-a href…` drew no link card at all, because the tool
 * saw one opaque token where the reader's client renders a live link. And
 * ISO-2022-KR is not an attack at all — it is what RFC 1557 defines for Korean
 * mail, so an attachment named `보고서.exe` in an ISO-2022-KR encoded-word left
 * the executable check reading `=?ISO-2022-KR?B?…?=` and the card silent.
 *
 * Each of these is mechanical, which is why they are here and ISO-2022-CN is
 * not: ISO-2022-KR and HZ are their 8-bit siblings (EUC-KR, GBK) with the high
 * bit carried by a shift sequence, and UTF-7 is base64 over UTF-16. ISO-2022-CN
 * can designate CNS 11643 planes, which no encoding `TextDecoder` knows can
 * represent, so rewriting it would be inventing characters rather than reading
 * them — it stays on the caller's existing fallback.
 *
 * Keyed by the labels IANA registers, since that is what a mail header writes.
 */
const MAIL_ONLY_CHARSETS = new Map([
  ['utf-7', 'utf-7'],
  ['csutf7', 'utf-7'],
  ['unicode-1-1-utf-7', 'utf-7'],
  ['csunicode11utf7', 'utf-7'],
  ['iso-2022-kr', 'iso-2022-kr'],
  ['csiso2022kr', 'iso-2022-kr'],
  ['hz-gb-2312', 'hz-gb-2312'],
  ['cshzgb2312', 'hz-gb-2312'],
]);

/** Which of the above a label names, or null for everything else. */
export function mailOnlyCharset(label) {
  return MAIL_ONLY_CHARSETS.get(String(label ?? '').trim().toLowerCase()) ?? null;
}

const UTF7_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * UTF-7 (RFC 2152): ASCII in the clear, everything else in a `+…-` run of
 * modified base64 over UTF-16 code units.
 *
 * `+-` is the one escape: a literal plus. A run ends at the first character
 * outside the base64 alphabet, which is consumed when it is `-` and kept
 * otherwise. Leftover bits at the end of a run are padding by construction and
 * are dropped, which is also what a client does with a truncated run.
 */
function fromUtf7(bytes) {
  let out = '';
  let inRun = false;
  let taken = 0;
  let bits = 0;
  let held = 0;

  for (const byte of bytes) {
    const ch = String.fromCharCode(byte);
    if (!inRun) {
      if (ch === '+') { inRun = true; taken = 0; bits = 0; held = 0; continue; }
      out += ch;
      continue;
    }
    const value = UTF7_B64.indexOf(ch);
    if (value >= 0) {
      bits = (bits << 6) | value;
      held += 6;
      taken += 1;
      if (held >= 16) {
        held -= 16;
        out += String.fromCharCode((bits >> held) & 0xffff);
      }
      continue;
    }
    if (!taken && ch === '-') out += '+';
    else if (ch !== '-') out += ch;
    inRun = false;
  }
  return out;
}

/**
 * The 7-bit ISO 2022 / HZ forms, rewritten into the 8-bit encoding they are a
 * shifted spelling of, and handed to the decoder that does know it.
 *
 * `shift` recognises the bytes that move in and out of the double-byte set;
 * inside it every byte is its 8-bit counterpart with the high bit set. Both
 * specifications reset the state at every line break (RFC 1557 §4, RFC 1843
 * §2), so a message that forgets to shift back cannot swallow the rest of
 * itself.
 */
function fromShifted(bytes, target, shift) {
  const out = [];
  let shifted = false;
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte === 0x0a || byte === 0x0d) { shifted = false; out.push(byte); continue; }
    const move = shift(bytes, i, shifted);
    if (move) {
      if (move.emit !== undefined) out.push(move.emit);
      if (move.shifted !== undefined) shifted = move.shifted;
      i += move.skip;
      continue;
    }
    // Only a graphic byte is half of a double-byte character. Raising the high
    // bit on anything else would manufacture the one thing this program is
    // most careful never to manufacture: 0x1B shifted is 0x9B, the C1 spelling
    // of CSI, so a malformed run would grow a terminal escape sequence that
    // nobody sent. Control bytes pass through as themselves, and stay evidence.
    const graphic = byte > 0x20 && byte < 0x7f;
    out.push(shifted && graphic ? byte | 0x80 : byte);
  }
  return new TextDecoder(target, { fatal: false }).decode(Uint8Array.from(out));
}

/** ISO-2022-KR (RFC 1557): `ESC $ ) C` announces it, SO/SI shift into KS X 1001. */
function fromIso2022kr(bytes) {
  return fromShifted(bytes, 'euc-kr', (all, i) => {
    // The one escape this charset defines is the designator, and it carries no
    // text. Any other ESC is not part of the encoding and is left where it is,
    // because a stray escape byte in a mail body is a finding of its own.
    if (all[i] === 0x1b && all[i + 1] === 0x24 && all[i + 2] === 0x29) return { skip: 3 };
    if (all[i] === 0x0e) return { shifted: true, skip: 0 };
    if (all[i] === 0x0f) return { shifted: false, skip: 0 };
    return null;
  });
}

/** HZ-GB-2312 (RFC 1843): `~{` and `~}` shift, `~~` is a tilde, `~\n` joins lines. */
function fromHz(bytes) {
  return fromShifted(bytes, 'gbk', (all, i, shifted) => {
    if (all[i] !== 0x7e) return null;
    const next = all[i + 1];
    if (next === 0x7e) return { emit: 0x7e, skip: 1 };
    if (next === 0x7b) return { shifted: true, skip: 1 };
    if (next === 0x7d) return { shifted: false, skip: 1 };
    // A line continuation removes the break and carries the state across it —
    // the one place the per-line reset does not apply (RFC 1843 §2.2).
    if (next === 0x0a) return { shifted, skip: 1 };
    return null;
  });
}

/**
 * Bytes read under a charset only mail uses, or null when this is not one.
 *
 * Null rather than a guess, twice over: for a label outside the table, and for
 * a stream carrying a byte above 0x7F. All three of these encodings are 7-bit
 * by definition, so a high byte means the bytes are not what the label says —
 * the same rule js/mime.js already applies to quoted-printable, and the reason
 * a message that mislabels UTF-8 as UTF-7 keeps being read as the UTF-8 it is.
 */
export function decodeMailCharset(bytes, label) {
  const family = mailOnlyCharset(label);
  if (!family) return null;
  for (const byte of bytes) {
    if (byte > 0x7f) return null;
  }
  if (family === 'utf-7') return fromUtf7(bytes);
  if (family === 'iso-2022-kr') return fromIso2022kr(bytes);
  return fromHz(bytes);
}

/**
 * A whole message, from bytes to text, without inventing a character.
 *
 * Both front ends receive a message as text: the page from a paste, which the
 * operating system already decoded, and the terminal from a file or a pipe,
 * which it did not. A file is bytes, and the obvious call — `file.text()`,
 * `readFile(path, 'utf8')` — decodes them as UTF-8 and writes U+FFFD wherever
 * they were not. That is the one character on a report that can only have come
 * from this tool (test/invariants.test.js), and here it was inserted before
 * js/mime.js had seen a byte: an 8bit body labelled iso-8859-1 arrived with its
 * umlauts already replaced, and so did the raw 8-bit header values some
 * senders still write. Found in review of the file-open feature, on the day it
 * was written; the terminal had carried the same seam since its first file.
 *
 * Strict UTF-8 first, which nearly every message written this decade is. Where
 * that fails, windows-1252 — chosen because it is total: all 256 byte values
 * map to a character, so the decode cannot fail and cannot invent anything —
 * and because it is the superset of ISO-8859-1 every mail client has read for
 * thirty years. A message in a third 8-bit charset (koi8-r, iso-8859-2) comes
 * out as wrong letters rather than as U+FFFD: still the sender's bytes, one
 * per byte, which a reader can recognise — the same result a paste from a
 * client that guessed wrong gives. Deciding per part, under each part's own
 * declared charset, would be better still and is not done here: the parts are
 * only known after the split, and the split needs text. Total by
 * construction: every byte maps to one code point in fromWindows1252, so no
 * byte value can produce U+FFFD on any runtime.
 */
export function textFromMessageBytes(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return fromWindows1252(bytes);
  }
}

/**
 * The 32 bytes where windows-1252 differs from ISO-8859-1, from the WHATWG
 * index. Everything else in the range is the byte's own code point.
 */
const WINDOWS_1252_HIGH = [
  0x20ac, 0x0081, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021,
  0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008d, 0x017d, 0x008f,
  0x0090, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
  0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x009d, 0x017e, 0x0178,
];

/**
 * windows-1252 by table, not by TextDecoder.
 *
 * `new TextDecoder('windows-1252')` is not one decoder: Node 20 answers it
 * with ICU's ISO-8859-1, so 0x80 came back as U+0080 where Node 26 and every
 * browser give €. Measured on CI the day the fallback shipped — the euro test
 * went red on the engines floor and green on the deploy version. Left to the
 * runtime, a Windows client's curly quotes would have read as C1 control
 * bytes in one terminal and as punctuation in another, and the controls card
 * would have accused the sender on the first. A message must read the same
 * everywhere this tool runs, so the differing bytes are spelled out here.
 */
function fromWindows1252(bytes) {
  const units = new Uint16Array(bytes.length);
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = bytes[i];
    units[i] = byte >= 0x80 && byte < 0xa0 ? WINDOWS_1252_HIGH[byte - 0x80] : byte;
  }
  // In chunks: fromCharCode takes its arguments on the stack, and a 32 MB
  // file would overflow it in one call.
  const CHUNK = 8192;
  let out = '';
  for (let i = 0; i < units.length; i += CHUNK) {
    out += String.fromCharCode.apply(null, units.subarray(i, i + CHUNK));
  }
  return out;
}

export function decodeEncodedWords(text) {
  // RFC 2047 §6.2: whitespace separating two adjacent encoded-words is removed
  // on display — it is there only so a long run can be split across words (and
  // folded lines), not to insert a space. Whitespace between an encoded-word and
  // ordinary text is kept, so the collapse is anchored to `?=…=?` and touches
  // nothing else. Without it every reader saw a space no mail client shows:
  // `caf =?…?=` rendered `café` as `caf é`, a split filename `report.ex` + `e`
  // read as `report.ex e` so the `.exe` check went silent on a file the client
  // runs as `report.exe`, and a split address `ali` + `ce=40x.org` decoded to
  // `ali ce@x.org` — the wrong recipient found, the real one missed.
  return String(text)
    .replace(/\?=\s+=\?/g, '?==?')
    .replace(
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
          // RFC 2231 §5 decorates the charset with a language tag —
          // `=?utf-8*en?B?…?=` — and a conformant client drops the `*en` and
          // decodes as utf-8. `TextDecoder('utf-8*en')` throws, so without this
          // the whole word was returned raw: a subject rendered as its own
          // gibberish, and — the reason this is a fix and not fidelity — the
          // filename `=?utf-8*en?B?<report.exe>?=` never became `report.exe`, so
          // the executable check ran on a string ending in `?=` and the
          // attachment card went silent on a file the client runs. Stripping the
          // tag only ever exposes what a real reader already sees.
          const label = charset.toLowerCase().split('*')[0];
          // The charsets only mail uses get first refusal; everything else is
          // the Encoding Standard's, including its throw for a label it does
          // not know, which is what keeps an unreadable word raw rather than
          // rendered as somebody's guess.
          return decodeMailCharset(bytes, label)
            ?? new TextDecoder(label, { fatal: false }).decode(bytes);
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
