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

  if (/%[0-9A-F]{2}/i.test(raw)) {
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
          return new TextDecoder(label, { fatal: false }).decode(bytes);
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
