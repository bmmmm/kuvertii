// Split a whole pasted message into its header and its body parts.
//
// Everything below the first blank line is 100% sender-written text. It is
// taken apart so it can be *described* — which links it carries, which parts it
// declares, what reading it would reveal — and it is never rendered: no part
// of it reaches an HTML sink, nothing it names is fetched, no attachment is
// opened. The findings built from it go through the same `neutralise`+`defang`
// path as every header value.
//
// Every ceiling in this file exists because `analyse` runs synchronously on
// the browser's main thread, and the sender chooses how large the body is.
// A ceiling that bites is announced (the clippedNote lesson: a silent clip
// makes the closing tally a lie), and the wording lives here, once, so the two
// renderers cannot drift apart about what was read.

import { decodeEncodedWords, decodeMailCharset, decodeQuotedPrintable, mailOnlyCharset } from './decode.js';
import { get, MAX_HEADER_BYTES, readHeaders } from './unfold.js';

/**
 * How much body is analysed before the rest is ignored.
 *
 * Same reasoning as MAX_HEADER_BYTES one module over: not a defence against
 * slow input — the walk below is linear — but a bound on how long the page can
 * stop responding. Four megabytes is past any newsletter worth reading and
 * still parses well inside a second; a 10 MB message degrades with a sentence
 * rather than a stall.
 */
export const MAX_BODY_BYTES = 4 * 1024 * 1024;

// Decoded text kept per part. A single part larger than this is read up to
// here and its `clipped` flag says so.
export const MAX_PART_TEXT = 2 * 1024 * 1024;

// MIME nesting a real mailer produces is two or three levels
// (mixed → related → alternative). Five is past all of it; a message nested
// deeper is exercising the parser, not carrying content.
export const MAX_DEPTH = 5;

// Parts read before the count itself becomes the finding.
export const MAX_PARTS = 50;

// Decoded bytes kept from the front of every part, text or not — enough for a
// declared-type-vs-magic-bytes comparison and nothing more. Attachments are
// never decoded beyond this.
const HEAD_BYTES = 16;

// Fields whose presence marks a block of text as a mail header. Deliberately
// the common ones only: the question is not "is this a valid header" but "did
// the person paste a header at all", and one recognisable field answers it.
const KNOWN_FIELDS = new Set([
  'from', 'to', 'cc', 'bcc', 'subject', 'date', 'message-id', 'received',
  'return-path', 'reply-to', 'delivered-to', 'mime-version', 'content-type',
  'content-transfer-encoding', 'dkim-signature', 'authentication-results',
  'received-spf', 'list-id', 'list-unsubscribe', 'x-mailer', 'user-agent',
  'sender', 'envelope-to', 'x-original-to', 'original-recipient',
  'in-reply-to', 'references', 'feedback-id', 'x-priority', 'importance',
  'x-spam-status', 'x-forefront-antispam-report',
]);

// Tags that mark a paste as a message body rather than a mangled header.
// Matched against the raw input, so a minified newsletter — one enormous line,
// no blank line anywhere — is recognised as what it is instead of being read
// as a fifty-kilobyte unlabelled header field.
const MARKUP_RE = /<(?:!doctype|html|head|body|div|table|tbody|tr|td|p|a|img|span|center|font|style|meta|br)[\s>/]/i;

/**
 * The type a body is read as, which is not always the type it declares.
 *
 * A body that is visibly markup, read as plain text, hides every href behind
 * its angle brackets: the link card then tallies the decoy text a reader sees
 * instead of the destinations underneath it. That is the one thing this tool
 * promises not to do, so content wins over the declaration — and the
 * declaration is written by the sender, who is the party that benefits from
 * the misreading. `Content-Type: text/plain` over an HTML body had the report
 * name the anchor text as the destination and never mention the host the link
 * actually goes to.
 *
 * Only an absent or `text/*` declaration is second-guessed. A part that says
 * it is a PDF or an image is taken at its word: those are read for their first
 * bytes, not their text, and a hex string inside one is not a `<p>` tag.
 */
function typeForContent(declared, body) {
  const parsed = parseContentType(declared);
  if (parsed.type === 'text/html') return parsed;
  const openToReading = !String(declared ?? '').trim() || parsed.type.startsWith('text/');
  if (!openToReading || !MARKUP_RE.test(body)) return parsed;
  // Only the reading changes. Every parameter the declaration carried is kept
  // — the charset above all, since it is what turns the bytes into text, and
  // replacing the whole descriptor dropped it: a `text/html; charset=utf-8`
  // part came back out of here with no charset at all. `declaredType` keeps
  // what the message offered this part as, which is a different question from
  // how it is read: the plain/html divergence card pairs the two versions of a
  // multipart/alternative by what they were offered as, and reading a plain
  // part as markup silently unpaired them.
  return { ...parsed, type: 'text/html', declaredType: parsed.type };
}

/**
 * Does this block of text carry a recognisable mail header?
 *
 * Runs the real parser over the front of the block rather than a cheap regex,
 * because the real parser is what will read it — and it is the one that knows
 * a localised `Von:` is a From. One known field is enough: the alternative
 * reading (that the sender's body happens to open with `Received:`) loses to
 * the alternative cost (a real partial header dismissed as not-a-header).
 */
export function looksLikeHeaderBlock(text) {
  const block = String(text ?? '');
  if (!block.trim()) return false;
  const { headers } = readHeaders(block.slice(0, MAX_HEADER_BYTES));
  return headers.some((h) => KNOWN_FIELDS.has(h.name.toLowerCase()));
}

/**
 * Does this block carry any field at all that was written as one?
 *
 * Same construction as looksLikeHeaderBlock — ask the real parser, because it
 * is the one that knows `An:` is a To and that an unlabelled leading sender
 * line becomes a From. A synthetic `(unlabelled)` entry does not count: that
 * is the parser keeping a line it could not read as a field, which is exactly
 * the reading this function exists to overrule.
 */
function carriesAnyLabelledField(text) {
  const block = String(text ?? '');
  if (!block.trim()) return false;
  const { headers } = readHeaders(block.slice(0, MAX_HEADER_BYTES));
  return headers.some((h) => !h.synthetic);
}

/**
 * Cut a paste into header text and body text.
 *
 * The paste decides the mode — there is no switch. A header block before the
 * first blank line: header analysis, and body analysis if anything follows.
 * No recognisable header but markup-shaped content: the whole paste is a body,
 * and `bodyOnly` says so, so the caller can be honest about what cannot be
 * answered. Everything else is treated exactly as before this module existed.
 *
 * The boundary is the same one js/unfold.js uses: the first line that is blank
 * or whitespace-only, after at least one line that is not. Using a stricter
 * boundary here (a truly empty line) would read parts the header parser had
 * already declared to be body, and the two answers would disagree.
 */
export function splitMessage(raw) {
  const text = String(raw ?? '');
  const lines = text.split(/\r\n|\r|\n/);

  let seen = false;
  let boundary = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim()) { seen = true; continue; }
    if (seen) { boundary = i; break; }
  }

  const headerText = boundary === -1 ? text : lines.slice(0, boundary).join('\n');
  const bodyText = boundary === -1 ? '' : lines.slice(boundary + 1).join('\n');

  // Markup is strong body evidence, so one known field is enough to overrule
  // it. Prose is weak evidence, so it flips only when the front block carries
  // no labelled field at all — before that rule, a greeting parsed as one
  // unlabelled fragment and the report told the reader their message text
  // looked like part of a header, which it factually was not. An Apple Mail
  // display-lines paste survives the rule: its leading `Name <addr>` line is
  // promoted to a From by the parser this asks, and localised labels count.
  if (!looksLikeHeaderBlock(headerText) && text.trim()
    && (MARKUP_RE.test(text) || !carriesAnyLabelledField(headerText))) {
    return { headerText: '', bodyText: text, bodyOnly: true };
  }
  return { headerText, bodyText, bodyOnly: false };
}

/**
 * What to tell the reader when the body was cut at MAX_BODY_BYTES.
 *
 * Same contract as clippedNote in js/unfold.js: empty when nothing was
 * dropped, one leading space when something was, so callers append it
 * unconditionally and the claim cannot drift between renderers.
 */
export function bodyClippedNote(originalLength) {
  if (originalLength <= MAX_BODY_BYTES) return '';
  return ` Only the first ${Math.round(MAX_BODY_BYTES / (1024 * 1024))} MB of the body were read — anything after that was not analysed.`;
}

/**
 * The opening sentence of the closing tally: what was read.
 *
 * One wording for both front ends, for the reason clippedNote was unified —
 * two copies of a sentence drift, and this one drifted into saying nothing at
 * all. Built by joining the non-zero counts, it produced a bare `" read."`
 * with no subject whenever both were zero: a body-only paste under
 * `--headers-only` on the command line, and on the page a body-only paste
 * whose parseParts degraded to no parts. The line whose entire job is to be a
 * complete account of the input could not say that the input had not been
 * read.
 */
export function readTally(headerCount, partCount) {
  const read = [
    headerCount ? `${headerCount} header field${headerCount === 1 ? '' : 's'}` : null,
    partCount ? `${partCount} body part${partCount === 1 ? '' : 's'}` : null,
  ].filter(Boolean).join(' and ');
  return read ? `${read} read.` : 'Nothing was read.';
}

/**
 * Walk the MIME structure and return every leaf part, decoded within limits.
 *
 * A part is { contentType, declaredType, charset, disposition, filename,
 * transferEncoding, bytesDeclared, text, head, clipped }. `contentType` is how
 * the part is read and `declaredType` is what the message offered it as — the
 * two differ where content outranked a declaration, and the second answers
 * "which version of this message is this", which the first cannot.
 * `text` is the decoded content for
 * text/* parts and null for everything else — an attachment is never decoded
 * beyond `head`, the first few bytes kept for a type check. `bytesDeclared`
 * is the size= parameter when the sender stated one, otherwise the decoded
 * size as computed from the encoded length.
 *
 * Malformed MIME degrades to one part, never to a throw: a boundary that
 * never appears, a multipart with no boundary parameter, nesting past the
 * depth ceiling — each keeps whatever content it wraps as a single part, and
 * every one of those outcomes announces itself in `notes`.
 */
export function parseParts(headers, bodyText) {
  const notes = [];
  let body = String(bodyText ?? '');
  if (!/\S/.test(body)) return { parts: [], notes };

  if (body.length > MAX_BODY_BYTES) {
    notes.push(bodyClippedNote(body.length));
    body = body.slice(0, MAX_BODY_BYTES);
  }

  const parts = [];
  const state = { overflow: 0, tooDeep: false, partClipped: false, unreadableStructure: false };
  const declared = get(headers, 'content-type');
  const contentType = typeForContent(declared, body);
  const disposition = parseDisposition(get(headers, 'content-disposition'), contentType);
  const encoding = normalEncoding(get(headers, 'content-transfer-encoding'));

  walk(contentType, encoding, disposition, body, 0, parts, state);

  if (state.tooDeep) {
    notes.push(` The message nests parts deeper than ${MAX_DEPTH} levels; whatever lies below that depth was kept unopened.`);
  }
  if (state.overflow) {
    notes.push(` Only the first ${MAX_PARTS} body parts were read; ${state.overflow} more were not.`);
  }
  if (state.partClipped) {
    notes.push(` A body part was larger than ${Math.round(MAX_PART_TEXT / (1024 * 1024))} MB; only its first ${Math.round(MAX_PART_TEXT / (1024 * 1024))} MB were read.`);
  }
  if (state.unreadableStructure) {
    notes.push(' The message says it is made of several parts but names a boundary that never appears in it, so the parts could not be told apart; what was there was read as one.');
  }
  return { parts, notes };
}

function walk(contentType, encoding, disposition, body, depth, parts, state) {
  if (contentType.type.startsWith('multipart/')) {
    if (depth >= MAX_DEPTH) {
      state.tooDeep = true;
      leaf(contentType, encoding, disposition, body, parts, state, { opaque: true });
      return;
    }
    const sections = contentType.boundary ? splitMultipart(body, contentType.boundary) : [];
    if (!sections.length) {
      // No boundary parameter, or a boundary that never appears in the body.
      // The structure is unreadable — the content is not, and keeping it as
      // one opaque part threw the whole message away in silence: a lookalike
      // link and a tracking pixel drew no card at all, while the tally still
      // said a body part had been read. One `boundary=` the sender never uses
      // cost nothing to write and emptied the report.
      //
      // So the bytes are read for what they look like, exactly as an
      // undeclared body is, and the fact that the structure could not be
      // followed is announced — the other three unreadable outcomes here
      // (too deep, too many parts, too large) all say so, and this one is the
      // only one the sender can trigger for free.
      state.unreadableStructure = true;
      leaf(typeForContent('', body), encoding, disposition, body, parts, state, {});
      return;
    }
    for (const section of sections) {
      const { headerText, body: sectionBody } = splitSection(section);
      const { headers } = readHeaders(headerText);
      const childType = typeForContent(get(headers, 'content-type'), sectionBody);
      const childDisposition = parseDisposition(get(headers, 'content-disposition'), childType);
      const childEncoding = normalEncoding(get(headers, 'content-transfer-encoding'));
      walk(childType, childEncoding, childDisposition, sectionBody, depth + 1, parts, state);
    }
    return;
  }
  leaf(contentType, encoding, disposition, body, parts, state, {});
}

function leaf(contentType, encoding, disposition, body, parts, state, { opaque = false }) {
  if (parts.length >= MAX_PARTS) {
    state.overflow += 1;
    return;
  }
  const wantText = !opaque && contentType.type.startsWith('text/');
  const decoded = decodeBody(body, encoding, contentType.charset, wantText);
  if (decoded.clipped) state.partClipped = true;

  parts.push({
    contentType: contentType.type,
    declaredType: contentType.declaredType ?? contentType.type,
    charset: contentType.charset,
    disposition: disposition.disposition,
    filename: disposition.filename,
    transferEncoding: encoding,
    bytesDeclared: disposition.size ?? decoded.bytes,
    text: decoded.text,
    head: decoded.head,
    clipped: decoded.clipped,
  });
}

// ------------------------------------------------------------------ splitting

/**
 * The bodies between one boundary's delimiter lines.
 *
 * String comparison per line, not a regex: the boundary is sender-written and
 * may contain anything a regex would obey. RFC 2046 allows trailing transport
 * padding after the delimiter, which trimEnd covers. Text before the first
 * delimiter (the preamble) and after the closing one (the epilogue) is
 * structural filler by definition and is dropped. A missing closing delimiter
 * keeps the final section — real mailers forget it.
 */
function splitMultipart(body, boundary) {
  const open = `--${boundary}`;
  const close = `--${boundary}--`;
  const sections = [];
  let current = null;

  for (const line of body.split('\n')) {
    const trimmed = line.trimEnd();
    if (trimmed === open || trimmed === close) {
      if (current) sections.push(current.join('\n'));
      current = trimmed === close ? null : [];
      if (!current) break;
      continue;
    }
    if (current) current.push(line);
  }
  if (current) sections.push(current.join('\n'));
  return sections;
}

/** A section's own header block and its body, cut at the first blank line. */
function splitSection(section) {
  const lines = section.split('\n');
  let end = lines.length;
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].trim()) { end = i; break; }
  }
  return {
    headerText: lines.slice(0, end).join('\n'),
    body: lines.slice(Math.min(end + 1, lines.length)).join('\n'),
  };
}

// ------------------------------------------------------------------- decoding

/**
 * One part's content, decoded as far as the limits allow.
 *
 * Returns { text, head, bytes, clipped }: the decoded text for text parts
 * (null otherwise), the first HEAD_BYTES decoded bytes for everyone, the
 * decoded size, and whether the per-part ceiling bit.
 */
function decodeBody(raw, encoding, charset, wantText) {
  if (encoding === 'base64') {
    // Whitespace is stripped; anything else disqualifies the declaration.
    // Deleting foreign characters instead would "decode" ordinary prose into
    // bytes that were never sent — the strictness rule js/decode.js already
    // follows for the same reason.
    const cleaned = raw.replace(/\s+/g, '');
    if (/[^A-Za-z0-9+/=_-]/.test(cleaned)) return textVerbatim(raw, wantText, charset);
    const bytes = Math.floor(cleaned.replace(/=+$/, '').length * 3 / 4);
    // Clip the *encoded* form so the decoded result respects the ceiling; the
    // cut lands on a four-character group so the tail still decodes.
    const budget = Math.ceil((MAX_PART_TEXT * 4) / 3);
    const clipped = cleaned.length > budget;
    const slice = clipped ? cleaned.slice(0, budget - (budget % 4)) : cleaned;
    const head = base64Bytes(slice.slice(0, 32)) ?? new Uint8Array(0);
    if (!wantText) return { text: null, head: [...head.slice(0, HEAD_BYTES)], bytes, clipped: false };
    const all = base64Bytes(slice);
    if (all === null) {
      // Not base64 despite the declaration. Kept as the text it visibly is —
      // refusing it entirely would hide content that is sitting in the clear.
      return textVerbatim(raw, wantText, charset);
    }
    return { text: decodeCharset(all, charset), head: [...all.slice(0, HEAD_BYTES)], bytes, clipped };
  }

  if (encoding === 'quoted-printable') {
    const clipped = raw.length > MAX_PART_TEXT;
    const slice = clipped ? raw.slice(0, MAX_PART_TEXT) : raw;
    // A pasted body can arrive already decoded by the mail client — real
    // umlauts where the wire had =C3=BC. Quoted-printable on the wire is pure
    // ASCII by construction, so any character past it means the text is
    // already decoded and must be taken as it stands — running the byte cast
    // over it would destroy exactly the characters the decoding restored.
    if (hasNonAscii(slice)) return textVerbatim(raw, wantText, charset);
    const latin1 = decodeQuotedPrintable(slice);
    const bytes = Uint8Array.from(latin1, (c) => c.charCodeAt(0) & 0xff);
    return {
      text: wantText ? decodeCharset(bytes, charset) : null,
      head: [...bytes.slice(0, HEAD_BYTES)],
      bytes: bytes.length,
      clipped,
    };
  }

  return textVerbatim(raw, wantText, charset);
}

/** Any codepoint past ASCII — text that cannot be undecoded wire bytes. */
function hasNonAscii(text) {
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) > 0x7f) return true;
  }
  return false;
}

/** The part's content taken as the text it already is, ceiling applied. */
function textVerbatim(raw, wantText, charset) {
  const clipped = raw.length > MAX_PART_TEXT;
  const slice = clipped ? raw.slice(0, MAX_PART_TEXT) : raw;
  const head = new TextEncoder().encode(slice.slice(0, HEAD_BYTES * 4)).slice(0, HEAD_BYTES);
  return { text: wantText ? verbatimText(slice, charset) : null, head: [...head], bytes: raw.length, clipped };
}

/**
 * Content that arrived without a transfer encoding is already characters — but
 * not yet text, when the charset it declares is one of the 7-bit escape
 * encodings.
 *
 * Those are exactly the charsets that need no transfer encoding, so this is
 * where they arrive: `charset=utf-7` with `Content-Transfer-Encoding: 7bit` is
 * the natural pairing, and it is the one path that never reached a charset at
 * all. A phishing anchor written as `+ADw-a href…` sat here as one opaque
 * token and the link card printed nothing.
 *
 * Guarded by the same rule as quoted-printable above: a character past ASCII
 * means the paste is already-decoded text, and casting it back to bytes would
 * destroy what the decoding restored.
 */
function verbatimText(slice, charset) {
  if (!mailOnlyCharset(charset) || hasNonAscii(slice)) return slice;
  return decodeMailCharset(Uint8Array.from(slice, (c) => c.charCodeAt(0)), charset) ?? slice;
}

function base64Bytes(input) {
  const normalised = input.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (normalised.length % 4 === 1) return null;
  try {
    const binary = atob(normalised + '='.repeat((4 - (normalised.length % 4)) % 4));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

/**
 * Bytes to text under the charset the part declared, without believing it.
 *
 * fatal:false because a charset that lies about its own content is ordinary
 * hostile input: the replacement characters are the honest rendering of bytes
 * that were not what the label said. A charset label TextDecoder does not
 * know falls back to UTF-8 — reading the bytes wrongly-but-inertly beats
 * refusing to read them at all.
 *
 * The charsets only mail declares get there first, in js/decode.js. TextDecoder
 * refuses those on a browser's reasoning that does not reach this program, and
 * inheriting the refusal meant reading a Korean body as ASCII noise.
 */
function decodeCharset(bytes, charset) {
  const mail = decodeMailCharset(bytes, charset);
  if (mail !== null) return mail;

  let decoder;
  try {
    decoder = new TextDecoder(charset || 'utf-8', { fatal: false });
  } catch {
    decoder = new TextDecoder('utf-8', { fatal: false });
  }
  return decoder.decode(bytes);
}

// ----------------------------------------------------------------- parameters

/** `text/html; charset="utf-8"; boundary=b` → its type and the parameters used here. */
function parseContentType(value) {
  const raw = String(value ?? '').trim();
  const type = raw.match(/^([A-Za-z0-9!#$&^_.+-]{1,64}\/[A-Za-z0-9!#$&^_.+-]{1,64})/)?.[1]?.toLowerCase()
    ?? 'text/plain';
  return {
    type,
    charset: parameter(raw, 'charset')?.toLowerCase() ?? null,
    boundary: parameter(raw, 'boundary'),
    name: parameter(raw, 'name'),
    extendedName: extendedParameter(raw, 'name'),
    continuationName: continuationParameter(raw, 'name'),
  };
}

function parseDisposition(value, contentType) {
  const raw = String(value ?? '').trim();
  // Continuation first, then single-extended, then plain — the order a
  // conformant client prefers when more than one form is present, so the tool
  // reads the name the client would act on rather than a decoy alongside it.
  const name = continuationParameter(raw, 'filename')
    ?? extendedParameter(raw, 'filename') ?? parameter(raw, 'filename')
    ?? contentType.continuationName ?? contentType.extendedName ?? contentType.name;
  // `size=` is optional and most mailers never write it. `Number(null)` is 0,
  // so an absent parameter passed the safe-integer check as a stated size of
  // zero, `bytesDeclared` never fell through to the size actually decoded, and
  // the attachment inventory printed "0 bytes" for an ordinary PDF — the
  // honest "size unstated" branch was unreachable in exactly the common case.
  const declared = parameter(raw, 'size');
  const size = declared === null ? null : Number(declared);
  return {
    disposition: raw.match(/^([A-Za-z-]{1,32})/)?.[1]?.toLowerCase() ?? null,
    // RFC 2047 in a filename is nonstandard and everywhere; decoding it is
    // what makes `=?utf-8?B?...?=.pdf` legible enough to warn about.
    filename: name ? decodeEncodedWords(name).slice(0, 255) : null,
    size: size !== null && Number.isSafeInteger(size) && size >= 0 ? size : null,
  };
}

/**
 * One MIME parameter, quoted or bare. Bounds on every quantifier: parameter
 * values are sender-written and a header field can be 100 KB long.
 */
function parameter(value, name) {
  const match = String(value ?? '').match(
    new RegExp(`[;\\s]\\s*${name}\\s*=\\s*(?:"([^"]{0,1024})"|([^;\\s]{1,1024}))`, 'i'),
  );
  return match ? (match[1] ?? match[2]) : null;
}

/**
 * The RFC 2231 extended form, `name*=charset''percent-encoded`, decoded as
 * UTF-8 — which is what real senders emit. A value that fails to decode is
 * returned as it stands rather than dropped.
 */
function extendedParameter(value, name) {
  const match = String(value ?? '').match(
    new RegExp(`[;\\s]\\s*${name}\\*=\\s*(?:"([^"]{0,1024})"|([^;\\s]{1,1024}))`, 'i'),
  );
  if (!match) return null;
  const raw = match[1] ?? match[2];
  const encoded = raw.match(/^[^']{0,40}'[^']{0,40}'([\s\S]*)$/)?.[1];
  if (encoded === undefined) return raw;
  try {
    return decodeURIComponent(encoded);
  } catch {
    return encoded;
  }
}

/**
 * The RFC 2231 §3 continuation form, `name*0=…; name*1=…`, reassembled.
 *
 * A long or non-ASCII parameter is split across numbered segments, and a
 * conformant client concatenates them in index order before acting on the
 * result. This tool read only `filename=` and the single `filename*=`, so a
 * name written as `filename*0="report."; filename*1="exe"` matched neither: the
 * part came out with no filename at all, the `$`-anchored executable check ran
 * on "(unnamed)", and the attachment card went silent on a file the client
 * saves and runs as report.exe — the same false reassurance as the language-tag
 * gap, one RFC section over.
 *
 * A segment key ending in `*` (`name*0*=`) is percent-encoded; the first such
 * segment carries a `charset'language'` prefix that governs the whole value and
 * is stripped. Runs of encoded segments are decoded together, so a percent
 * escape split across a segment boundary still decodes. Returns null when no
 * continuation segment is present, so the caller falls through to the plain form.
 */
function continuationParameter(value, name) {
  const raw = String(value ?? '');
  const re = new RegExp(
    `[;\\s]\\s*${name}\\*(\\d{1,3})(\\*?)\\s*=\\s*(?:"([^"]{0,1024})"|([^;\\s]{1,1024}))`,
    'gi',
  );
  const segments = [];
  let match;
  while ((match = re.exec(raw)) !== null) {
    segments.push({ index: Number(match[1]), encoded: match[2] === '*', text: match[3] ?? match[4] });
  }
  if (!segments.length) return null;
  segments.sort((a, b) => a.index - b.index);

  let firstEncoded = true;
  let out = '';
  let encRun = '';
  const flush = () => {
    if (!encRun) return;
    try { out += decodeURIComponent(encRun); } catch { out += encRun; }
    encRun = '';
  };
  for (const seg of segments) {
    if (seg.encoded) {
      let enc = seg.text;
      if (firstEncoded) { enc = enc.replace(/^[^']{0,40}'[^']{0,40}'/, ''); firstEncoded = false; }
      encRun += enc;
    } else {
      flush();
      out += seg.text;
    }
  }
  flush();
  return out;
}

function normalEncoding(value) {
  const encoding = String(value ?? '').trim().toLowerCase();
  return encoding || null;
}
