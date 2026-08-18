// Parsing of a pasted email header block into ordered name/value pairs.
//
// Deliberately more forgiving than RFC 5322, because the input is whatever the
// user's mail client put on the clipboard — which is routinely re-indented,
// missing its continuation whitespace, or carrying a stray line whose field
// name got lost in the copy.

// RFC 5322 field name: printable ASCII except ':'. Localised names may contain
// spaces and accents ("Antwort an:", "Répondre à:"), so the pattern is widened
// and the result checked against the alias table below.
const FIELD_START = /^([!-9;-~]+):[ \t]?([\s\S]*)$/;
const LOCALISED_FIELD_START = /^([\p{L}][\p{L} \t-]{1,24}):[ \t]?([\s\S]*)$/u;

/**
 * Localised field names, as mail clients display them.
 *
 * Copying "All Headers" out of a localised Apple Mail or Outlook yields the
 * translated labels for the handful of fields the client renders itself. Those
 * are exactly the fields that matter most here — without this table a German
 * paste loses its From and Reply-To, and the most useful finding of all (that
 * replies go somewhere unexpected) silently never fires.
 */
const FIELD_ALIASES = new Map(Object.entries({
  // German
  'an': 'To', 'von': 'From', 'betreff': 'Subject', 'antwort an': 'Reply-To',
  'kopie': 'Cc', 'blindkopie': 'Bcc', 'datum': 'Date', 'gesendet': 'Date',
  'antwort-an': 'Reply-To', 'empfänger': 'To', 'absender': 'From',
  // French
  'de': 'From', 'objet': 'Subject', 'répondre à': 'Reply-To', 'copie': 'Cc',
  // Spanish / Portuguese
  'para': 'To', 'asunto': 'Subject', 'responder a': 'Reply-To', 'fecha': 'Date',
  'assunto': 'Subject', 'responder para': 'Reply-To',
  // Italian
  'oggetto': 'Subject', 'rispondi a': 'Reply-To',
  // Dutch
  'aan': 'To', 'onderwerp': 'Subject', 'antwoorden aan': 'Reply-To',
}));

/**
 * How much pasted text is read before the rest is ignored.
 *
 * Not a defence against slow input — the patterns this analysis runs are all
 * linear now, and 1 MB of hostile header measures 426 ms end to end. It is a
 * bound on how long the page can stop responding, since `analyse` runs on the
 * browser's main thread with no worker behind it.
 *
 * Set where a real header cannot reach it. Postfix caps a single logical header
 * at 102400 octets and does not cap how many there are, so a delivered message
 * can legitimately run to a few hundred kilobytes; a megabyte is ten times the
 * largest header worth reading and still returns inside half a second.
 */
export const MAX_HEADER_BYTES = 1024 * 1024;

/** Canonical field name for a label, or null when it is not a known field. */
function canonicalise(name) {
  return FIELD_ALIASES.get(name.trim().toLowerCase()) ?? null;
}

/**
 * Strip the indentation that every line shares.
 *
 * Pasting from a chat message or a code block often indents the whole block by
 * a fixed amount. Without this, every line looks like a folded continuation and
 * the entire header collapses into one giant value.
 */
export function dedent(text) {
  const lines = text.split(/\r\n|\r|\n/);
  let common = Infinity;
  for (const line of lines) {
    if (!line.trim()) continue;
    const indent = line.length - line.replace(/^[ \t]+/, '').length;
    if (indent < common) common = indent;
    if (common === 0) break;
  }
  if (!isFinite(common) || common === 0) return lines;
  return lines.map((line) => line.slice(common));
}

/**
 * Parse a header block.
 *
 * Returns an array of {name, value, raw, line} in original order. Duplicates are
 * preserved — `Received` and `Authentication-Results` legitimately repeat, and
 * their repetition is often the interesting part.
 */
/**
 * Parse a header block, and account for every line of it.
 *
 * `parseHeaders` below is this without the accounting, kept because most
 * callers only want the fields. The accounting exists because of the way this
 * function fails: it stops at the first line it reads as a boundary and returns
 * what it had, and everything after that simply is not in the answer. Nothing
 * said so. A ten-field header with one stray space in the middle analysed as
 * six fields and reported "6 header fields read" in the same confident tone as
 * a complete one — and the four it dropped were the authentication results, a
 * lookalike Reply-To and an unsubscribe link pointing at a login page.
 *
 * A narrower answer than the reader asked for is the failure this whole project
 * is written against. It cannot also be the failure of the parser reporting it.
 */
export function readHeaders(text) {
  const lines = dedent(String(text ?? ''));
  const headers = [];
  const skipped = { lines: 0, reason: null };
  let current = null;
  let inBody = false;

  const flush = () => {
    if (!current) return;
    // Unfold: join continuations with a single space (RFC 5322 keeps the
    // leading whitespace; collapsing it is what every decoder wants anyway).
    current.value = current.parts.join(' ').trim();
    current.raw = current.rawParts.join('\n');
    delete current.parts;
    delete current.rawParts;
    headers.push(current);
    current = null;
  };

  lines.forEach((line, index) => {
    if (inBody) {
      // Counted rather than ignored: this is the number the reader needs in
      // order to know whether the answer covers what they pasted.
      if (line.length) skipped.lines += 1;
      return;
    }

    if (!line.trim()) {
      // A blank line ends the header block and starts the body. Everything
      // after it is message content we deliberately do not touch — a Subject:
      // quoted inside a reply must not be mistaken for a real field.
      if (headers.length || current) {
        flush();
        inBody = true;
        // Which kind of boundary it was. An empty line is the one RFC 5322
        // defines; a line of spaces or tabs is obs-FWS, which several clients
        // emit mid-header and which this parser treats the same way. The
        // distinction matters to a reader deciding whether the paste was
        // truncated or the message simply ended.
        skipped.reason = line.length ? 'a line containing only whitespace' : 'a blank line';
      }
      return;
    }

    // Only leading whitespace makes a continuation. Without this rule a bare
    // `<message-id@host>` line gets silently glued onto whichever field
    // happened to precede it, and its content disappears from the analysis.
    if (/^[ \t]/.test(line) && current) {
      current.parts.push(line.trim());
      current.rawParts.push(line);
      return;
    }

    const match = line.match(FIELD_START);
    const localised = match ? null : line.match(LOCALISED_FIELD_START);
    const alias = localised ? canonicalise(localised[1]) : null;
    flush();

    if (match) {
      // Short localised names ("An", "Von", "Datum") are valid RFC field names
      // too, so the alias table has to be consulted here as well — not only on
      // the localised path, which only catches names containing spaces.
      const canonical = canonicalise(match[1]);
      current = {
        name: canonical ?? match[1],
        parts: [match[2] ?? ''],
        rawParts: [line],
        line: index + 1,
        ...(canonical ? { displayedAs: match[1] } : {}),
      };
    } else if (alias) {
      current = {
        name: alias,
        parts: [localised[2] ?? ''],
        rawParts: [line],
        line: index + 1,
        displayedAs: localised[1],
      };
    } else {
      // A value whose field name was lost in the copy — keep it, because it is
      // usually the Message-ID or the sender line, and both are worth reading.
      current = {
        name: '(unlabelled)',
        parts: [line.trim()],
        rawParts: [line],
        line: index + 1,
        synthetic: true,
      };
    }
  });

  flush();
  return { headers: promoteLeadingSender(resolveAliasConflicts(headers)), skipped };
}

/**
 * What to tell the reader about the lines that were not read.
 *
 * Empty when nothing was dropped, so a caller can append it unconditionally.
 * Written once here rather than in each renderer, because the last time one
 * claim lived in two places they had already drifted before anyone looked.
 */
export function skippedNote({ lines, reason }) {
  if (!lines) return '';
  return ` ${lines} further line${lines === 1 ? '' : 's'} were treated as message body, after ${reason}.`;
}

/** The fields alone, for the callers that have no use for the accounting. */
export function parseHeaders(text) {
  return readHeaders(text).headers;
}

/**
 * Stop a localised label from outranking the field it is a translation of.
 *
 * The alias table exists for a paste that lost its English labels — an Apple
 * Mail window that renders `Von:` and never shows `From:`. It was never meant
 * to arbitrate between the two, and left to do so it arbitrates badly: `get()`
 * returns the first match, so a line the sender invented wins over the field
 * the mail actually carries.
 *
 * That is reachable. `De:` is a syntactically valid optional header, so it
 * survives every relay untouched and no client displays it; placed above the
 * real `From:`, it silently removes the finding that says a reply would go
 * somewhere unexpected — which is the single most useful thing this tool says.
 *
 * So an alias yields whenever the real field is present, and keeps the name the
 * sender actually wrote. The value is not discarded: an unexplained `De:` in a
 * header is worth seeing, it is just not a From.
 */
function resolveAliasConflicts(headers) {
  const stated = new Set(
    headers.filter((h) => !h.displayedAs).map((h) => h.name.toLowerCase()),
  );
  if (!stated.size) return headers;

  return headers.map((header) => {
    if (!header.displayedAs || !stated.has(header.name.toLowerCase())) return header;
    const { displayedAs, ...rest } = header;
    return { ...rest, name: displayedAs, aliasOverruled: header.name };
  });
}

/**
 * Treat an unlabelled leading `Name <addr@host>` line as the From field.
 *
 * Mail clients print the sender above the header block without a label. Left
 * unclaimed, the sender is missing entirely — which suppresses the Reply-To
 * comparison and risks the sender's own address being reported as a hidden
 * recipient.
 */
function promoteLeadingSender(headers) {
  if (headers.some((h) => h.name.toLowerCase() === 'from')) return headers;

  const index = headers.findIndex((h) => h.synthetic);
  if (index === -1 || index > 1) return headers;

  const candidate = headers[index];
  if (!/^[^<>@]*<[^<>@\s]+@[^<>@\s]+\.[A-Za-z]{2,}>$/.test(candidate.value.trim())) {
    return headers;
  }
  // A colon before the address means the line carried a field name we did not
  // recognise — `X Foo: PayPal Security <security@paypal.com>` — and promoting
  // that to From lets a sender put any name they like where the reader expects
  // the one the message actually claims.
  if (/^[^<]*:/.test(candidate.raw ?? candidate.value)) return headers;

  headers[index] = { ...candidate, name: 'From', synthetic: false, inferred: true };
  return headers;
}

/** All values for a field name, case-insensitively, in document order. */
export function getAll(headers, name) {
  const wanted = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === wanted).map((h) => h.value);
}

/** First value for a field name, or '' when absent. */
export function get(headers, name) {
  return getAll(headers, name)[0] ?? '';
}
