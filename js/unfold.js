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
export function parseHeaders(text) {
  const lines = dedent(String(text ?? ''));
  const headers = [];
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
    if (inBody) return;

    if (!line.trim()) {
      // A blank line ends the header block and starts the body. Everything
      // after it is message content we deliberately do not touch — a Subject:
      // quoted inside a reply must not be mistaken for a real field.
      if (headers.length || current) {
        flush();
        inBody = true;
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
  return promoteLeadingSender(headers);
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
