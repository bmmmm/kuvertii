// Header → findings. This module is the product; everything else is plumbing.
//
// Each finding states what was found, what it means, and which header it came
// from. The tone is dry rather than alarmed: the goal is for someone to
// understand their own mail, not to be told what to feel about it.

import { hasControls, scanControls } from './control.js';
import { table } from './lookup.js';
import { bestDecode, clip, decodeIdentifier, decodeSegments, findAddresses, prettifyNulls } from './decode.js';
import { extractUrls, inspectUnsubscribeLink, registrableDomain } from './links.js';
import { filedAsUnwanted, microsoftVerdicts } from './microsoft.js';
import { identifyPlatformHeader, identifySender } from './senders.js';
import { get, getAll } from './unfold.js';

// Fields that legitimately name the recipient in the clear.
const RECIPIENT_FIELDS = [
  'to', 'cc', 'delivered-to', 'x-original-to', 'original-recipient',
  'envelope-to', 'x-envelope-to', 'x-rcpt-to', 'apparently-to',
];

// Fields naming the sender — addresses here are not recipients. The list-*
// administrative fields belong here too: they carry the list's own contact
// addresses, which would otherwise be reported as people this was sent to.
// `List-Unsubscribe` is deliberately absent, because its token is where the
// recipient's own address most often hides.
const SENDER_FIELDS = [
  'from', 'reply-to', 'sender', 'return-path', 'errors-to', 'x-sender',
  'list-owner', 'list-post', 'list-help', 'list-subscribe',
  // Reporting and abuse contacts belong to whoever runs the sending domain.
  // A DMARC record carries them as rua=/ruf= addresses, and reading those as
  // recipients puts a stranger's postmaster in the list of people this was
  // addressed to.
  'x-dmarc-policy', 'x-report-abuse', 'x-report-abuse-to',
  'x-complaints-to', 'abuse-reports-to',
];

/**
 * One section's worth of analysis, with its failure kept inside it.
 *
 * Thirteen producers share one array and, until this existed, one fate: a throw
 * anywhere took the whole report down and left the reader with a stack trace
 * instead of the twelve sections that had nothing wrong with them. That is
 * reachable from the header — `DKIM-Signature: t=99999999999999` is one field a
 * sender writes and controls, and it was enough.
 *
 * A caught throw is reported rather than swallowed, and reported as what it is:
 * not a fact about the message, but a fault in this tool. `absent` would be the
 * wrong level for it — that one means "the analysis could not do this", which
 * is a statement about the mail. This is a statement about us.
 *
 * Exported because a boundary nothing can test is a boundary nothing keeps:
 * test/findings.test.js drives it with a producer that throws on purpose, which
 * is the only way this path is reachable once the bugs behind it are fixed.
 */
export function guardSection(section, produce) {
  try {
    return produce();
  } catch (error) {
    return {
      id: `fault:${section}`,
      title: 'Part of this report could not be produced',
      tone: 'alert',
      lede: 'A section of this analysis failed while it ran. Everything else below was produced normally — but this report is now narrower than it looks, and the gap is ours rather than the message\'s.',
      items: [{
        label: `The ${section} section failed`,
        value: `${error?.name ?? 'Error'}: ${error?.message ?? String(error)}`,
        level: 'fault',
        note: 'This is a bug in kuvertii, not a finding about the message. Whatever that section would have told you about this header, it did not.',
      }],
    };
  }
}

export function analyse(headers) {
  const findings = [];
  const push = (section, produce) => {
    const finding = guardSection(section, produce);
    if (finding) findings.push(finding);
  };

  push('completeness', () => completenessFinding(headers));
  push('recipient', () => recipientFinding(headers));
  push('disclosure', () => disclosureFinding(headers));
  push('tracking', () => trackingFinding(headers));
  push('list', () => listFinding(headers));
  push('unsubscribe', () => unsubscribeFinding(headers));
  push('reply-to', () => replyToFinding(headers));
  push('origin', () => originFinding(headers));
  push('authentication', () => authFinding(headers));
  push('route', () => routeFinding(headers));
  push('judgement', () => judgementFinding(headers));

  // Both are computed last and read first. They qualify every finding above
  // them — if part of this report was written by the sender rather than derived
  // from the message, that has to be said before the rest of it is believed.
  const contradictions = guardSection('contradictions', () => contradictionFinding(headers));
  if (contradictions) findings.unshift(contradictions);

  // Necessarily after the others exist: the decoders turn values that were
  // ordinary base64 in the raw header into escape sequences, and those only
  // become visible once a finding has been built out of them.
  const controls = guardSection('control characters', () => controlCharacterFinding(headers, findings));
  if (controls) findings.unshift(controls);

  return findings;
}

// ---------------------------------------------------------------- contradictions

// RFC 5322 §3.6 permits each of these at most once. A second copy is not a
// formatting quirk: every one of them is a field some part of this analysis
// reads by taking the first match, so a duplicate is a way of answering a
// question before the real field gets to.
const SINGLETON_FIELDS = ['from', 'reply-to', 'to', 'cc', 'subject', 'date', 'message-id', 'sender'];

/**
 * Report a header that states the same thing twice, or states it in disguise.
 *
 * Two mechanisms, one consequence. A field repeated outright is the plain case.
 * The subtler one is a localised label — `De:`, `Von:`, `Antwort an:` — which is
 * a valid optional header that no relay strips and no client displays, and
 * which this parser used to accept as a translation of the field it names.
 * Either way the reader is shown one value while the message carries another.
 */
function contradictionFinding(headers) {
  const items = [];

  for (const field of SINGLETON_FIELDS) {
    const values = getAll(headers, field);
    if (values.length < 2) continue;
    items.push({
      label: `${field} appears ${values.length} times`,
      value: values.map((v, i) => `${i + 1}. ${clip(v, 120)}`).join('\n'),
      mono: true,
      level: 'caution',
      note: 'A message may carry each of these once. Mail software reading the first copy and mail software reading the last will disagree about who sent this.',
    });
  }

  // Return-Path is not in SINGLETON_FIELDS because two copies can be honest:
  // each final delivery prepends one, so a message forwarded out of a mailbox
  // carries the old one below the new. What cannot be honest-and-harmless is
  // two copies naming different addresses while nothing points that out — the
  // reader is shown one bounce address while the message carries another.
  const returnPaths = getAll(headers, 'return-path');
  if (new Set(returnPaths.map((v) => v.trim().toLowerCase())).size > 1) {
    items.push({
      label: `Return-Path appears ${returnPaths.length} times, naming different addresses`,
      value: returnPaths.map((v, i) => `${i + 1}. ${clip(v, 120)}`).join('\n'),
      mono: true,
      level: 'caution',
      note: 'One per delivery is expected, newest first. Everything below the first was written earlier — by a previous delivery, or by whoever sent the message.',
    });
  }

  // Set by js/unfold.js when a localised label was displaced by the real field.
  for (const header of headers.filter((h) => h.aliasOverruled)) {
    items.push({
      label: `${header.name} was written as if it were ${header.aliasOverruled}`,
      value: clip(header.value, 160),
      level: 'bad',
      chips: [header.name],
      note: `The message already carries a real ${header.aliasOverruled}, so this one was ignored. A label that reads as a translation, placed above the field it translates, is how a sender gets a reader to see an address the message does not actually use.`,
    });
  }

  if (!items.length) return null;

  return {
    id: 'contradictions',
    title: 'This header says the same thing twice',
    tone: 'alert',
    lede: 'Fields that may appear only once appear more than once. Which value counts depends on which program is reading, and that is the point of writing it this way.',
    items,
  };
}

// ----------------------------------------------------------- control characters

/** Every string in a finding that came, however indirectly, from the header. */
function* renderedText(findings) {
  for (const finding of findings) {
    for (const item of finding.items ?? []) {
      yield item.label;
      yield item.value;
      if (item.note) yield item.note;
      for (const chip of item.chips ?? []) yield chip;
    }
  }
}

/**
 * Report a header carrying characters that are instructions rather than text.
 *
 * Both renderers already print these inert — `neutralise` in js/control.js runs
 * on everything on its way to the screen, so nothing here is load-bearing for
 * safety. What it is load-bearing for is honesty. A sender who puts `ESC ] 52`
 * in a `List-ID` is trying to write the reader's clipboard; one who puts U+202E
 * in a hostname is trying to make the destination read as somebody else's. Both
 * are findings in their own right, and a tool that quietly cleaned them up
 * would be withholding the most direct evidence of intent in the whole header.
 *
 * Two passes, because there are two ways for these bytes to arrive. The header
 * fields catch what the sender wrote; the rendered findings catch what this
 * tool's own decoders produced, since a value of pure `[A-Za-z0-9+/=]` gives no
 * sign of the escape sequence it unpacks into.
 */
function controlCharacterFinding(headers, findings) {
  const items = [];
  const seen = new Set();

  for (const header of headers) {
    if (!hasControls(header.value)) continue;
    const effects = scanControls(header.value);
    effects.forEach((effect) => seen.add(effect));
    items.push({
      label: `${header.name} contains control characters`,
      value: `It ${effects.join('; it ')}.`,
      level: 'bad',
      chips: [header.name],
    });
  }

  // Anything the decoders unpacked. Reported as one row rather than per field:
  // the reader has already been told which fields were decoded, and the point
  // here is that the encoding was hiding this, not where it sat.
  const decoded = [];
  for (const text of renderedText(findings)) {
    if (!hasControls(text)) continue;
    for (const effect of scanControls(text)) {
      if (!seen.has(effect) && !decoded.includes(effect)) decoded.push(effect);
    }
  }
  if (decoded.length) {
    items.push({
      label: 'An encoded value unpacks into control characters',
      value: `Decoded, it ${decoded.join('; it ')}.`,
      level: 'bad',
      note: 'In the raw header this was ordinary-looking base64. The encoding is what kept it out of sight.',
    });
  }

  if (!items.length) return null;

  return {
    id: 'controls',
    title: 'This header carries instructions, not just text',
    tone: 'alert',
    lede: 'Some of these fields contain bytes that a terminal obeys as commands and a browser uses to reorder what you see. They are shown inert everywhere below — <1b> was an escape byte, <U+202E> reverses reading direction — so that reading this report cannot act on them.',
    items: [
      ...items,
      {
        label: 'Nothing puts these here by accident',
        value: 'Mail software does not emit escape sequences or bidi overrides into header fields. Their presence is a deliberate attempt to control the program that reads this message, which places everything else in this header in doubt.',
        level: 'caution',
      },
    ],
  };
}

// -------------------------------------------------------------- completeness

/**
 * Fields every delivered message carries, and what their absence costs.
 *
 * Missing one of these never means the message lacked it — it means the paste
 * stopped short. Which matters, because a partial header does not fail loudly:
 * it analyses fine and quietly answers a narrower question than the reader
 * thinks they asked.
 */
const EXPECTED_FIELDS = [
  ['from', 'From', 'without it, the sender is unknown, and addresses belonging to them can be mistaken for yours'],
  ['date', 'Date', 'no timezone, and no way to place the message in time'],
  ['message-id', 'Message-ID', 'the per-message identifier is missing'],
  ['received', 'Received', 'the route is missing entirely — that is usually the bulk of a header'],
];

// Every field that can name the recipient in the clear — the sender-written
// pair, the delivery stamps, and Original-Recipient (RFC 3798), which a real
// iCloud message carried while this list did not know it. That message
// rendered "no recipient is named in the clear" on one card while the card
// beneath it read the recipient openly out of Original-Recipient.
const RECIPIENT_PRESENT = ['to', 'cc', 'delivered-to', 'x-original-to', 'envelope-to', 'x-rcpt-to', 'original-recipient'];

// Fields naming the mailbox this copy was actually delivered to. Unlike To:,
// which the sender writes, these are added by the receiving side — so an
// address here is the reader, and every other name in To/Cc is somebody else.
const DELIVERY_FIELDS = ['delivered-to', 'x-original-to', 'envelope-to', 'x-rcpt-to'];

/**
 * Say so when the paste is only part of a header.
 *
 * Placed first deliberately. Everything below reports on what it was given, and
 * a reader who cannot see that half the header is absent will read those
 * findings as the whole answer.
 */
function completenessFinding(headers) {
  if (!headers.length) return null;

  const missing = EXPECTED_FIELDS.filter(([field]) => !get(headers, field));
  if (!RECIPIENT_PRESENT.some((field) => get(headers, field))) {
    missing.push(['to', 'To', 'no recipient is named in the clear, so there is nothing to compare the encoded copies against']);
  }

  // One absent field is ordinary — plenty of legitimate mail has no Message-ID
  // from a badly behaved sender, and a copied header often drops its last line.
  // Two or more mean something is genuinely absent.
  if (missing.length < 2) return null;

  // What kind of absence, though, depends on how much else came through. Mail
  // clients render From, To, Subject and Date above the header block rather
  // than inside it, so a complete copy of "all headers" can still arrive
  // without them. Thirty-eight fields is not a fragment; two is.
  const displayFieldsOnly = headers.length >= 12
    && missing.every(([field]) => ['from', 'to', 'date', 'message-id'].includes(field));

  return {
    id: 'completeness',
    title: displayFieldsOnly
      ? 'Your mail program kept a few fields to itself'
      : 'This looks like part of a header, not all of it',
    tone: 'info',
    lede: displayFieldsOnly
      ? `The rest of the header came through — ${headers.length} fields of it — so this is not a truncated paste. Mail clients display these particular fields above the header block instead of inside it, and copying "all headers" leaves them behind. Everything below is accurate; it simply had less to work with. Adding the missing lines by hand, in the form \`From: name@example.com\`, restores the findings that depend on them.`
      : `A delivered message always carries these fields, so their absence is a property of the paste rather than of the message. Everything below still holds for what was given — it is just answering a narrower question than it appears to. A full header runs to several dozen fields; this one has ${headers.length}.`,
    items: missing.map(([, name, cost]) => ({
      label: `${name} is missing`,
      value: cost,
      level: 'absent',
    })),
  };
}


/**
 * Addresses the receiving side recorded as the destination of this copy.
 *
 * `To:` is written by the sender and can say anything; these fields are added
 * on delivery, so an address here is the mailbox that actually received the
 * message. That makes it the one way to tell the reader apart from everyone
 * else named in the header.
 */
function readerAddresses(headers) {
  const reader = new Set();
  for (const field of DELIVERY_FIELDS) {
    for (const value of getAll(headers, field)) findAddresses(value).forEach((a) => reader.add(a));
  }
  for (const value of getAll(headers, 'received')) {
    const match = value.match(/\bfor\s+<([^>]+)>/i);
    if (match) findAddresses(match[1]).forEach((a) => reader.add(a));
  }
  return reader;
}

/**
 * Every address known to belong to this message's recipient side.
 *
 * The union the body analysis needs: what the sender wrote into the
 * recipient fields plus what the receiving side stamped on delivery. A body
 * link carrying one of these — open, encoded, or hashed — identifies the
 * reader, and that comparison cannot be made without this set.
 */
export function knownRecipientAddresses(headers) {
  const known = new Set(readerAddresses(headers));
  for (const field of RECIPIENT_FIELDS) {
    for (const value of getAll(headers, field)) {
      findAddresses(value).forEach((address) => known.add(address));
    }
  }
  return [...known];
}

// ---------------------------------------------------------------- recipients

function recipientFinding(headers) {
  const open = new Map(); // address -> [source fields]
  const hidden = new Map(); // address -> [{field, method}]

  const senderAddresses = new Set();
  for (const field of SENDER_FIELDS) {
    for (const value of getAll(headers, field)) {
      findAddresses(value).forEach((a) => senderAddresses.add(a));
    }
  }

  // The authentication headers name the envelope sender in passing, and that
  // matters most when the paste has lost its From: line — a partial header
  // otherwise reports the sender as a recipient hiding in encoded form, which
  // is both wrong and exactly backwards.
  for (const header of headers) {
    for (const [, claimed] of header.value.matchAll(
      /\b(?:envelope-from|smtp\.mailfrom|header\.from|rua|ruf)\s*=\s*(?:mailto:)?([^\s;,)]+)/gi,
    )) {
      findAddresses(claimed).forEach((a) => senderAddresses.add(a));
    }
  }

  for (const header of headers) {
    const field = header.name.toLowerCase();
    if (!RECIPIENT_FIELDS.includes(field)) continue;
    for (const address of findAddresses(header.value)) {
      if (!open.has(address)) open.set(address, []);
      open.get(address).push(header.name);
    }
  }

  // `Received: … for <addr>` records the envelope recipient at each hop — the
  // address the delivering server was actually told to hand this to.
  for (const value of getAll(headers, 'received')) {
    const match = value.match(/\bfor\s+<([^>]+)>/i);
    if (!match) continue;
    for (const address of findAddresses(match[1])) {
      if (!open.has(address)) open.set(address, []);
      if (!open.get(address).includes('Received (envelope)')) {
        open.get(address).push('Received (envelope)');
      }
    }
  }

  // Now the interesting part: addresses that were encoded rather than written.
  for (const header of headers) {
    if (SENDER_FIELDS.includes(header.name.toLowerCase())) continue;

    // Addresses already legible in this field, whatever the decoders make of
    // the rest of it. A decoder returns the whole value with one part changed,
    // so anything plainly written alongside an encoded token rides along in the
    // result — and was then reported as "never written openly, recoverable only
    // by decoding" about text sitting in the clear two lines above. Percent
    // decoding made this easy to hit, because one `%20` anywhere qualifies a
    // whole field, but the same was always true of base64 and quoted-printable.
    const inTheClear = new Set(findAddresses(header.value));

    const record = (text, method) => {
      for (const address of findAddresses(text)) {
        if (senderAddresses.has(address)) continue;
        if (inTheClear.has(address)) continue;
        if (BOUNCE_DOMAIN_RE.test(address.split('@')[1] ?? '')) continue;
        if (!hidden.has(address)) hidden.set(address, []);
        const entries = hidden.get(address);
        if (!entries.some((e) => e.field === header.name && e.method === method)) {
          entries.push({ field: header.name, method });
        }
      }
    };

    for (const candidate of decodeSegments(header.value)) {
      record(candidate.text, candidate.method);
    }

    // Tokens inside URLs — the unsubscribe link is the usual carrier.
    //
    // Two layers, because that is what a click tracker actually builds: the
    // destination is base64 inside the path, and the address inside *that* is
    // percent-encoded, because it sits in a query parameter. One pass found the
    // URL and stopped, so the tool would print the address plainly in the
    // decoded destination and, four lines higher, report one fewer hidden copy
    // than it had just shown. The reader had to spot the contradiction.
    for (const url of extractUrls(header.value)) {
      for (const segment of url.split(/[/?&=#]/)) {
        if (segment.length < 12) continue;
        const decoded = bestDecode(segment, 0.5);
        if (!decoded) continue;
        record(decoded.text, `${decoded.method} inside the URL`);

        // What the first pass produced is usually another URL. Splitting it the
        // same way and decoding again costs nothing and is where the address
        // normally is. Depth stops here: a third layer is not something senders
        // build, and every extra pass is another chance to decode a coincidence.
        for (const inner of decoded.text.split(/[/?&=#]/)) {
          if (inner.length < 12) continue;
          const twice = bestDecode(inner, 0.5);
          if (twice) record(twice.text, `${decoded.method}, then ${twice.method}, inside the URL`);
        }
      }
    }

    // VERP bounce addresses embed the recipient in their own local part, with
    // the @ written as = — `bounce-alice=example.com@sender.example`. The
    // pattern has to require a real domain after the =, otherwise every
    // `key=value` pair in an Authentication-Results line reads as an address.
    // Bounded, and preceded by a lookbehind, for the reason given at EMAIL_RE
    // in js/decode.js: an unanchored `+` over a character class the sender
    // controls the length of is quadratic, and header fields are long.
    for (const [, local, domain] of header.value.matchAll(
      /(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{1,64})=([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,10}\.[A-Za-z]{2,24})@/g,
    )) {
      const stripped = `${stripBouncePrefix(local)}@${domain}`;
      record(foldOntoKnownRecipient(stripped, open.keys()), 'VERP bounce address');
    }
  }

  if (!open.size && !hidden.size) return null;

  // Where an address was found is a list of short facts, not a sentence — it
  // goes into chips so the count is visible at a glance and the prose is left
  // to say the one thing prose is good for: what it means.
  const placeChips = (entries) => entries.map((e) => `${e.field} · ${e.method}`);

  // On a message addressed to a crowd, listing every name turns this card into
  // a directory and buries what it is for. The addresses that also appear
  // encoded are the point — those identify the reader — so they are kept, a
  // few plain ones are shown for context, and the rest is counted. The people
  // themselves are not dropped: the disclosure card is about exactly them.
  const OPEN_SHOWN = 4;
  const reader = readerAddresses(headers);
  // An address earns its own row by identifying this reader: it appears in
  // encoded form, or the receiving side recorded it as the destination.
  const identifying = ([address]) => hidden.has(address) || reader.has(address);

  const ranked = [...open].sort((a, b) => (identifying(b) ? 1 : 0) - (identifying(a) ? 1 : 0));
  const keep = ranked.filter(identifying).length;
  const visible = ranked.slice(0, keep || Math.min(OPEN_SHOWN, ranked.length));
  const omitted = ranked.length - visible.length;

  const items = [];
  for (const [address, fields] of visible) {
    const encodings = hidden.get(address) ?? [];
    items.push({
      label: address,
      value: `Written openly in ${[...new Set(fields)].join(', ')}`,
      chips: placeChips(encodings),
      note: encodings.length
        ? `Carried ${encodings.length} further ${encodings.length === 1 ? 'time' : 'times'} in encoded form.`
        : null,
      emphasis: encodings.length > 0,
    });
  }
  if (omitted) {
    items.push({
      label: `${omitted} further ${omitted === 1 ? 'address is' : 'addresses are'} named in the clear`,
      value: 'None of them carry encoded copies, so they are other recipients rather than this one.',
    });
  }
  for (const [address, entries] of hidden) {
    if (open.has(address)) continue;
    items.push({
      label: address,
      value: 'Never written openly — recoverable only by decoding',
      chips: placeChips(entries),
      emphasis: true,
    });
  }

  const encodedCount = [...hidden.values()].reduce((n, e) => n + e.length, 0);

  // The lede must not lean on a field the paste does not carry: measured on a
  // real message with no To: at all, it read "more times than the visible To:
  // field suggests" one card below "To is missing".
  const hasTo = Boolean(get(headers, 'to').trim());
  const times = `${encodedCount} ${encodedCount === 1 ? 'time' : 'times'}`;

  return {
    id: 'recipients',
    title: 'Who this was actually addressed to',
    tone: encodedCount ? 'alert' : 'info',
    lede: encodedCount
      ? hasTo
        ? `The recipient address appears ${encodedCount} more ${encodedCount === 1 ? 'time' : 'times'} than the visible To: field suggests, each one encoded. Encoding is not encryption — it is just a step that assumes nobody looks.`
        : `There is no To: field, and the recipient address still appears ${times} in encoded form. Encoding is not encryption — it is just a step that assumes nobody looks.`
      : 'The addresses this message names as its destination.',
    items,
  };
}

/**
 * Subdomains that exist to receive bounces, not people.
 *
 * `bounce.linkedin.com`, `em9672.sender.example` and the like are the sending
 * side's own return path. Nobody has a mailbox there, so an address on one is
 * never the reader — which the envelope-sender scan already establishes when
 * the header says `envelope-from=`. This catches the same address when it
 * arrives without that label, as it does in a partial paste.
 */
const BOUNCE_DOMAIN_RE = /^(?:bounces?|bnc|v?erp|reply|replies|mailer|em\d+|mta|smtp)\./i;

// Routing prefixes that VERP schemes put in front of the encoded recipient.
// Hyphens are legal in a local part, so the boundary cannot be guessed — only
// a known prefix may be removed, and anything else is left intact.
const BOUNCE_PREFIX_RE = /^(?:bounces?d?|return|returns|bnc|verp|prvs|msys|srs\d*|sb|fbl)[-_.]/i;

function stripBouncePrefix(local) {
  let out = local;
  // Repeat: `bounce-return-alice` occurs in the wild.
  for (let i = 0; i < 3 && BOUNCE_PREFIX_RE.test(out); i++) {
    out = out.replace(BOUNCE_PREFIX_RE, '');
  }
  return out || local;
}

/**
 * Fold a VERP extraction onto the recipient it actually names.
 *
 * Real schemes put routing ids between the prefix and the address —
 * `bounces+31859940-8aa2-alice=example.org@…` — and no prefix table can know
 * where those ids end. Guessing risks mangling a local part that legitimately
 * starts with digits, and leaving it alone reports the same person twice, once
 * under a name they would not recognise as their own.
 *
 * So it is not guessed: if a recipient already found in the clear sits at the
 * end of the local part, on a separator, this is that recipient.
 */
function foldOntoKnownRecipient(address, known) {
  const at = address.lastIndexOf('@');
  const local = address.slice(0, at);
  const domain = address.slice(at + 1);

  for (const candidate of known) {
    const candidateAt = candidate.lastIndexOf('@');
    const candidateLocal = candidate.slice(0, candidateAt);
    if (candidate.slice(candidateAt + 1) !== domain) continue;
    if (candidateLocal === local || !local.endsWith(candidateLocal)) continue;

    const boundary = local[local.length - candidateLocal.length - 1];
    if (/[-_.+]/.test(boundary ?? '')) return candidate;
  }
  return address;
}

// ---------------------------------------------------------------- disclosure

/**
 * Who else was shown your address.
 *
 * `To:` and `Cc:` are visible to every recipient at once, so a message with
 * twenty names in them has handed each of those people the other nineteen. It
 * is the most ordinary privacy failure in email and the least remarked upon —
 * the sender had `Bcc` available and did not reach for it.
 */
function disclosureFinding(headers) {
  const everyone = new Map(); // address -> field it appeared in
  for (const field of ['to', 'cc']) {
    for (const value of getAll(headers, field)) {
      for (const address of findAddresses(value)) {
        if (!everyone.has(address)) everyone.set(address, field === 'cc' ? 'Cc' : 'To');
      }
    }
  }
  if (everyone.size < 2) return null;

  const reader = readerAddresses(headers);
  const others = [...everyone].filter(([address]) => !reader.has(address));
  if (!others.length) return null;

  const inCc = others.filter(([, field]) => field === 'Cc').length;
  const shown = others.slice(0, 6);

  const items = shown.map(([address, field]) => ({ label: address, value: `named in ${field}` }));
  if (others.length > shown.length) {
    items.push({
      label: `and ${others.length - shown.length} more`,
      value: 'Listed in the same fields, and visible to everyone who received this.',
    });
  }

  return {
    id: 'disclosure',
    title: `Your address was shown to ${others.length} other ${others.length === 1 ? 'person' : 'people'}`,
    tone: others.length > 5 ? 'alert' : 'info',
    lede: inCc
      ? 'Everyone named in To and Cc can read every other name there, including yours. Bcc exists precisely so that this does not happen, and the sender chose not to use it — most likely without noticing.'
      : 'Everyone named in To can read every other name there, including yours. Bcc exists precisely so that this does not happen.',
    items,
  };
}

// ------------------------------------------------------------------ tracking

function trackingFinding(headers) {
  const items = [];

  const returnPath = get(headers, 'return-path');
  if (returnPath && /[-=][0-9a-f]{6,}/i.test(returnPath)) {
    items.push({
      label: 'Return-Path carries a per-recipient id',
      value: returnPath,
      note: 'Bounces come back to an address unique to you (VERP). It tells the sender which recipient bounced without asking the bounce message.',
    });
  }

  for (const field of ['feedback-id', 'x-feedback-id']) {
    const value = get(headers, field);
    if (value) {
      items.push({
        label: 'Feedback-ID',
        value,
        note: 'Identifies sender, campaign and customer account to the mailbox provider. Used to attribute spam complaints.',
      });
    }
  }

  // Mailer fields habitually repeat one payload across several headers
  // (`X-Mailer-Info`, then `-Extra`, sometimes more). Listing each separately
  // fills the card with the same decoded string; grouping by content states it
  // once and names every field it turned up in.
  const mailerGroups = new Map();
  for (const header of headers) {
    if (!/^x-mailer-info/i.test(header.name)) continue;
    const decoded = decodeSegments(header.value).slice(0, 4);
    if (!decoded.length) continue;

    const body = decoded.map((d) => prettifyNulls(d.text)).join('\n');
    if (!mailerGroups.has(body)) mailerGroups.set(body, { fields: [], methods: new Set() });
    const group = mailerGroups.get(body);
    group.fields.push(header.name);
    decoded.forEach((d) => group.methods.add(d.method));
  }
  for (const [body, group] of mailerGroups) {
    items.push({
      label: group.fields.join(', '),
      value: body,
      chips: [...group.methods],
      note: 'Campaign metadata, stored backwards so it does not read as text at a glance.',
      mono: true,
    });
  }

  const messageId = get(headers, 'message-id') || get(headers, '(unlabelled)');
  if (/^<?mid-[0-9a-f]{16,}/i.test(messageId)) {
    items.push({
      label: 'Message-ID is a generated tracking id',
      value: messageId,
      note: 'Not a random id — it is the send record\'s primary key on the sender\'s side.',
    });
  }

  // Platform-specific recipient keys. Every suite stamps its own; naming the
  // platform is what makes the id legible, because it says which system holds
  // a record about this address and what that record is called there.
  const seen = new Set(items.map((i) => i.label.toLowerCase()));
  for (const header of headers) {
    const identified = identifyPlatformHeader(header.name);
    if (!identified || !header.value.trim()) continue;
    if (seen.has(header.name.toLowerCase())) continue;
    seen.add(header.name.toLowerCase());

    items.push({
      label: header.name,
      value: clip(header.value),
      chips: identified.platform ? [identified.platform] : [],
      note: identified.meaning,
      mono: true,
    });
  }

  if (!items.length) return null;

  return {
    id: 'tracking',
    title: 'This copy belongs to you alone',
    tone: 'alert',
    lede: 'Nothing here is shared with other recipients. Every id below is unique to your copy, which is how a reply, a bounce, a click or an unsubscribe gets attributed back to your address.',
    items,
  };
}

// ---------------------------------------------------------------------- list

// RFC 2919 puts the identifier in angle brackets, with an optional human
// description in front of it: `Weekly deals <deals.list.example.com>`.
/**
 * Split a List-ID into its description and its identifier (RFC 2919).
 *
 * Index arithmetic rather than a regex. The obvious pattern for this —
 * `^\s*(.*?)\s*<([^>]+)>\s*$` — pairs a lazy `.*?` with a trailing anchor,
 * which makes the engine retry the whole tail at every position: a List-ID of
 * `a` + 40 000 spaces + `a` cost 3.3 seconds on its own, and a browser runs
 * this on the main thread. The same rule expressed by position is linear.
 */
function splitListId(raw) {
  const value = String(raw ?? '').trim();
  if (!value.endsWith('>')) return null;
  const open = value.lastIndexOf('<');
  if (open === -1) return null;
  const identifier = value.slice(open + 1, -1);
  if (!identifier) return null;
  return { description: value.slice(0, open).trim(), identifier };
}

const LIST_CONTEXT = [
  ['list-owner', 'Run by', 'The address that answers for this list — usually a person rather than a no-reply.'],
  ['list-post', 'Posting address', 'Where messages to the list itself go. Its presence means this is a discussion list, not a one-way broadcast.'],
  ['list-archive', 'Public archive', 'Messages to this list are kept somewhere readable. Anything you post to it is published.'],
  ['list-help', 'Help address', null],
  ['list-subscribe', 'Subscribe address', null],
];

/**
 * What the list headers say about the subscription behind this message.
 *
 * `List-Unsubscribe` gets its own card because leaving is the action people
 * want. This one answers the prior question: which list is this, and what did
 * the sender name it? The identifier is chosen internally and never meant to
 * be read, so it is often the most candid line in the whole header — segment
 * names like `reactivation` or `inactive-90d` say plainly how you are filed.
 */
function listFinding(headers) {
  const rawId = get(headers, 'list-id');
  const items = [];

  if (rawId) {
    const parts = splitListId(rawId);
    const identifier = parts?.identifier ?? rawId;
    const description = parts?.description.replace(/^"|"$/g, '').trim();

    items.push({
      label: 'List identifier',
      value: identifier,
      note: 'Assigned by the sender and stable across mailings, so it is the same string every message from this list carries.',
      mono: true,
      emphasis: true,
    });

    if (description) {
      items.push({
        label: 'The sender calls it',
        value: description,
        note: 'The description they chose to put in the header, which need not match the name on the sign-up form.',
      });
    }
  }

  for (const [field, label, note] of LIST_CONTEXT) {
    const value = get(headers, field);
    // These arrive as `<mailto:owner@host>` or `<https://…>`. The brackets and
    // the scheme are RFC packaging, not information.
    const bare = value.replace(/^<|>$/g, '').replace(/^mailto:/i, '').trim();
    if (bare) items.push({ label, value: clip(bare), note });
  }

  if (!items.length) return null;

  return {
    id: 'list',
    title: 'The list you are on',
    tone: 'info',
    lede: 'These headers describe the subscription rather than the message. They are set once per list, which means every copy that reaches you names the same record on the sender\'s side.',
    items,
  };
}

// --------------------------------------------------------------- unsubscribe

function unsubscribeFinding(headers) {
  const raw = getAll(headers, 'list-unsubscribe').join(' ');
  if (!raw) return null;

  const fromDomain = (findAddresses(get(headers, 'from'))[0] ?? '').split('@')[1] ?? '';
  // RFC 8058 §3 defines exactly one value for this header. A substring test
  // accepted anything containing the words, so `List-Unsubscribe-Post:
  // definitely-not-one-click` bought the full green endorsement — a phish could
  // manufacture the reassurance with one fabricated header.
  const hasOneClick = /^\s*List-Unsubscribe\s*=\s*One-Click\s*$/i
    .test(get(headers, 'list-unsubscribe-post'));
  const items = [];
  const hosts = new Set();

  for (const url of extractUrls(raw)) {
    const report = inspectUnsubscribeLink(url, { fromDomain, hasOneClickHeader: hasOneClick });
    (report.hostsToCheck ?? []).forEach((h) => hosts.add(h));
    if (report.destination && report.destination !== url) {
      items.push({
        label: 'Real destination behind the redirect',
        value: report.destination,
        chips: ['decoded from the link', 'no request made'],
        mono: true,
      });
    }
    for (const signal of report.signals) {
      items.push({ label: signal.title, value: signal.detail, level: signal.level });
    }
  }

  if (!items.length) return null;

  return {
    id: 'unsubscribe',
    title: 'Where the unsubscribe link really goes',
    tone: items.some((i) => i.level === 'bad') ? 'alert' : 'info',
    lede: hasOneClick
      ? 'This sender supports one-click unsubscribe (RFC 8058). Prefer your mail client\'s own unsubscribe button over the link in the message body: it posts to the same address, so the sender still learns you acted, but it carries no cookies, no login and no browser fingerprint, and it never opens the page.'
      : 'Checked by taking the link apart, not by visiting it. Nothing was sent anywhere.',
    items,
    // Resolved asynchronously against the offline blocklist once the page has it.
    hostsToCheck: [...hosts],
  };
}

// ------------------------------------------------------------------ reply-to

function replyToFinding(headers) {
  const from = get(headers, 'from');
  const replyTo = get(headers, 'reply-to');
  if (!replyTo) return null;

  // Set by js/unfold.js when there was no From field and an unlabelled line at
  // the top of the paste was read as one.
  const fromInferred = Boolean(
    headers.find((h) => h.name.toLowerCase() === 'from')?.inferred,
  );

  const fromAddress = findAddresses(from)[0];
  const replyAddress = findAddresses(replyTo)[0];
  if (!fromAddress || !replyAddress || fromAddress === replyAddress) return null;

  const fromDomain = registrableDomain(fromAddress.split('@')[1] ?? '');
  const replyDomain = registrableDomain(replyAddress.split('@')[1] ?? '');
  if (fromDomain === replyDomain) return null;

  return {
    id: 'reply-to',
    title: 'Your reply would go to a different organisation',
    tone: 'alert',
    lede: 'The visible sender and the address that receives replies are on unrelated domains. Sometimes that is a mailing platform doing its job — and sometimes it is the entire trick, because the reply is the part a filter never sees.',
    items: [
      {
        label: fromInferred ? 'Appears to be from (inferred)' : 'Appears to be from',
        value: `${fromAddress}  (${fromDomain})`,
        // The `inferred` flag has existed in js/unfold.js since the promotion
        // was written and was read by nothing. A sender the parser guessed at,
        // presented as one the message stated, is the wrong kind of confident.
        note: fromInferred
          ? 'No From field was present. This was taken from an unlabelled line at the top of the paste, the way a mail client prints the sender above the header block — so it is this tool\'s reading, not the message\'s claim.'
          : null,
      },
      { label: 'Replies actually reach', value: `${replyAddress}  (${replyDomain})`, emphasis: true },
    ],
  };
}

// ------------------------------------------------------------------ origin

// Client IP as various providers record it. Webmail interfaces are the usual
// source: the browser connects over HTTP, and the gateway writes the address
// it saw into the outgoing message.
// Spelled out rather than derived from the field name, because deriving turns
// `x-originating-ip` into "Originating ip".
const CLIENT_IP_FIELDS = [
  ['x-originating-ip', 'Originating IP'],
  ['x-original-ip', 'Original IP'],
  ['x-sender-ip', 'Sender IP'],
  ['x-source-ip', 'Source IP'],
  ['x-remote-ip', 'Remote IP'],
  ['x-client-ip', 'Client IP'],
  ['x-originating-email', 'Originating address'],
];

const PRIVATE_IP_RE = /^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|::1$|f[cd])/i;

// Named in full, because `Priority` and `X-Priority` are different fields and
// stripping the prefix would print one under the other's name.
const URGENCY_FIELDS = [
  ['x-priority', 'X-Priority'],
  ['x-msmail-priority', 'X-MSMail-Priority'],
  ['importance', 'Importance'],
  ['priority', 'Priority'],
];

/**
 * The machine and program that composed the message.
 *
 * On mail you received this describes the sender. The reason it belongs in a
 * tool about *your* header is the symmetry: these are the same fields your own
 * client writes into everything you send, so the card doubles as a look at
 * what you hand over with every reply. Said plainly, without pretending the
 * address belongs to the reader when it does not.
 */
function originFinding(headers) {
  const items = [];

  // RFC 8689. A sender-set header whose only function is to ask every relay on
  // the route to deliver without encryption, and to disregard the recipient's
  // own MTA-STS and DANE policy while doing so. It belongs on this card because
  // it is the same category as everything else here: something the sending side
  // chose to say about itself.
  if (/^\s*no\b/i.test(get(headers, 'tls-required'))) {
    items.push({
      label: 'The sender asked for this to travel unencrypted',
      value: 'TLS-Required: No instructs every relay along the way to deliver even if it cannot negotiate TLS, and to ignore any policy you publish saying otherwise.',
      note: 'RFC 8689 added this for senders whose mail is worth less than the risk of it bouncing. On a message about an account or a payment, it is worth asking why.',
      level: 'caution',
      emphasis: true,
    });
  }

  for (const [field, label] of CLIENT_IP_FIELDS) {
    for (const value of getAll(headers, field)) {
      // Providers bracket the address: `X-Originating-IP: [203.0.113.5]`.
      const address = value.replace(/^\[|\]$/g, '').trim();
      if (!address) continue;

      const isPrivate = PRIVATE_IP_RE.test(address);
      items.push({
        label,
        value: address,
        note: isPrivate
          ? 'A private address, so it names a machine inside the sender\'s network rather than one reachable from outside.'
          : 'The address of the device that submitted the message, recorded by the provider that accepted it. It survives into every copy — nothing downstream removes it.',
        level: isPrivate ? null : 'caution',
        emphasis: !isPrivate,
      });
    }
  }

  const mailer = get(headers, 'user-agent') || get(headers, 'x-mailer');
  if (mailer) {
    const versioned = /\d+\.\d+/.test(mailer);
    items.push({
      label: 'Composed with',
      value: clip(mailer),
      note: versioned
        ? 'Named down to the version. On personal mail this pins the sender to a specific program and release — one of the few header fields chosen by a person rather than a server.'
        : 'The program that generated the message.',
    });
  }

  // Urgency is a claim the sender makes about their own message, which is why
  // it belongs here rather than among the filter verdicts. Only a high setting
  // is worth a line — normal and low are the defaults and say nothing. Stated
  // without alarm: plenty of honest mail marks itself important, and it is the
  // combination with an unverified sender that matters, which the reader can
  // see for themselves one card down.
  const urgency = URGENCY_FIELDS
    .map(([field, name]) => [name, get(headers, field)])
    .find(([, value]) => /^\s*(1|2|high|highest|urgent)\b/i.test(value));
  if (urgency) {
    items.push({
      label: 'Marked urgent by the sender',
      value: `${urgency[0]}: ${urgency[1]}`,
      note: 'A self-declaration, not a verdict — the sending program set it, and nothing checked it.',
    });
  }

  // The offset in Date: is the composing machine's clock, not the server's.
  // UTC is skipped: it means an automated sender and says nothing about anyone.
  const offset = get(headers, 'date').match(/([+-]\d{4})\s*$/)?.[1];
  if (offset && offset !== '+0000' && offset !== '-0000') {
    items.push({
      label: 'Written in timezone',
      value: `UTC${offset.replace(/^([+-])(\d{2})(\d{2})$/, '$1$2:$3')}`,
      note: 'Taken from the Date field, which carries the composing machine\'s local offset. It narrows down a part of the world, and on personal mail it narrows down a working day.',
    });
  }

  if (!items.length) return null;

  return {
    id: 'origin',
    title: 'The machine that wrote this',
    tone: items.some((i) => i.level === 'caution') ? 'alert' : 'neutral',
    lede: 'Fields the sending side filled in about itself. On a message you received they describe the sender — and on every message you send, the same fields describe you.',
    items,
  };
}

// -------------------------------------------------------------------- auth

/**
 * The headline a message gets when nothing that decides anything failed.
 *
 * Exported so that the test asserting it is never printed over a failure can
 * compare against the string the code actually uses. A test carrying its own
 * copy of a sentence stops testing the moment somebody rewords the original,
 * and says nothing while it stops.
 */
export const ALL_CLEAR_TITLE = 'Every check passed. That proves less than it sounds.';

/**
 * A DKIM `t=`/`x=` value as a Date, or null when it is not a time at all.
 *
 * Both tags are decimal seconds and the sender writes them. The pattern that
 * reads them, `\d{9,}`, has no upper bound; `Date` does, at ±8.64e15
 * milliseconds. A value one digit too long therefore reached `toISOString()`,
 * which throws `RangeError: Invalid time value` — and that throw travelled out
 * of `analyse`, out of `report`, and out of the process, so a single field a
 * spammer controls completely suppressed the entire report.
 *
 * Returning null instead of throwing lets the caller say what is true — that
 * the field is not a time — rather than either crashing or, worse, quietly
 * comparing against an invalid Date, where every `<` and `>` answers false and
 * "has it expired" gets the same reassuring answer whichever way it is asked.
 */
function signatureTime(seconds) {
  const at = new Date(Number(seconds) * 1000);
  return Number.isNaN(at.getTime()) ? null : at;
}

/** A Date as the `YYYY-MM-DD HH:MM:SS UTC` this report prints everywhere. */
function formatUtc(at) {
  return at.toISOString().replace('T', ' ').replace(/\..+/, ' UTC');
}

/**
 * The `dmarc=…` portion of an Authentication-Results string.
 *
 * Runs to the next unparenthesised semicolon, because every receiver worth
 * reading puts its policy detail inside parentheses — Google's
 * `dmarc=fail (p=NONE sp=NONE dis=NONE)` carries a semicolon-free parenthetical
 * but the ones that do not are why the depth is tracked.
 */
/**
 * Timestamps from the Received chain, newest first.
 *
 * `Received` is prepended by each hop, so the first one is the last machine to
 * touch the message — the closest thing the header has to "when this arrived".
 * Preferred over `Date:`, which the sender writes and can set to anything.
 */
function receivedDates(headers) {
  return getAll(headers, 'received')
    .map((value) => new Date(value.slice(dateSeparator(value) + 1).trim()))
    .filter((date) => !Number.isNaN(date.getTime()));
}

function dmarcSpan(results) {
  const start = results.search(/\bdmarc=/i);
  if (start === -1) return '';
  let depth = 0;
  for (let i = start; i < results.length; i++) {
    const char = results[i];
    if (char === '(') depth += 1;
    else if (char === ')') depth -= 1;
    else if (char === ';' && depth <= 0) return results.slice(start, i);
  }
  return results.slice(start);
}

// What the receiver did, as distinct from what the domain asked for.
// `pct.quarantine` and `pct.reject` are Microsoft's, and outlive the tag they
// are named after: RFC 9989 removed `pct=` (Appendix A.6), Microsoft still
// stamps these.
const DMARC_DISPOSITION = table({
  none: 'Delivered, with no DMARC action taken.',
  quarantine: 'Set aside — junk folder or quarantine — because the message failed the domain\'s policy.',
  reject: 'Refused outright at the door.',
  oreject: 'The domain asked for rejection and this receiver overrode it, delivering anyway.',
  'pct.quarantine': 'The domain asked for quarantine on a fraction of failures, and this message fell outside that fraction, so it was delivered. Microsoft still reports this although RFC 9989 removed the pct tag.',
  'pct.reject': 'The domain asked for rejection on a fraction of failures, and this message fell outside that fraction, so it was delivered. Microsoft still reports this although RFC 9989 removed the pct tag.',
  permerror: 'No action: the domain\'s own DMARC record could not be read.',
  temperror: 'No action: a lookup failed while the check was running.',
});

// Microsoft's composite authentication reason codes, which record the identity
// decision an M365 tenant actually made. Not in any RFC — this is the largest
// receiver's own vocabulary, and on its mail it says more than dmarc= does.
const COMPAUTH_REASONS = table({
  '000': ['The message failed authentication outright, and the domain asked for such mail to be quarantined or rejected.', 'bad'],
  '001': ['The message failed authentication, and the sending domain publishes nothing strong enough to say what should happen — no records, or a policy of p=none.', 'caution'],
  '002': ['An administrator here has explicitly forbidden this sender and domain from sending on its behalf.', 'bad'],
  '010': ['The message failed DMARC while claiming to come from this organisation\'s own domain. That is self-to-self spoofing — someone outside writing as though they were a colleague.', 'bad'],
  '109': ['The sending domain publishes no DMARC record, but the message would have passed if it did.', null],
  '111': ['DMARC could not be evaluated, and SPF or DKIM aligned with the From domain anyway.', null],
  '112': ['A DNS timeout stopped the DMARC record from being fetched.', 'caution'],
  '130': ['A forwarder this organisation trusts sealed the message, and that seal overrode the DMARC failure.', null],
  '501': ['A genuine bounce message between correspondents who have written to each other before, so DMARC was not enforced.', null],
  '502': ['A genuine bounce for a message sent from this organisation, so DMARC was not enforced.', null],
  '601': ['The sending domain belongs to this organisation — self-to-self, and it did not authenticate.', 'bad'],
  '905': ['DMARC was not enforced because the mail took a complicated route, such as through an on-premises server before reaching Microsoft.', 'caution'],
});

// The leading digit classifies anything the table above does not name.
const COMPAUTH_CLASSES = table({
  1: ['The message authenticated.', null],
  2: ['The message partly authenticated.', null],
  3: ['Composite authentication was not run on this message.', null],
  4: ['The message bypassed composite authentication.', 'caution'],
  6: ['The message failed implicit authentication.', 'caution'],
  7: ['DMARC was not enforced, because this organisation has a history of legitimate mail from this infrastructure.', null],
  9: ['The message bypassed composite authentication.', 'caution'],
});

function authFinding(headers) {
  const results = getAll(headers, 'authentication-results').join('\n');
  // The field object, not just the value: the row below quotes this as "the
  // receiving server's own words", and whether that attribution is honest
  // depends on where the field sits — the same question already asked of
  // Authentication-Results further down.
  const receivedSpfField = headers.find((h) => h.name.toLowerCase() === 'received-spf');
  const receivedSpf = receivedSpfField?.value ?? '';
  // RFC 6376 §4 permits any number of these, and ordinary mail uses the
  // permission: an ESP signs with RSA and ed25519 side by side, and a mailing
  // list adds its own over the top. Reading `get` — the first one — meant the
  // rest were not merely unreported but unreachable, so a sender could put a
  // clean signature above a weak one and the card would describe the clean one.
  // The same class as the singleton fields in `contradictionFinding`, arriving
  // from the opposite direction: there a field that may appear once appeared
  // twice; here a field that may appear many times was read once.
  const dkimSignatures = getAll(headers, 'dkim-signature');
  const dkimSignature = dkimSignatures[0] ?? '';
  const dkim2 = get(headers, 'dkim2-signature') || get(headers, 'message-instance');
  // Without this, a message signed only under the DKIM2 draft produces no
  // authentication card at all — the reader is told nothing rather than told
  // that something unfamiliar is here.
  if (!results && !receivedSpf && !dkimSignature && !dkim2) return null;

  const items = [];
  const verdicts = {};

  // Where the field sat, not only what it said.
  //
  // A receiving server prepends its Authentication-Results above the Received it
  // also writes — so the position no receiver produces is below EVERY Received:
  // nothing was delivered before the first hop, so a field there was put in
  // place by a forwarder or by whoever sent the message. The field is trivial to
  // write: a message carrying nothing but a fabricated `spf=pass; dkim=pass;
  // dmarc=pass` earned the full "every check passed" headline with three green
  // rows under it, all of them quoting the sender.
  //
  // Below the FIRST Received is NOT that position, and asking it there was wrong:
  // internal hops after the check stack their own Received above the border
  // server's A-R, so a genuine, honestly-written verdict routinely sits
  // mid-chain. The corpus made that concrete — this caution fired on all 25 real
  // messages, 17 of them delivered directly with no forwarding at all, each time
  // calling the delivering provider's own results "not written by the last hop".
  // Received-SPF and the Forefront report were already moved off the first-hop
  // test onto the every-hop one; this is the same fix, late to the third check.
  //
  // Not treated as forgery even when it does fire, because it routinely is not
  // one — mail forwarded through a second provider carries the first provider's
  // honest verdict in exactly this position. So the position is reported rather
  // than judged, which is what the route card already does one section down when
  // it says everything before your own provider is whatever the sender claimed.
  const lower = (name) => name.toLowerCase();
  const lastHop = headers.findLastIndex((h) => lower(h.name) === 'received');
  const resultFields = headers.filter((h) => lower(h.name) === 'authentication-results');
  const writtenBeforeTheLastHop = {};

  for (const field of resultFields) {
    const below = lastHop !== -1 && headers.indexOf(field) > lastHop;
    for (const [, mechanism, verdict] of field.value.matchAll(/\b(spf|dkim|dmarc|arc|bimi)=(\w+)/gi)) {
      const key = mechanism.toLowerCase();
      if (verdicts[key]) continue;
      verdicts[key] = verdict.toLowerCase();
      writtenBeforeTheLastHop[key] = below;
    }
  }

  // Each verdict needs its own sentence. A single description per mechanism
  // reads as the pass case, which on a failing message states the opposite of
  // what happened — the one error this card must never make.
  //
  // The result vocabularies are RFC 8601 §2.7, which takes SPF's from RFC 7208
  // §2.6 and DKIM's from RFC 6376 §3.9. All of them are here, because the
  // catch-all used to answer for the ones that were missing and it answered
  // wrongly: `neutral` is not "no verdict could be reached", it is the domain
  // owner declining to assert one, which is a decision they made on purpose.
  //
  // `table()` for the same reason it is used elsewhere — the verdict is `(\w+)`
  // out of a header, so a plain object answers to `constructor` with a function
  // and prints it as a finding.
  const explain = table({
    spf: table({
      pass: 'The sending server was authorised by the domain to send on its behalf.',
      fail: 'The sending server was not authorised by the domain it claims to send for.',
      softfail: 'The domain lists this server as probably not authorised, but stops short of saying so outright.',
      neutral: 'The domain publishes an SPF record and it declines to say either way about this server. That is a deliberate position, not a missing answer.',
      none: 'The domain publishes no SPF record, so there was nothing to check against.',
      temperror: 'The check could not be completed — a DNS lookup failed temporarily. It says nothing about the message; a retry might have passed.',
      permerror: 'The domain\'s own SPF record could not be interpreted — it is malformed, or it exceeds the ten-lookup limit. The fault is in the published record, not in this message.',
      other: 'This receiver used an SPF result word this tool does not know.',
    }),
    dkim: table({
      pass: 'The message carries an intact cryptographic signature from the domain.',
      fail: 'A signature was present but did not verify. The message was altered in transit, or it was never signed by the domain it names.',
      none: 'The message carries no signature at all, so nothing about it can be verified cryptographically.',
      neutral: 'A signature was present but could not be judged either way — usually one that is malformed rather than wrong.',
      policy: 'The signature verified, and the receiver declined to accept it anyway: it did not meet a local rule, such as a minimum key size or a required signing domain.',
      temperror: 'The check could not be completed — retrieving the public key from DNS failed temporarily.',
      permerror: 'The signature could not be checked at all: the header is malformed, or the key it names does not exist.',
      other: 'This receiver used a DKIM result word this tool does not know.',
    }),
    dmarc: table({
      pass: 'The domain\'s published policy on failures was satisfied.',
      fail: 'The message failed the domain\'s own policy — the domain owner asks receivers not to trust mail like this.',
      none: 'The domain publishes no DMARC policy, so it has never said what should happen to forgeries.',
      bestguesspass: 'The domain publishes no DMARC record, but the check would have passed if it did. Microsoft\'s wording, not a standard result — treat it as "no policy", because that is what it is.',
      temperror: 'The check could not be completed — a DNS lookup failed temporarily.',
      permerror: 'The domain\'s DMARC record could not be interpreted. The fault is in the published record.',
      other: 'This receiver used a DMARC result word this tool does not know.',
    }),
    // ARC is not decisive, but it is not noise either — see the note below,
    // which is replaced when ARC is the thing explaining a DMARC failure.
    arc: table({
      pass: 'A forwarder vouched for how this message looked when it arrived, and that chain of custody is intact.',
      fail: 'A forwarder\'s seal did not verify, so nothing can be reconstructed about the message before it was forwarded.',
      none: 'No forwarder sealed this message, which is the ordinary case for mail sent directly.',
      other: 'Chain of custody across forwarding hops.',
    }),
    bimi: table({
      pass: 'The sender is entitled to display a verified logo in mail clients that show one.',
      fail: 'A logo was claimed and the claim did not check out.',
      skipped: 'The receiver did not look, usually because the message did not qualify.',
      none: 'No brand logo was claimed.',
      other: 'Brand logo verification.',
    }),
  });

  // Only SPF, DKIM and DMARC carry weight. BIMI and ARC are absent or failing
  // on most legitimate mail, so colouring them red would cry wolf.
  const DECISIVE = new Set(['spf', 'dkim', 'dmarc']);

  // Forwarding is the commonest innocent cause of a DMARC failure, and when a
  // forwarder sealed the message the header says so directly.
  const arcExplainsDmarc = verdicts.dmarc === 'fail' && verdicts.arc === 'pass';

  for (const [mechanism, verdict] of Object.entries(verdicts)) {
    const wording = explain[mechanism] ?? {};
    items.push({
      label: `${mechanism.toUpperCase()} = ${verdict}`,
      value: wording[verdict] ?? wording.other ?? '',
      // A pass is a pass on any mechanism. Failure is where the distinction
      // matters: BIMI and ARC are absent or failing on most legitimate mail,
      // so marking those red would cry wolf, while `none` is neither good nor
      // bad — it means there was nothing to check.
      level: verdict === 'pass' ? 'good'
        : verdict === 'none' ? 'absent'
          : (DECISIVE.has(mechanism) && verdict === 'fail') ? 'bad'
            : null,
      note: DECISIVE.has(mechanism) ? null
        // ARC stays out of DECISIVE — a seal is worth whatever the receiver's
        // trust list says it is — but calling it noise while it is sitting
        // there explaining the DMARC failure beside it is simply wrong.
        : (mechanism === 'arc' && arcExplainsDmarc)
          ? 'This is the likeliest reason DMARC failed. A forwarder altered the message and recorded how it looked beforehand; whether that record counts is the receiving side\'s decision, not the sender\'s.'
          : 'Informational — commonly absent even on legitimate mail.',
    });
  }

  // Said once, under the rows it qualifies, and before the policy detail that
  // rests on the same field.
  const earlier = Object.keys(verdicts).filter((m) => writtenBeforeTheLastHop[m]);
  if (earlier.length) {
    // The label names exactly the rows it applies to. "These verdicts" over a
    // card where two of the three came from the delivering server is the same
    // disagreement between a headline and its rows that `tone-computed-beside-items`
    // exists to catch, and it would be arguing against rows that are sound.
    const named = earlier.map((m) => m.toUpperCase());
    const all = named.length === Object.keys(verdicts).length;
    items.push({
      label: all
        ? 'These verdicts were not written by the last hop'
        : `The ${named.join(' and ')} ${named.length === 1 ? 'verdict was' : 'verdicts were'} not written by the last hop`,
      value: `The Authentication-Results field carrying ${named.join(', ')} sits below a Received, so it was added earlier in the chain than the server that delivered this. That is ordinary on forwarded mail, where it is the first provider's honest answer — and it is also where a fabricated one would sit, because the sender writes everything below their own hop.`,
      note: 'A receiving server puts its own results above the Received it writes. Read these as worth whatever the hop that wrote them is worth.',
      level: 'caution',
    });
  }

  // Scoped to the dmarc= result, not scraped from the whole string. `=` is
  // legal in a local part, so an envelope sender of `p=reject@evil.example` —
  // which Gmail-class receivers echo verbatim into the SPF parenthetical, and
  // the SPF result comes first — used to make this row read `p=reject` on a
  // message whose own header said `(p=NONE)`.
  const dmarc = dmarcSpan(results);
  // X-DMARC-Policy is the receiver's copy of the record it fetched, and on
  // iCloud it carries the whole record, not a policy word. It used to be
  // printed raw: a real message rendered "v=DMARC1; p=reject; adkim=s;
  // aspf=r; rf=afrf; pct=100;." as the published policy. Both sources now get
  // the same scoped read; a field holding just the bare word still counts.
  const fieldRecord = get(headers, 'x-dmarc-policy');
  const record = /\bp=/i.test(fieldRecord) ? fieldRecord : dmarc;
  const policy = record.match(/\bp=(none|quarantine|reject)\b/i)?.[1]
    ?? fieldRecord.trim().match(/^(none|quarantine|reject)$/i)?.[1];
  if (policy) {
    const tag = (name) => record.match(new RegExp(`\\b${name}=([A-Za-z]+)\\b`, 'i'))?.[1];
    const subdomain = tag('sp');
    const nonExistent = tag('np');
    const testing = tag('t');

    const extra = [
      subdomain ? `Subdomains: ${subdomain}.` : '',
      nonExistent ? `Subdomains that do not exist: ${nonExistent}.` : '',
    ].filter(Boolean).join(' ');

    items.push({
      label: 'Published DMARC policy',
      value: `${policy}${extra ? `. ${extra}` : '.'}`,
      note: 'What the domain owner asks receivers to do with mail that fails. It binds nobody — each receiver decides for itself.',
    });

    // RFC 9989 §5.5.1: `t=y` means the policy is published for observation and
    // is not to be applied. A domain can therefore advertise `p=reject` and ask
    // that nothing be rejected, which is worth more than the policy word.
    if (testing?.toLowerCase() === 'y') {
      items.push({
        label: 'The policy is in test mode',
        value: `The domain publishes p=${policy} and sets t=y beside it, which asks receivers to observe the outcome and act as though the policy were "none".`,
        note: 'RFC 9989 replaced the old pct= tag with this. A policy in test mode protects nothing.',
        level: 'caution',
      });
    }
  }

  // Microsoft's composite verdict. Structurally invisible to the mechanism
  // scanner above, which only knows the five RFC names — and on M365 mail this
  // is the field recording what the receiver concluded about the sender's
  // identity, after weighing SPF, DKIM, DMARC and the message together.
  const compauth = results.match(/\bcompauth=(\w+)/i)?.[1]?.toLowerCase();
  if (compauth) {
    items.push({
      label: `Composite authentication = ${compauth}`,
      value: compauth === 'pass'
        ? 'Microsoft weighed SPF, DKIM, DMARC and the message together and accepted the sender\'s identity.'
        : compauth === 'fail'
          ? 'Microsoft weighed everything together and did not accept that this message is from who it says.'
          : 'Microsoft did not reach a composite verdict on this sender.',
      level: compauth === 'pass' ? 'good' : compauth === 'fail' ? 'bad' : null,
      note: 'Microsoft\'s own judgement rather than any RFC\'s. On mail through Microsoft 365 it is the verdict that decided delivery.',
    });

    const code = results.match(/\breason=(\d{3})/i)?.[1];
    const known = code && (COMPAUTH_REASONS[code] ?? COMPAUTH_CLASSES[code[0]]);
    if (known) {
      items.push({
        label: `Reason ${code}`,
        value: known[0],
        level: known[1],
        emphasis: known[1] === 'bad',
      });
    }
  }

  // What the receiver actually did, which is the part the reader wants and the
  // only part that was not a request. Google writes `dis=`, Microsoft `action=`.
  const applied = dmarc.match(/\b(?:dis|action)=([A-Za-z.]+)/i)?.[1];
  if (applied) {
    items.push({
      label: 'What this receiver did about it',
      value: DMARC_DISPOSITION[applied.toLowerCase()] ?? `Recorded as "${applied}".`,
      note: 'The published policy is a request; this is the decision. They differ more often than not.',
    });
  }

  // Received-SPF usually carries a sentence explaining the verdict, which says
  // more than `spf=fail` does — it names the domain and the server that was not
  // authorised for it.
  if (receivedSpf) {
    const [outcome, ...rest] = receivedSpf.split(/\s+/);
    const explanation = rest.join(' ').replace(/^\((.*)\)$/, '$1').trim();
    if (explanation) {
      // RFC 7208 §9.1 has the receiver prepend this field above the Received
      // it writes — and internal hops after the check stack their Received
      // above it, so a genuine one routinely sits mid-chain. The first cut of
      // this check asked "below the first Received?" and marked iCloud's own
      // Received-SPF on a directly delivered message, because iCloud stamps
      // smtpin's check and then mailgateway's Received on top. Below the LAST
      // Received is the position no receiver produces: nothing delivered
      // before the first hop, so whatever sits there was written by the
      // sender — and quoting that as "the receiving server's own words" put
      // this tool's voice behind a sentence the sender may have written.
      const lastHop = headers.findLastIndex((h) => h.name.toLowerCase() === 'received');
      const below = lastHop !== -1 && headers.indexOf(receivedSpfField) > lastHop;
      items.push({
        label: `Received-SPF: ${outcome.replace(/[^A-Za-z]/g, '')}`,
        value: explanation,
        note: below
          ? 'This field sits below every Received, so no server on the delivery path wrote it — it was already part of the message when the first hop took it, which is where a fabricated one sits. A receiver records its check above the Received it writes.'
          : 'The receiving server\'s own words, recorded as it made the decision.',
        level: below ? 'caution' : undefined,
      });
    }
  }

  // Every signature is described, and each row says which one it is describing.
  // Naming the signature matters most exactly where it is least convenient: a
  // weak signature beside a strong one is the case where an unlabelled warning
  // reads as though it applied to both.
  // Only when the domains actually differ. Two signatures from one sender —
  // the RSA-and-ed25519 pair an ESP publishes so that receivers without the
  // newer algorithm can still verify — are distinguished by nothing the suffix
  // would say, and appending the same domain to every row states a difference
  // that is not there.
  const signingDomains = new Set(
    dkimSignatures.map((s) => s.match(/\bd=([^;\s]+)/)?.[1]).filter(Boolean),
  );
  const forSignature = (label, domain) => (signingDomains.size > 1 && domain ? `${label} — ${domain}` : label);
  // Rows are collected per signature rather than pushed as they are found,
  // because the number of signatures is written by the sender. Reading only the
  // first one held that number at one by accident; reading all of them removed
  // the bound altogether, and 500 fabricated DKIM-Signature fields produced
  // 1,500 rows with every real warning buried somewhere inside them. Making a
  // card unreadable is a way of making it say nothing.
  //
  // So the bound is by content, not by position — the same rule
  // `recipientFinding` applies to a message addressed to a crowd. A signature
  // that produced a warning is always described, because prepending harmless
  // signatures until the warning falls off the end is precisely the attack.
  const perSignature = [];
  const seenRows = new Set();
  const collect = (rows, row) => {
    const key = `${row.label}\u0000${row.value}`;
    if (seenRows.has(key)) return;
    seenRows.add(key);
    rows.push(row);
  };

  // Walking every Received to find the newest hop is only worth doing when a
  // signature carries an expiry to compare against, and hoisting it out of the
  // loop made it unconditional. Deferred rather than guarded by a second copy
  // of the `x=` pattern, because two patterns that must agree are two patterns
  // that can stop agreeing.
  let arrival;
  const arrivedAt = () => {
    if (arrival === undefined) arrival = receivedDates(headers)[0] ?? null;
    return arrival;
  };

  for (const signature of dkimSignatures) {
    const rows = [];
    const domain = signature.match(/\bd=([^;\s]+)/)?.[1];
    if (domain) {
      collect(rows, {
        label: 'Signed by domain',
        value: domain,
        note: 'The signature proves this domain sent it — it says nothing about whether the domain is trustworthy.',
      });
    }

    const timestamp = signature.match(/\bt=(\d{9,})/)?.[1];
    if (timestamp) {
      const signedAt = signatureTime(timestamp);
      collect(rows, signedAt
        ? { label: forSignature('Signed at', domain), value: formatUtc(signedAt) }
        : {
          label: forSignature('The signature claims a time that is not a time', domain),
          value: `t=${timestamp}`,
          level: 'caution',
          note: 'Seconds since 1970, and this many of them lands outside any date that can be expressed. A verifier reading it has nothing to compare against, so whatever the signature was meant to bound, it does not.',
        });
    }

    // A length tag signs only the first l= bytes of the body. Everything after
    // that can be appended by anyone without breaking the signature, so "DKIM
    // passed" stops meaning "the message is intact". Rare in ordinary mail and
    // worth naming when it appears, but reported as a property of the signature
    // rather than as an accusation — some legitimate mailing lists set it.
    //
    // `\d+` has no upper bound and `Number` does. A 25-digit length printed as
    // 10,000,000,000,000,000,000,000,000 — a figure that was not in the header,
    // because everything past 2^53 rounds — and 400 digits printed as "∞ bytes".
    // Neither is a length, and saying so beats printing a number the message
    // never carried. The same answer `signatureTime` gives to the same shape.
    //
    // `l=0` is the opposite mistake. It is the most serious value the tag can
    // take — no part of the body is signed, so all of it can be replaced while
    // the signature keeps verifying — and "covers the first 0 bytes of the
    // body" was the mildest sentence on the card.
    const signedLength = signature.match(/\bl=(\d+)/)?.[1];
    if (signedLength !== undefined) {
      const bytes = Number(signedLength);
      collect(rows, !Number.isSafeInteger(bytes)
        ? {
          label: forSignature('The signed length is not a length', domain),
          value: `l=${clip(signedLength, 40)}`,
          level: 'caution',
          note: 'Too large to be a count of bytes, so nothing can be read from it about how much of the message this signature covers. Read it as a signature whose coverage is unstated, not as one that covers a great deal.',
        }
        : bytes === 0
          ? {
            label: forSignature('None of the message body is signed', domain),
            value: 'The signature sets l=0, so it covers zero bytes of the body. The whole of it can be replaced without invalidating the signature.',
            note: 'The length tag bounds what a signature vouches for, and at zero it vouches for nothing but the headers it names — while still verifying. "DKIM passed" then says nothing whatever about the message you are reading.',
            level: 'caution',
          }
          : {
            label: forSignature('Only part of the message is signed', domain),
            value: `The signature covers the first ${bytes.toLocaleString('en')} bytes of the body.`,
            note: 'Anything after that can be added without invalidating it, so a passing DKIM result does not vouch for the whole message.',
            level: 'caution',
          });
    }

    // An expiry is the industry's main answer to DKIM replay — a spammer taking
    // one correctly signed message and re-sending it to thousands of other
    // recipients, where the signature keeps verifying because it covers nothing
    // about who it was sent to.
    const expiry = signature.match(/\bx=(\d{9,})/)?.[1];
    if (expiry) {
      const expiresAt = signatureTime(expiry);
      const newestHop = arrivedAt();
      const stale = expiresAt && newestHop && expiresAt < newestHop;
      collect(rows, expiresAt
        ? {
          label: forSignature(stale ? 'The signature had expired before this message arrived' : 'The signature carries an expiry', domain),
          value: `Valid until ${formatUtc(expiresAt)}.`,
          note: stale
            ? 'An expired signature verifies as no signature at all, so whatever DKIM appeared to vouch for here, it no longer does.'
            : 'A short window limits how long a correctly signed copy can be replayed to other recipients.',
          level: stale ? 'caution' : null,
        }
        : {
          label: forSignature('The expiry is not a time', domain),
          value: `x=${expiry}`,
          level: 'caution',
          note: 'An expiry outside any expressible date bounds nothing. Read it as a signature without an expiry, not as one with a distant deadline — and note that a comparison against it silently answers "not yet expired" whichever way it is asked.',
        });
    }

    const algorithm = signature.match(/\ba=([\w-]+)/)?.[1]?.toLowerCase();
    if (algorithm && /sha1$/.test(algorithm)) {
      collect(rows, {
        label: forSignature(`Signed with ${algorithm}`, domain),
        value: 'SHA-1 has been prohibited for DKIM since RFC 8301 in 2018, because collisions are practical.',
        note: 'Most receivers now treat such a signature as no signature at all.',
        level: 'caution',
      });
    } else if (algorithm === 'ed25519-sha256') {
      // Without this the `a=` branch only ever speaks to accuse, and a sender who
      // did the modern thing gets the same silence as one who did nothing.
      collect(rows, {
        label: forSignature('Signed with ed25519-sha256', domain),
        value: 'The elliptic-curve signature type from RFC 8463. Shorter keys than RSA at the same strength, which is why it fits in DNS without splitting the record.',
        note: 'Still uncommon; senders usually publish an RSA signature beside it for receivers that do not implement it.',
      });
    }
  
    if (rows.length) perSignature.push(rows);
  }


  // A ceiling, not a filter. Ordering by what a signature says puts the
  // warnings first, but ordering alone bounds nothing: an attacker who wants
  // 500 rows writes `l=1` on all 500 and every one of them then "says
  // something". The count itself has to be capped, and what falls outside the
  // cap has to be reported as a quantity rather than dropped.
  //
  // Six is past anything honest — an ESP's RSA-and-ed25519 pair, a mailing list
  // signing over the top, and room to spare. Beyond it the number is the
  // finding: nobody signs a message fifty times except to bury something.
  const DESCRIBED_AT_MOST = 6;
  const speaks = (rows) => rows.some((row) => row.level);
  const ordered = [...perSignature.filter(speaks), ...perSignature.filter((rows) => !speaks(rows))];
  for (const rows of ordered.slice(0, DESCRIBED_AT_MOST)) items.push(...rows);

  const undescribed = dkimSignatures.length - Math.min(ordered.length, DESCRIBED_AT_MOST);
  if (undescribed > 0) {
    items.push({
      label: `This message carries ${dkimSignatures.length} DKIM signatures`,
      value: `${undescribed} of them are not described above. The ones that say something about the message were kept; a header this size is not a message that has been signed carefully.`,
      note: 'One signature is normal and three happens. Past that, the count is the finding — signatures are cheap to write, and a long enough list pushes everything else off the end of whatever reads it.',
      level: 'caution',
    });
  }

  if (dkim2) {
    items.push({
      label: 'Signed under the DKIM2 draft',
      value: 'This message carries DKIM2-Signature or Message-Instance fields, which record each modification a forwarder made rather than breaking when one is made.',
      note: 'draft-ietf-dkim-dkim2-spec, an active Internet-Draft with no published RFC. Nothing here verifies it, and few receivers evaluate it yet.',
    });
  }

  const failed = Object.entries(verdicts)
    .filter(([mechanism, verdict]) => DECISIVE.has(mechanism) && verdict === 'fail')
    .map(([mechanism]) => mechanism.toUpperCase());

  // "Everything passed" has to mean everything that decides anything, and it
  // has to become false the moment one of them says otherwise. Counting passes
  // was neither. Two passes were enough to earn the headline, and `arc=pass`
  // with `bimi=pass` is two — a forwarder's seal and a logo entitlement,
  // neither of which asserts anything about who sent this. So a message that
  // failed SPF and DMARC outright, with a REJECT policy published, was
  // headlined as fully authenticated with the red rows printed underneath it.
  //
  // 302 of the 3,528 verdict combinations took that path. Not an edge case —
  // a third of every combination in which something decisive failed. It went
  // unnoticed because the two fixtures are a message that passes everything and
  // one that fails everything, and the fault only appears in between.
  //
  // `compauth` is in the same sentence because it is in the same header and it
  // is rendered as a red row: Microsoft weighing everything together and saying
  // someone outside wrote as though they were a colleague. It decided nothing
  // about this headline, so SPF, DKIM and DMARC all passing was enough to print
  // "every check passed" directly above it.
  // Every decisive verdict that exists has to be `pass`, not merely "none of
  // them said fail". The first rewrite of this line fixed the case that had been
  // reported — arc and bimi passing while SPF and DMARC failed — and left every
  // other non-pass word invisible: softfail, neutral, temperror, permerror,
  // DKIM policy, DMARC none. `spf=softfail` with two passes still earned the
  // headline "Every check passed", printed above a row explaining that the
  // domain lists this server as probably not authorised.
  //
  // 168 of the 3,528 combinations, and the reason they survived the first fix
  // is that the fix was written against a reported case rather than against the
  // vocabulary. The vocabulary is enumerated in test/verdicts.js; the invariant
  // there now walks all of it.
  const decisiveVerdicts = [...DECISIVE].map((mechanism) => verdicts[mechanism]).filter(Boolean);
  // Read off the rows, for the reason the tone below is: the headline is the
  // other place "everything passed" is decided, and it drifted the same way the
  // tone once had. A Microsoft `compauth=pass reason=000` writes a good compauth
  // row and a `bad` reason row that says the message failed authentication
  // outright — decisive verdicts all pass, so the word-level test called it
  // all-clear over a red row. Any bad row the card carries denies the headline.
  const allPass = decisiveVerdicts.length >= 2
    && decisiveVerdicts.every((verdict) => verdict === 'pass')
    && compauth !== 'fail'
    && !items.some((item) => item.level === 'bad');

  return {
    id: 'auth',
    title: allPass
      ? ALL_CLEAR_TITLE
      : failed.length
        ? 'The sender\'s identity did not check out'
        : 'Authentication results',
    // Read off the rows rather than computed beside them. The parallel version
    // said 'info' whenever `failed` was empty, and `failed` only ever held SPF,
    // DKIM and DMARC — so a red `compauth=fail` row sat in a blue card, which
    // is what a reader glancing at colour would take for routine. Any card
    // carrying a row this tool marked `bad` is alert, by construction, and
    // there is no second place for that decision to drift away from.
    tone: items.some((item) => item.level === 'bad') ? 'alert' : 'info',
    lede: allPass
      // The closing clause is a claim about this specific message, so it is
      // only made when the header actually carries a filter verdict saying so.
      // Asserting it unconditionally told every clean message it had been
      // filed as junk.
      ? `SPF, DKIM and DMARC answer one question: is this server allowed to send for this domain? They do not ask whether the mail is wanted, honest, or from someone you have heard of. A spammer who owns their domain passes all three${
        wasFiledAsSpam(headers)
          ? ' — this one did, and the mailbox provider still filed it as junk.'
          : ', and many do.'
      }`
      : failed.length
        ? `${failed.join(' and ')} failed. These checks break for innocent reasons too — a forwarded message loses SPF, a mailing list rewrites the body and voids the signature. But they also fail for the obvious reason, and nothing in the header distinguishes the two. Treat the name in the From field as unverified.`
        : 'What the receiving server could verify about the sender\'s identity.',
    items,
  };
}

// -------------------------------------------------------------------- route

function routeFinding(headers) {
  const received = getAll(headers, 'received');
  if (!received.length) return null;

  // Received headers are prepended, so the last one is the first hop.
  const hops = received.map(parseReceived).reverse();

  const items = hops.map((hop, index) => {
    const platform = hop.from ? identifySender(registrableDomain(hop.from)) : null;

    // A hop that names itself with an encoded id rather than a machine. The
    // first hop of an API injection is the usual place: the sending platform
    // labels the connection with the customer it is billing, which is an
    // identifier for the sender's account, not a host anyone could resolve.
    const encodedName = decodeIdentifier(hop.from);
    const reused = encodedName && headers.some(
      (h) => !/^received$/i.test(h.name) && h.value.includes(encodedName),
    );

    return {
      label: `Hop ${index + 1}${index === 0 ? ' — origin' : ''}`,
      value: [
        hop.from ? `from ${hop.from}` : null,
        hop.by ? `by ${hop.by}` : null,
        hop.protocol ? `via ${hop.protocol}` : null,
      ].filter(Boolean).join('  '),
      chips: [
        hop.date,
        // The `S` immediately after SMTP is the one that means TLS (RFC 3848):
        // `ESMTPS` and `ESMTPSA` are encrypted, `ESMTPA` is only authenticated,
        // and `ESMTP` is neither. The chip carried the word and never said
        // which — so the one fact a reader can get out of it went unstated.
        hop.protocol
          ? (/^(?:e?smtps|https)/i.test(hop.protocol)
            ? 'encrypted hop'
            : hop.tlsInComment
              ? 'encrypted hop, according to a comment rather than the protocol'
              : 'unencrypted hop')
          : null,
        platform ? `${platform.name} — bulk mail platform` : null,
        encodedName ? `decodes to ${encodedName}` : null,
      ].filter(Boolean),
      note: encodedName
        ? `This hop is named after an encoded identifier rather than a machine.${
          reused
            ? ' The same value appears elsewhere in this header, which makes it the sender\'s account number on the platform — carried in the routing, where nobody looks.'
            : ''
        }`
        : null,
      emphasis: index === 0,
      mono: true,
    };
  });

  const origin = hops[0];
  const apiInjected = origin && /^https?$/i.test(origin.protocol ?? '');

  return {
    id: 'route',
    title: 'The paper trail, read backwards',
    tone: 'neutral',
    lede: apiInjected
      ? 'The first hop was handed over via HTTP, not SMTP — the message was injected through a sending platform\'s API. That first address is the machine that actually generated this mail, which is rarely the same as the brand on the envelope.'
      : 'Each server that touched this message added a line on top, so the oldest entry is the true origin. Only the hops inside your own provider are hard to forge; everything before that is whatever the sender claimed.',
    items,
  };
}

/**
 * A Received clause with its comments removed.
 *
 * RFC 5322 comments nest and can hold anything, including the words this
 * function's callers are looking for. `from mail.example.com (Postfix with
 * SMTP) by mx.example.net with ESMTPS` has two `with`s, and the first one is
 * somebody's prose — but it was the one that answered, so a hop encrypted with
 * TLS 1.3 was reported to the reader as unencrypted. A wrong statement about a
 * security property, in a card about the route a message took.
 *
 * Depth-counted rather than a regex, because comments nest and `\(.*?\)` stops
 * at the first close paren regardless of what opened after it.
 */
function withoutComments(text) {
  let depth = 0;
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '\\') { i += 1; continue; } // quoted-pair: skip what it escapes
    if (ch === '(') { depth += 1; continue; }
    if (ch === ')') { depth = Math.max(0, depth - 1); out += ' '; continue; }
    if (!depth) out += ch;
  }
  // An unterminated comment swallows everything after it, and the sender writes
  // this line. One stray '(' erased the receiving server and the protocol from
  // the route card — `from evil.example` and nothing else, no `by`, no
  // encryption verdict. A comment that does not close is not a comment; read
  // the line as written rather than reporting a hop that has no destination.
  return depth === 0 ? out : text;
}

/**
 * Only the comments — the exact complement of `withoutComments`.
 *
 * Needed because the TLS evidence is a claim about what a comment says, and the
 * first version of it tested the whole clause. `from tls.attacker.example … with
 * SMTP` has no encryption anywhere and no TLS inside any comment, and it was
 * reported as "encrypted hop, according to a comment rather than the protocol"
 * — a false statement about a security property, from a hostname the sending
 * client chooses. Worse than the bug it replaced, which at least erred towards
 * saying a hop was less protected than it was.
 */
function commentsOnly(text) {
  let depth = 0;
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '\\') { i += 1; continue; }
    if (ch === '(') { depth += 1; continue; }
    if (ch === ')') { depth = Math.max(0, depth - 1); out += ' '; continue; }
    if (depth) out += ch;
  }
  return out;
}

// How servers actually spell it. Exchange writes `version=TLS1_2`, Postfix
// `(using TLSv1.3 …)`, others just `TLS`. The first pattern here required a word
// boundary after the version — `\bTLS(?:v[\d.]+)?\b` — which `TLS1_2` never
// provides, since `1` and `_` are both word characters. So the guard written to
// stop Microsoft 365 hops being called plaintext did not fire on a single
// Microsoft 365 hop.
const TLS_TOKEN = /\bTLS[v._\d]*/i;

function parseReceived(value) {
  const [head, tail] = splitOnce(value);
  const clause = withoutComments(head);
  return {
    from: clause.match(/\bfrom\s+([^\s;()]+)/i)?.[1] ?? null,
    by: clause.match(/\bby\s+([^\s;()]+)/i)?.[1] ?? null,
    protocol: clause.match(/\bwith\s+([A-Za-z0-9]+)/i)?.[1] ?? null,
    // Kept from the full line, comments included. RFC 3848 says a hop that used
    // TLS should say `ESMTPS`, and the ones that instead write `with ESMTP
    // (using TLSv1.3 …)` are being sloppy rather than unencrypted. Reporting
    // those as plaintext would be the same kind of wrong in the other
    // direction, so the two cases are told apart rather than merged.
    tlsInComment: TLS_TOKEN.test(commentsOnly(head)),
    date: tail?.trim() || null,
  };
}

/**
 * Where the route tokens end and the date begins.
 *
 * RFC 5322 §3.6.7 puts exactly one `;` there, and everything to its left may
 * carry comments — which hold semicolons of their own. `lastIndexOf` answers
 * with whichever one sits furthest right, so a comment written *after* the date
 * (`… ; Mon, 17 Aug 2026 10:00:00 +0000 (envelope-from <a@b>; helo=c)`) made
 * the tail `helo=c)` and the route card printed that as the hop's timestamp.
 *
 * Worse when the clause has no date at all: the split then lands inside the
 * comment, `withoutComments` is handed an unbalanced fragment and returns it
 * whole, and `by` and `with` end up on the far side of the separator. One
 * semicolon inside one comment — both written by the sender — erased the
 * receiving server and the encryption verdict from the card. That is the
 * defect `unbalanced-comment-eats-the-clause` closed, arriving by the one
 * route that fix did not cover, because it was written against the example it
 * was reported with.
 *
 * Depth-counted for the same reason `withoutComments` is, and it defers to
 * that function's rule at the end: what never closes is not a comment, so an
 * unbalanced clause is read exactly as written.
 */
function dateSeparator(text) {
  let depth = 0;
  let index = -1;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '\\') { i += 1; continue; } // quoted-pair: skip what it escapes
    if (ch === '(') { depth += 1; continue; }
    if (ch === ')') { depth = Math.max(0, depth - 1); continue; }
    if (ch === ';' && depth === 0) index = i;
  }
  return depth === 0 ? index : text.lastIndexOf(';');
}

function splitOnce(text) {
  const index = dateSeparator(text);
  return index === -1 ? [text, null] : [text.slice(0, index), text.slice(index + 1)];
}

/**
 * Did something along the way actually rule this message spam?
 *
 * Only used to decide whether the authentication card may say so. Deliberately
 * narrow: a flag set to "no" is not a verdict, and an SCL below 5 is Microsoft
 * saying the opposite.
 */
function wasFiledAsSpam(headers) {
  if (/^yes\b/i.test(get(headers, 'x-spam-flag'))) return true;
  if (/junk/i.test(get(headers, 'x-apple-action'))) return true;
  if (/junk|spam/i.test(get(headers, 'x-apple-movetofolder'))) return true;
  if (/^yes\b/i.test(get(headers, 'x-suspected-spam'))) return true;

  // The threat category rather than the SCL score. Microsoft's reference states
  // that on cloud mailboxes SCL "doesn't determine whether the message is
  // identified as spam", and a `CAT:BIMP` message routinely carries `SCL:1` —
  // so the old `scl >= 5` test read a brand-impersonation verdict as clean.
  return filedAsUnwanted(headers);
}

// --------------------------------------------------------------- judgements

function judgementFinding(headers) {
  const items = [];
  const interesting = [
    ['x-spam-flag', 'Spam flag'],
    ['x-spam-status', 'Spam status'],
    ['x-suspected-spam', 'Suspected spam'],
    ['x-apple-action', 'Apple Mail action'],
    ['x-apple-movetofolder', 'Filed into folder'],
    ['x-spam-score', 'Spam score'],
    ['x-icl-score', 'iCloud score'],
  ];

  for (const [field, label] of interesting) {
    const value = get(headers, field);
    if (value) items.push({ label, value });
  }

  items.push(...microsoftVerdicts(headers));

  if (!items.length) return null;

  return {
    id: 'judgement',
    title: 'Someone already made up their mind',
    tone: items.some((i) => i.level === 'bad') ? 'alert' : 'neutral',
    lede: 'Filters along the way left their verdicts in the header. These are opinions, not facts — but they are the opinions that decided which folder this landed in.',
    items,
  };
}
