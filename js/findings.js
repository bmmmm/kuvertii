// Header → findings. This module is the product; everything else is plumbing.
//
// Each finding states what was found, what it means, and which header it came
// from. The tone is dry rather than alarmed: the goal is for someone to
// understand their own mail, not to be told what to feel about it.

import { bestDecode, clip, decodeIdentifier, decodeSegments, findAddresses, prettifyNulls } from './decode.js';
import { extractUrls, inspectUnsubscribeLink, registrableDomain } from './links.js';
import { microsoftVerdicts } from './microsoft.js';
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

export function analyse(headers) {
  const findings = [];
  const push = (f) => { if (f) findings.push(f); };

  push(completenessFinding(headers));
  push(recipientFinding(headers));
  push(disclosureFinding(headers));
  push(trackingFinding(headers));
  push(listFinding(headers));
  push(unsubscribeFinding(headers));
  push(replyToFinding(headers));
  push(originFinding(headers));
  push(authFinding(headers));
  push(routeFinding(headers));
  push(judgementFinding(headers));

  return findings;
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

const RECIPIENT_PRESENT = ['to', 'cc', 'delivered-to', 'x-original-to', 'envelope-to'];

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

    const record = (text, method) => {
      for (const address of findAddresses(text)) {
        if (senderAddresses.has(address)) continue;
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
    for (const url of extractUrls(header.value)) {
      for (const segment of url.split(/[/?&=#]/)) {
        if (segment.length < 12) continue;
        const decoded = bestDecode(segment, 0.5);
        if (decoded) record(decoded.text, `${decoded.method} inside the URL`);
      }
    }

    // VERP bounce addresses embed the recipient in their own local part, with
    // the @ written as = — `bounce-alice=example.com@sender.example`. The
    // pattern has to require a real domain after the =, otherwise every
    // `key=value` pair in an Authentication-Results line reads as an address.
    for (const [, local, domain] of header.value.matchAll(
      /([A-Za-z0-9._%+-]+)=([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})@/g,
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

  return {
    id: 'recipients',
    title: 'Who this was actually addressed to',
    tone: encodedCount ? 'alert' : 'info',
    lede: encodedCount
      ? `The recipient address appears ${encodedCount} more ${encodedCount === 1 ? 'time' : 'times'} than the visible To: field suggests, each one encoded. Encoding is not encryption — it is just a step that assumes nobody looks.`
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
const LIST_ID_RE = /^\s*(.*?)\s*<([^>]+)>\s*$/;

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
    const match = rawId.match(LIST_ID_RE);
    const identifier = match?.[2] ?? rawId;
    const description = match?.[1]?.replace(/^"|"$/g, '').trim();

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
  const hasOneClick = /one-click/i.test(get(headers, 'list-unsubscribe-post'));
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
      ? 'This sender supports one-click unsubscribe (RFC 8058). Prefer your mail client\'s own unsubscribe button over the link in the message body — it skips the click tracker.'
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
      { label: 'Appears to be from', value: `${fromAddress}  (${fromDomain})` },
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

function authFinding(headers) {
  const results = getAll(headers, 'authentication-results').join('\n');
  const receivedSpf = get(headers, 'received-spf');
  const dkimSignature = get(headers, 'dkim-signature');
  if (!results && !receivedSpf && !dkimSignature) return null;

  const items = [];
  const verdicts = {};
  for (const [, mechanism, verdict] of results.matchAll(/\b(spf|dkim|dmarc|arc|bimi)=(\w+)/gi)) {
    const key = mechanism.toLowerCase();
    if (!verdicts[key]) verdicts[key] = verdict.toLowerCase();
  }

  // Each verdict needs its own sentence. A single description per mechanism
  // reads as the pass case, which on a failing message states the opposite of
  // what happened — the one error this card must never make.
  const explain = {
    spf: {
      pass: 'The sending server was authorised by the domain to send on its behalf.',
      fail: 'The sending server was not authorised by the domain it claims to send for.',
      softfail: 'The domain lists this server as probably not authorised, but stops short of saying so outright.',
      none: 'The domain publishes no SPF record, so there was nothing to check against.',
      other: 'No verdict could be reached — usually a lookup that failed rather than a judgement.',
    },
    dkim: {
      pass: 'The message carries an intact cryptographic signature from the domain.',
      fail: 'A signature was present but did not verify. The message was altered in transit, or it was never signed by the domain it names.',
      none: 'The message carries no signature at all, so nothing about it can be verified cryptographically.',
      other: 'The signature could not be evaluated.',
    },
    dmarc: {
      pass: 'The domain\'s published policy on failures was satisfied.',
      fail: 'The message failed the domain\'s own policy — the domain owner asks receivers not to trust mail like this.',
      none: 'The domain publishes no DMARC policy, so it has never said what should happen to forgeries.',
      other: 'The policy could not be evaluated.',
    },
    arc: { other: 'Chain of custody across forwarding hops.' },
    bimi: { other: 'Brand logo verification.' },
  };

  // Only SPF, DKIM and DMARC carry weight. BIMI and ARC are absent or failing
  // on most legitimate mail, so colouring them red would cry wolf.
  const DECISIVE = new Set(['spf', 'dkim', 'dmarc']);
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
      note: DECISIVE.has(mechanism) ? null : 'Informational — commonly absent even on legitimate mail.',
    });
  }

  const dmarcPolicy = get(headers, 'x-dmarc-policy') || results.match(/p=(\w+)/)?.[0];
  if (dmarcPolicy) {
    items.push({
      label: 'Published DMARC policy',
      value: dmarcPolicy,
      note: 'What the domain owner asks receivers to do with messages that fail.',
    });
  }

  // Received-SPF usually carries a sentence explaining the verdict, which says
  // more than `spf=fail` does — it names the domain and the server that was not
  // authorised for it.
  if (receivedSpf) {
    const [outcome, ...rest] = receivedSpf.split(/\s+/);
    const explanation = rest.join(' ').replace(/^\((.*)\)$/, '$1').trim();
    if (explanation) {
      items.push({
        label: `Received-SPF: ${outcome.replace(/[^A-Za-z]/g, '')}`,
        value: explanation,
        note: 'The receiving server\'s own words, recorded as it made the decision.',
      });
    }
  }

  const signingDomain = dkimSignature.match(/\bd=([^;\s]+)/)?.[1];
  if (signingDomain) {
    items.push({
      label: 'Signed by domain',
      value: signingDomain,
      note: 'The signature proves this domain sent it — it says nothing about whether the domain is trustworthy.',
    });
  }

  const timestamp = dkimSignature.match(/\bt=(\d{9,})/)?.[1];
  if (timestamp) {
    items.push({
      label: 'Signed at',
      value: new Date(Number(timestamp) * 1000).toISOString().replace('T', ' ').replace(/\..+/, ' UTC'),
    });
  }

  // A length tag signs only the first l= bytes of the body. Everything after
  // that can be appended by anyone without breaking the signature, so "DKIM
  // passed" stops meaning "the message is intact". Rare in ordinary mail and
  // worth naming when it appears, but reported as a property of the signature
  // rather than as an accusation — some legitimate mailing lists set it.
  const signedLength = dkimSignature.match(/\bl=(\d+)/)?.[1];
  if (signedLength) {
    items.push({
      label: 'Only part of the message is signed',
      value: `The signature covers the first ${Number(signedLength).toLocaleString('en')} bytes of the body.`,
      note: 'Anything after that can be added without invalidating it, so a passing DKIM result does not vouch for the whole message.',
      level: 'caution',
    });
  }

  const algorithm = dkimSignature.match(/\ba=([\w-]+)/)?.[1]?.toLowerCase();
  if (algorithm && /sha1$/.test(algorithm)) {
    items.push({
      label: `Signed with ${algorithm}`,
      value: 'SHA-1 has been prohibited for DKIM since RFC 8301 in 2018, because collisions are practical.',
      note: 'Most receivers now treat such a signature as no signature at all.',
      level: 'caution',
    });
  }

  const allPass = Object.values(verdicts).filter((v) => v === 'pass').length >= 2;
  const failed = Object.entries(verdicts)
    .filter(([mechanism, verdict]) => DECISIVE.has(mechanism) && verdict === 'fail')
    .map(([mechanism]) => mechanism.toUpperCase());

  return {
    id: 'auth',
    title: allPass
      ? 'Every check passed. That proves less than it sounds.'
      : failed.length
        ? 'The sender\'s identity did not check out'
        : 'Authentication results',
    tone: failed.length ? 'alert' : 'info',
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

function parseReceived(value) {
  const [head, tail] = splitOnce(value, ';');
  return {
    from: head.match(/\bfrom\s+([^\s;()]+)/i)?.[1] ?? null,
    by: head.match(/\bby\s+([^\s;()]+)/i)?.[1] ?? null,
    protocol: head.match(/\bwith\s+([A-Za-z0-9]+)/i)?.[1] ?? null,
    date: tail?.trim() || null,
  };
}

function splitOnce(text, separator) {
  const index = text.lastIndexOf(separator);
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

  const scl = Number(
    get(headers, 'x-forefront-antispam-report').match(/\bSCL:(-?\d+)/i)?.[1]
    ?? get(headers, 'x-ms-exchange-organization-scl'),
  );
  return Number.isFinite(scl) && scl >= 5;
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
