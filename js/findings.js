// Header → findings. This module is the product; everything else is plumbing.
//
// Each finding states what was found, what it means, and which header it came
// from. The tone is dry rather than alarmed: the goal is for someone to
// understand their own mail, not to be told what to feel about it.

import { bestDecode, decodeSegments, findAddresses, prettifyNulls } from './decode.js';
import { extractUrls, inspectUnsubscribeLink, registrableDomain } from './links.js';
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
];

export function analyse(headers) {
  const findings = [];
  const push = (f) => { if (f) findings.push(f); };

  push(recipientFinding(headers));
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

/**
 * Shorten an opaque value for display.
 *
 * Tracking payloads run to kilobytes of base64. The head and tail are what a
 * reader can act on — enough to recognise the value again, and to see that it
 * is an id rather than a sentence — so the middle is what gets dropped.
 */
function clip(value, max = 160) {
  const text = String(value ?? '').trim();
  if (text.length <= max) return text;
  const keep = Math.floor((max - 3) / 2);
  return `${text.slice(0, keep)}...${text.slice(-keep)}`;
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
      record(`${stripBouncePrefix(local)}@${domain}`, 'VERP bounce address');
    }
  }

  if (!open.size && !hidden.size) return null;

  // Where an address was found is a list of short facts, not a sentence — it
  // goes into chips so the count is visible at a glance and the prose is left
  // to say the one thing prose is good for: what it means.
  const placeChips = (entries) => entries.map((e) => `${e.field} · ${e.method}`);

  const items = [];
  for (const [address, fields] of open) {
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

  const explain = {
    spf: 'The sending server was authorised by the domain to send on its behalf.',
    dkim: 'The message carries an intact cryptographic signature from the domain.',
    dmarc: 'The domain\'s published policy on failures was satisfied.',
    arc: 'Chain of custody across forwarding hops.',
    bimi: 'Brand logo verification.',
  };

  // Only SPF, DKIM and DMARC carry weight. BIMI and ARC are absent or failing
  // on most legitimate mail, so colouring them red would cry wolf.
  const DECISIVE = new Set(['spf', 'dkim', 'dmarc']);
  for (const [mechanism, verdict] of Object.entries(verdicts)) {
    items.push({
      label: `${mechanism.toUpperCase()} = ${verdict}`,
      value: explain[mechanism] ?? '',
      level: DECISIVE.has(mechanism)
        ? (verdict === 'pass' ? 'good' : verdict === 'fail' ? 'bad' : null)
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

  const allPass = Object.values(verdicts).filter((v) => v === 'pass').length >= 2;

  return {
    id: 'auth',
    title: allPass ? 'Every check passed. That proves less than it sounds.' : 'Authentication results',
    tone: 'info',
    lede: allPass
      ? 'SPF, DKIM and DMARC answer one question: is this server allowed to send for this domain? They do not ask whether the mail is wanted, honest, or from someone you have heard of. A spammer who owns their domain passes all three — this one did, and the mailbox provider still filed it as junk.'
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
    return {
      label: `Hop ${index + 1}${index === 0 ? ' — origin' : ''}`,
      value: [
        hop.from ? `from ${hop.from}` : null,
        hop.by ? `by ${hop.by}` : null,
        hop.protocol ? `via ${hop.protocol}` : null,
      ].filter(Boolean).join('  '),
      chips: [hop.date, platform ? `${platform.name} — bulk mail platform` : null]
        .filter(Boolean),
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

  if (!items.length) return null;

  return {
    id: 'judgement',
    title: 'Someone already made up their mind',
    tone: 'neutral',
    lede: 'Filters along the way left their verdicts in the header. These are opinions, not facts — but they are the opinions that decided which folder this landed in.',
    items,
  };
}
