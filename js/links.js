// Unsubscribe- and redirect-link analysis — entirely offline.
//
// The obvious way to check a link is to ask a reputation service. We refuse to:
// these URLs carry a per-recipient id, so the lookup would leak exactly what
// this tool exists to protect. Everything below is structural, and it turns out
// structure answers most of the question.

import { clip, readability } from './decode.js';
import { identifySender, KIND_LABELS } from './senders.js';

// Approximation of the Public Suffix List — enough to stop `example.co.uk` from
// being read as `co.uk`. Labelled as approximate wherever it surfaces in the UI.
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'co.nz', 'co.za', 'co.jp', 'or.jp', 'ne.jp',
  'com.br', 'com.mx', 'com.ar', 'co.in', 'com.cn', 'com.tr', 'com.pl',
]);

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

// Paths a genuine unsubscribe endpoint tends to use.
const UNSUB_PATH_RE = /(unsub|unsubscribe|optout|opt-out|remove|preferences|subscription|abmeld)/i;
// Paths that have no business being behind an unsubscribe link.
const CREDENTIAL_PATH_RE = /(login|signin|sign-in|verify|validate|confirm-?account|password|secure|billing|payment|invoice|wallet|update-?info)/i;

/** Registrable domain (eTLD+1), approximately. */
export function registrableDomain(host) {
  const labels = String(host ?? '').toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  const take = MULTI_PART_SUFFIXES.has(lastTwo) ? 3 : 2;
  return labels.slice(-take).join('.');
}

/** Pull every http(s) and mailto URL out of a string. */
export function extractUrls(text) {
  const matches = String(text ?? '').match(/<([^>]+)>|(https?:\/\/[^\s<>"']+)|(mailto:[^\s<>"',]+)/gi) ?? [];
  return [...new Set(
    matches
      .map((m) => m.replace(/^<|>$/g, '').trim())
      .filter((m) => /^(https?:\/\/|mailto:)/i.test(m)),
  )];
}

/**
 * Unwrap an ESP click-tracking redirect.
 *
 * These pack the real destination into base64 path segments, usually behind a
 * one-character type prefix (`V` for the URL, `S` for the campaign, and so on).
 * Returns every readable fragment found, with the destination URL singled out.
 */
export function unwrapRedirect(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }

  const segments = [
    ...parsed.pathname.split('/'),
    ...parsed.search.replace(/^\?/, '').split(/[/&=]/),
  ].filter((s) => s.length >= 6);

  const fragments = [];
  let destination = null;

  for (const segment of segments) {
    for (const [offset, note] of [[0, null], [1, 'type-prefixed']]) {
      const body = segment.slice(offset);
      if (body.length < 6) continue;
      const text = base64ToText(body);
      if (text === null) continue;

      if (/^https?:\/\/\S+$/i.test(text.trim())) {
        if (!destination) destination = text.trim();
        fragments.push({ segment, text: text.trim(), kind: 'destination', note });
        break;
      }
      // A query fragment is unmistakable by shape, and scores low on
      // readability because an opaque id contains no words.
      if (/^[?&][A-Za-z0-9_.-]+=/.test(text) || readability(text) >= 0.6) {
        fragments.push({ segment, text, kind: 'metadata', note });
        break;
      }
    }
  }

  // Later segments often hold the query string of the destination (`?id=…`).
  const query = fragments.find((f) => f.kind === 'metadata' && f.text.startsWith('?'));
  if (destination && query) destination += query.text;

  return { url, destination, fragments };
}

function base64ToText(input) {
  if (/[^A-Za-z0-9+/\-_=]/.test(input)) return null;
  const normalised = input.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (normalised.length % 4 === 1) return null;
  try {
    const binary = atob(normalised + '='.repeat((4 - (normalised.length % 4)) % 4));
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    return text.includes('�') ? null : text;
  } catch {
    return null;
  }
}

/**
 * Structural verdict on an unsubscribe link.
 *
 * `signals` are ordered worst-first and each carry a `level`:
 *   'bad'      — a phishing tell, do not click
 *   'caution'  — worth knowing before clicking
 *   'good'     — consistent with a legitimate bulk sender
 */
export function inspectUnsubscribeLink(url, context = {}) {
  const { fromDomain = '', hasOneClickHeader = false } = context;
  const signals = [];

  if (/^mailto:/i.test(url)) {
    signals.push({
      level: 'good',
      title: 'Unsubscribes by email, not by click',
      detail: 'A mailto: unsubscribe cannot carry click tracking. This is the harmless variant.',
    });
    return { url, destination: null, signals, verdict: 'plausible' };
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return {
      url,
      destination: null,
      signals: [{ level: 'bad', title: 'Not a parseable URL', detail: 'This is not a well-formed link.' }],
      verdict: 'suspicious',
    };
  }

  const unwrapped = unwrapRedirect(url);
  const destination = unwrapped?.destination ?? null;
  let destParsed = null;
  if (destination) {
    try {
      destParsed = new URL(destination);
    } catch {
      /* keep destParsed null */
    }
  }

  const effective = destParsed ?? parsed;
  const effectiveHost = effective.hostname;
  const effectiveDomain = registrableDomain(effectiveHost);
  const linkDomain = registrableDomain(parsed.hostname);

  if (parsed.username || parsed.password) {
    signals.push({
      level: 'bad',
      title: 'Credentials embedded before the hostname',
      detail: `Everything before the @ is decoration; the real host is ${effectiveHost}. This is a classic disguise.`,
    });
  }

  if (IPV4_RE.test(parsed.hostname)) {
    signals.push({
      level: 'bad',
      title: 'Bare IP address instead of a hostname',
      detail: 'Legitimate senders use a named domain. A raw IP means nobody wanted this traced back.',
    });
  }

  if (/(^|\.)xn--/.test(parsed.hostname) || (destParsed && /(^|\.)xn--/.test(destParsed.hostname))) {
    signals.push({
      level: 'bad',
      title: 'Punycode in the hostname',
      detail: 'The domain uses non-Latin characters rendered as xn--. Often a lookalike of a familiar brand.',
    });
  }

  if (parsed.protocol === 'http:') {
    signals.push({
      level: 'caution',
      title: 'Unencrypted http://',
      detail: 'Your unsubscribe request, including the recipient id, travels in the clear.',
    });
  }

  if (destination && linkDomain !== effectiveDomain) {
    signals.push({
      level: 'caution',
      title: 'The link redirects elsewhere',
      detail: `You see ${linkDomain}, you land on ${effectiveDomain}. The hop exists to count the click.`,
    });
  } else if (!destination && /\/(click|track|r|redir|c)\b/i.test(parsed.pathname)) {
    signals.push({
      level: 'caution',
      title: 'Click-tracking redirect',
      detail: 'The path looks like a tracker, but the destination is not encoded in a way this tool can read.',
    });
  }

  const path = effective.pathname + effective.search;
  if (CREDENTIAL_PATH_RE.test(path)) {
    signals.push({
      level: 'bad',
      title: 'Destination asks for an account, not an unsubscribe',
      detail: `The target path points at a login or payment flow, and an unsubscribe never needs either: ${clip(effective.pathname, 80)}`,
    });
  } else if (UNSUB_PATH_RE.test(path)) {
    signals.push({
      level: 'good',
      title: 'Destination path matches an unsubscribe endpoint',
      detail: `The path is shaped like a genuine opt-out: ${clip(effective.pathname, 80)}`,
    });
  }

  if (fromDomain) {
    const senderDomain = registrableDomain(fromDomain);
    const brand = (d) => d.split('.')[0];
    if (senderDomain === effectiveDomain) {
      signals.push({
        level: 'good',
        title: 'Unsubscribe stays on the sender domain',
        detail: `Both are ${senderDomain}.`,
      });
    } else if (brand(senderDomain) === brand(effectiveDomain)) {
      signals.push({
        level: 'caution',
        title: 'Same brand, different domain',
        detail: `Mail from ${senderDomain}, unsubscribe on ${effectiveDomain}. Common for large senders who split marketing and delivery — but it is also what a convincing fake looks like.`,
      });
    } else {
      signals.push({
        level: 'caution',
        title: 'Unsubscribe leads to an unrelated domain',
        detail: `Mail from ${senderDomain}, unsubscribe on ${effectiveDomain}. Nothing connects the two by name.`,
      });
    }
  }

  // Recognising the platform turns "unknown domain" into "ordinary infrastructure".
  for (const [domain, role] of [[linkDomain, 'link'], [effectiveDomain, 'destination']]) {
    const platform = identifySender(domain);
    if (!platform) continue;
    if (role === 'destination' && effectiveDomain === linkDomain) continue;
    signals.push({
      level: platform.kind === 'shortener' ? 'caution' : 'good',
      title:
        platform.kind === 'shortener'
          ? `Hidden behind a ${KIND_LABELS.shortener} (${platform.name})`
          : `${role === 'link' ? 'Link' : 'Destination'} runs on a known ${KIND_LABELS.esp}`,
      detail:
        platform.kind === 'shortener'
          ? `${domain} conceals where you actually land. Legitimate senders have no reason to shorten an unsubscribe link.`
          : `${domain} belongs to ${platform.name}. A redirect through it is normal for bulk mail — it is how the sender counts clicks, not a sign of forgery.`,
    });
  }

  if (hasOneClickHeader) {
    signals.push({
      level: 'good',
      title: 'Supports RFC 8058 one-click unsubscribe',
      detail: 'Use your mail client\'s own unsubscribe button instead of this link — it talks to the header directly and skips the click tracker.',
    });
  }

  const order = { bad: 0, caution: 1, good: 2 };
  signals.sort((a, b) => order[a.level] - order[b.level]);

  const verdict = signals.some((s) => s.level === 'bad')
    ? 'suspicious'
    : signals.some((s) => s.level === 'good')
      ? 'plausible'
      : 'unclear';

  // Hostnames worth checking against the offline blocklist, most specific first.
  const hostsToCheck = [...new Set([destParsed?.hostname, parsed.hostname].filter(Boolean))];

  return { url, destination, fragments: unwrapped?.fragments ?? [], signals, verdict, hostsToCheck };
}
