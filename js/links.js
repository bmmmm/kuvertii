// Unsubscribe- and redirect-link analysis — entirely offline.
//
// The obvious way to check a link is to ask a reputation service. We refuse to:
// these URLs carry a per-recipient id, so the lookup would leak exactly what
// this tool exists to protect. Everything below is structural, and it turns out
// structure answers most of the question.

import { clip, readability } from './decode.js';
import { EXACT, EXCEPTION, WILDCARD } from './psl.js';
import { identifySender, KIND_LABELS } from './senders.js';

// Where one organisation's namespace ends and the next begins, from the Public
// Suffix List, baked in at build time by tools/build-psl.mjs.
//
// This used to be a hand-written list of twenty-one suffixes described as an
// approximation. It was not a safe one. `bank.com.sg` and `evil.com.sg` both
// reduced to `com.sg`, so a message from a bank with an unsubscribe link on an
// unrelated domain rendered as `✓ Unsubscribe stays on the sender domain —
// both are com.sg`. The error only ever ran one way, towards merging two
// parties into one, which is the direction that turns a warning into a
// reassurance. There are 8,806 multi-label rules; the list held 21.
//
// Both published sections are used, not only ICANN. ICANN alone answers the
// DMARC organisational-domain question — which registry sold this name — but
// the question asked here is whether two names belong to the same party, and on
// a hosting platform that answer is in the PRIVATE section. Without it
// `alice.github.io` and `evil.github.io` are the same domain, which is the
// `com.sg` bug again in a different suffix.
//
// Not the DNS tree walk that RFC 9989 §4.10 defines for DMARC: that needs up to
// five DNS queries per evaluation, and this tool does not make queries. The
// published list is the offline answer to the same question, and that question
// stays closed.

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

// Paths a genuine unsubscribe endpoint tends to use.
const UNSUB_PATH_RE = /(unsub|unsubscribe|optout|opt-out|remove|preferences|subscription|abmeld)/i;
// Paths that have no business being behind an unsubscribe link.
const CREDENTIAL_PATH_RE = /(login|signin|sign-in|verify|validate|confirm-?account|password|secure|billing|payment|invoice|wallet|update-?info)/i;

/**
 * How many trailing labels of `labels` form the public suffix.
 *
 * The algorithm published alongside the list: take every matching rule, prefer
 * an exception over all others, otherwise prefer the one with the most labels.
 * Scanning from the left tries the longest candidate first, so the first match
 * is the prevailing rule and the loop can stop there.
 *
 * An exception rule (`!www.ck`) is applied by dropping its leftmost label,
 * which is why it yields one label fewer than it matched. An unmatched name
 * falls to the default rule `*` — one label — and that is also what stands in
 * for every single-label rule, since js/psl.js does not ship those.
 */
function publicSuffixLength(labels) {
  for (let i = 0; i < labels.length; i++) {
    const candidate = labels.slice(i).join('.');
    if (EXCEPTION.has(candidate)) return labels.length - i - 1;
    if (EXACT.has(candidate)) return labels.length - i;
    if (i + 1 < labels.length && WILDCARD.has(labels.slice(i + 1).join('.'))) {
      return labels.length - i;
    }
  }
  return 1;
}

/**
 * Registrable domain (eTLD+1) — the boundary between two parties.
 *
 * A name that is itself a public suffix, or shorter than one, is returned whole:
 * `co.uk` has no registrant to name, and pretending otherwise would invent one.
 */
export function registrableDomain(host) {
  const labels = String(host ?? '').toLowerCase().replace(/\.$/, '').split('.');
  const suffix = publicSuffixLength(labels);
  if (suffix >= labels.length) return labels.join('.');
  return labels.slice(labels.length - suffix - 1).join('.');
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
