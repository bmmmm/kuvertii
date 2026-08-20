// Body → findings. The header module's sibling, under a stricter rule: the
// body is 100% attacker text, and it is described, never rendered. No body
// HTML reaches an HTML sink, nothing it names is fetched, and every quoted
// snippet goes to the screen through the same neutralise+defang pass as every
// header value — this module only builds finding objects.

import { hasControls, scanControls } from './control.js';
import { clip, hasKnownTld } from './decode.js';
import { guardSection } from './findings.js';
import {
  CREDENTIAL_PATH_RE, extractUrls, isAddressLiteral, registrableDomain, unwrapRedirect,
} from './links.js';
import { scanMarkup } from './markup.js';
import { identifySender, KIND_LABELS } from './senders.js';

// Target domains listed by name before the rest becomes a count. Warnings are
// never subject to this — a warning row is bounded by content, not position.
const DOMAINS_SHOWN = 12;

// Hostnames handed to the offline blocklist per message. The lookup is cheap;
// the bound exists because the sender writes the link count.
const MAX_HOSTS_CHECKED = 50;

// The same categories js/control.js neutralises — what a reader's screen
// renders as nothing. Used to reconstruct what a link's text *looks like*
// before asking which domain it claims.
const INVISIBLE_IN_TEXT = /[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}]/gu;

/**
 * The party a host belongs to — and for an address literal, the address.
 *
 * `registrableDomain` reads its input as labels, so handed `203.0.113.44` it
 * answers `113.44`: two octets dressed up as a domain, printed as where a
 * link "goes to". An address has no registrable domain; it is compared and
 * displayed whole.
 */
function party(host) {
  return isAddressLiteral(host) ? host : registrableDomain(host);
}

/**
 * Findings out of the body parts, fault-isolated like every header section.
 *
 * `bodyOnly` marks a paste that carried no recognisable header: the notice it
 * produces leads the report, because every finding a header would anchor —
 * sender, recipient, authentication, route — is missing, and the reader must
 * know that before reading anything below it.
 */
export function analyseBody(parts, { bodyOnly = false } = {}) {
  const findings = [];
  if (bodyOnly) findings.push(bodyOnlyNotice());
  if (!parts?.length) return findings;

  const links = guardSection('body links', () => linkFinding(parts));
  if (links) findings.push(links);

  return findings;
}

function bodyOnlyNotice() {
  return {
    id: 'body-only',
    title: 'A message body without its header',
    tone: 'info',
    lede: 'Nothing above the content parsed as a header block, so the questions a header answers — who sent this, to whom, whether its authentication held, which route it took — cannot be answered here. What the body itself says is read below. For the whole picture, paste the full "Show Original" / "View Source" output, header included.',
    items: [{
      label: 'Missing with the header',
      value: 'Sender, recipients, authentication verdicts, tracking identifiers, the delivery route — every finding that needs a header field.',
      level: 'absent',
    }],
  };
}

// ------------------------------------------------------------------ the card

/**
 * Where the links in this message go.
 *
 * Every judgement here is structural and offline: destinations are read out
 * of the message, redirects are unwrapped by decoding them, and the hosts are
 * handed to the offline blocklist through the same `hostsToCheck` bridge the
 * unsubscribe card uses. Warning rows are deduplicated by what they say, and
 * never crowded out by volume — the 500-signatures lesson.
 */
function linkFinding(parts) {
  const collected = [];
  const formActions = [];
  let base = null;
  let scannerTruncated = false;

  for (const part of parts) {
    if (!part.text) continue;
    if (part.contentType === 'text/html') {
      const scan = scanMarkup(part.text);
      base ??= scan.base;
      if (scan.truncated) scannerTruncated = true;
      for (const link of scan.links) collected.push({ href: link.href, text: link.text });
      for (const form of scan.forms) formActions.push(form.action);
    } else if (part.contentType.startsWith('text/')) {
      for (const url of extractUrls(part.text)) collected.push({ href: url, text: '' });
    }
  }

  if (!collected.length && !formActions.length) return null;

  // Dedup by what a row says: one warning per (kind, claim), however many
  // links repeat the pattern.
  const warnings = new Map();
  const warn = (key, item) => {
    if (!warnings.has(key)) warnings.set(key, item);
  };

  const targets = new Map(); // registrable domain -> { count, via:Set }
  const hosts = new Set();
  let baseUrl;
  try {
    baseUrl = base && /^https?:/i.test(base) ? new URL(base) : undefined;
  } catch {
    baseUrl = undefined;
  }

  for (const link of collected) {
    const href = String(link.href ?? '').trim();
    if (!href || href.startsWith('#')) continue;

    const scheme = href.match(/^([a-zA-Z][a-zA-Z0-9+.-]{0,15}):/)?.[1]?.toLowerCase() ?? null;

    if (scheme === 'javascript' || scheme === 'data' || scheme === 'vbscript' || scheme === 'file') {
      warn(`scheme:${scheme}`, {
        label: `A link is a ${scheme}: URI`,
        value: clip(href, 120),
        mono: true,
        level: 'bad',
        note: 'No destination on the web looks like this. A link of this shape exists to run or smuggle something in the program that opens it, not to take you anywhere.',
      });
      continue;
    }
    if (scheme && scheme !== 'http' && scheme !== 'https') continue; // mailto:, cid:, tel: — not journeys

    let parsed = null;
    try {
      parsed = new URL(href, baseUrl);
    } catch {
      continue;
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') continue;

    const linkHost = parsed.hostname;
    const linkDomain = party(linkHost);

    const unwrapped = unwrapRedirect(parsed.href);
    let destination = null;
    if (unwrapped?.destination) {
      try {
        destination = new URL(unwrapped.destination);
      } catch {
        destination = null;
      }
    }
    const effective = destination ?? parsed;
    const effectiveDomain = party(effective.hostname);

    hosts.add(linkHost);
    if (destination) hosts.add(destination.hostname);

    if (parsed.username || parsed.password) {
      warn(`userinfo:${linkHost}`, {
        label: 'Credentials embedded before a hostname',
        value: clip(href, 120),
        mono: true,
        level: 'bad',
        note: `Everything before the @ is decoration; the real host is ${linkHost}. This is a classic disguise.`,
      });
    }

    if (isAddressLiteral(linkHost) || (destination && isAddressLiteral(destination.hostname))) {
      warn(`ip:${effective.hostname}`, {
        label: 'A link leads to a bare IP address',
        value: clip(effective.hostname, 120),
        mono: true,
        level: 'bad',
        note: 'Legitimate senders link to named domains. A raw address means nobody wanted this traced back to one.',
      });
    }

    for (const candidate of [linkHost, destination?.hostname]) {
      if (candidate && /(^|\.)xn--/.test(candidate)) {
        warn(`punycode:${candidate}`, {
          label: 'Punycode in a link hostname',
          value: clip(candidate, 120),
          mono: true,
          level: 'bad',
          note: 'The domain uses non-Latin characters rendered as xn--. Often a lookalike of a familiar name.',
        });
      }
    }

    if (CREDENTIAL_PATH_RE.test(effective.pathname + effective.search)) {
      warn(`credential:${effectiveDomain}`, {
        label: 'A link points into a login or payment flow',
        value: clip(effective.pathname + effective.search, 120),
        mono: true,
        level: 'caution',
        note: `The path on ${effectiveDomain} is shaped like a place that asks for an account. Honest mail links there too — but it is exactly where a lookalike wants you, so check the domain above it before typing anything.`,
      });
    }

    // The single highest-value body finding: the words of the link claim one
    // place, the link goes to another. Compared by registrable domain, never
    // by string — www.paypal.com and paypal.com are one party.
    //
    // The claim is read off what the reader *sees*, so characters that render
    // as nothing are removed first: `paypal.com` with a bidi mark appended,
    // or zero-widths threaded through it, still reads as paypal.com on
    // screen — and skipping the comparison for exactly those links would
    // hand the evasion to the one sender who bothered to hide.
    const claimed = domainInText(String(link.text ?? '').replace(INVISIBLE_IN_TEXT, ''));
    if (claimed) {
      const claimedDomain = registrableDomain(claimed);
      if (claimedDomain !== linkDomain && claimedDomain !== effectiveDomain) {
        const platform = identifySender(linkDomain) ?? identifySender(effectiveDomain);
        if (platform) {
          warn(`mismatch-via:${claimedDomain}:${effectiveDomain}`, {
            label: `The text says ${claimed}, the link goes through ${platform.name}`,
            value: clip(href, 160),
            mono: true,
            level: 'caution',
            note: `The visible text names ${claimedDomain}; the link runs to ${effectiveDomain}, a known ${KIND_LABELS[platform.kind] ?? 'platform'}. Ordinary for tracked bulk mail — where you land after the hop is not written in a form this tool can read, so it cannot confirm the claim either.`,
          });
        } else {
          warn(`mismatch:${claimedDomain}:${effectiveDomain}`, {
            label: `The text says ${claimed}, the link goes to ${effectiveDomain}`,
            value: clip(href, 160),
            mono: true,
            level: 'bad',
            emphasis: true,
            note: 'The words of a link and its destination are written independently, and nothing checks them against each other before you click. Text that names one domain over a link that leaves for another is the shape of a lookalike.',
          });
        }
      }
    }

    if (hasControls(link.text)) {
      warn(`control:${effectiveDomain}`, {
        label: 'A link\'s visible text carries characters that steer how it reads',
        value: `It ${scanControls(link.text).join('; it ')}.`,
        level: 'bad',
        note: 'Shown inert here. Where you would read this link, those characters decide what you see — which is the point of putting them into a link.',
      });
    }

    const target = targets.get(effectiveDomain) ?? { count: 0, via: new Set() };
    target.count += 1;
    if (destination && linkDomain !== effectiveDomain) target.via.add(linkDomain);
    targets.set(effectiveDomain, target);
  }

  for (const action of formActions.slice(0, 8)) {
    let host = null;
    try {
      host = new URL(String(action ?? ''), baseUrl).hostname;
    } catch {
      host = null;
    }
    if (host) hosts.add(host);
    warn(`form:${host ?? '(unstated)'}`, {
      label: 'This message contains a form',
      value: action ? `It submits to ${clip(String(action), 120)}.` : 'It does not say where it submits to.',
      level: 'bad',
      emphasis: true,
      note: 'A message that collects input inside itself is asking you to skip the address bar and every other place you would check who is asking. Mail clients differ in whether they submit forms at all; no honest sender relies on it.',
    });
  }

  const items = [...warnings.values()];

  const ranked = [...targets].sort((a, b) => b[1].count - a[1].count);
  for (const [domain, target] of ranked.slice(0, DOMAINS_SHOWN)) {
    const platform = identifySender(domain);
    items.push({
      label: domain,
      value: `${target.count} link${target.count === 1 ? '' : 's'}${
        target.via.size ? `, reached through ${[...target.via].join(', ')}` : ''
      }`,
      chips: platform ? [`${platform.name} — ${KIND_LABELS[platform.kind] ?? platform.kind}`] : [],
      mono: true,
    });
  }
  if (ranked.length > DOMAINS_SHOWN) {
    items.push({
      label: `and ${ranked.length - DOMAINS_SHOWN} more domains`,
      value: 'The links to them raised none of the warnings above.',
    });
  }

  if (scannerTruncated) {
    items.push({
      label: 'Not every link was read',
      value: 'This message carries more links than this card reads. The ones past the ceiling were not judged — treat this card as a sample, not an inventory.',
      level: 'caution',
    });
  }

  const hostsToCheck = [...hosts].slice(0, MAX_HOSTS_CHECKED);

  return {
    id: 'body-links',
    title: 'Where the links in this message go',
    tone: items.some((item) => item.level === 'bad') ? 'alert' : 'info',
    lede: 'Every destination below was read out of the message itself — nothing was clicked, nothing fetched. The text of a link and where it goes are written independently, and the difference between the two is where a message says one thing and does another.',
    items,
    hostsToCheck,
  };
}

/**
 * The domain a link's visible text claims, if it claims one.
 *
 * Quantifiers bounded to what DNS permits, for the reason EMAIL_RE documents:
 * the text is sender-written and can be any length.
 *
 * A bare name only counts when it ends in a TLD a reader would recognise —
 * `Node.js` in a link label is a product, not a place, and reading it as one
 * would put a false warning on ordinary mail. A name behind an explicit
 * http(s):// is always a claim: nobody writes a scheme by accident.
 */
function domainInText(text) {
  const match = String(text ?? '').match(
    /(?:^|[\s(["'>])(https?:\/\/)?([a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,10}\.[a-z]{2,24})(?=[/\s)\]"'<,:]|$)/i,
  );
  if (!match) return null;
  const [, scheme, host] = match;
  if (!scheme && !hasKnownTld(host)) return null;
  return host.toLowerCase();
}
