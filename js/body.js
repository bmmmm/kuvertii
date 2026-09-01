// Body → findings. The header module's sibling, under a stricter rule: the
// body is 100% attacker text, and it is described, never rendered. No body
// HTML reaches an HTML sink, nothing it names is fetched, and every quoted
// snippet goes to the screen through the same neutralise+defang pass as every
// header value — this module only builds finding objects.

import { hasControls, scanControls } from './control.js';
import { clip, hasKnownTld } from './decode.js';
import { guardSection, knownRecipientAddresses } from './findings.js';
import {
  CREDENTIAL_PATH_RE, extractUrls, isAddressLiteral, registrableDomain, unwrapRedirect,
} from './links.js';
import { scanMarkup } from './markup.js';
import { identifySender, KIND_LABELS } from './senders.js';
import { get, getAll } from './unfold.js';

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
 * Every destination an HTML part offers a reader — hrefs and form actions are
 * only part of the answer.
 *
 * A URL written into the visible text of an HTML mail, with no anchor around
 * it, is turned into a live link by every mail client that renders the part;
 * a great deal of ordinary bulk mail is written that way. Reading only the
 * hrefs meant such a message drew no link card at all — a body whose one
 * destination was `https://tracker.example/click?u=…`, typed out in a
 * paragraph, produced silence.
 *
 * A URL that *is* a link's own text is not one of these: it is the claim the
 * link makes about itself, judged against the href by the mismatch rule, and
 * counting it as a destination would put the decoy back on the card as a place
 * the message goes.
 */
function autolinkedUrls(scan) {
  const claimed = new Set(scan.links.flatMap((link) => extractUrls(link.text)));
  return extractUrls(scan.text).filter((url) => !claimed.has(url));
}

/**
 * Findings out of the body parts, fault-isolated like every header section.
 *
 * `bodyOnly` marks a paste that carried no recognisable header: the notice it
 * produces leads the report, because every finding a header would anchor —
 * sender, recipient, authentication, route — is missing, and the reader must
 * know that before reading anything below it.
 */
export function analyseBody(parts, { headers = [], bodyOnly = false } = {}) {
  const findings = [];
  if (bodyOnly) findings.push(bodyOnlyNotice(Boolean(parts?.length)));
  if (!parts?.length) return findings;

  // One markup scan per part, shared by every producer. Memoised rather than
  // hoisted out of the guards: a scan that throws costs each section that
  // needed it, reported by its own guard, instead of costing them all in one
  // unattributed place.
  const scans = new Map();
  const scanOf = (part) => {
    if (!scans.has(part)) scans.set(part, scanMarkup(part.text));
    return scans.get(part);
  };

  const links = guardSection('body links', () => linkFinding(parts, scanOf));
  if (links) findings.push(links);

  const tracking = guardSection('body tracking', () => trackingFinding(parts, scanOf, headers));
  if (tracking) findings.push(tracking);

  const attachments = guardSection('attachments', () => attachmentFinding(parts));
  if (attachments) findings.push(attachments);

  const divergence = guardSection('plain/html divergence', () => divergenceFinding(parts, scanOf));
  if (divergence) findings.push(divergence);

  return findings;
}

/**
 * The notice a body-only paste leads with.
 *
 * `bodyWasRead` is not decoration. The sentence promising that the content is
 * read below is false whenever no part survived to be read — under
 * `--headers-only`, or when parseParts degraded to nothing — and it was
 * printed unconditionally, so the one card on screen announced a reading that
 * never happened and then ended.
 */
function bodyOnlyNotice(bodyWasRead) {
  const missing = 'This paste reads as the message content a mail program displays — nothing above it parsed as a header block. The questions a header answers — who sent this, to whom, whether its authentication held, which route it took — cannot be answered here.';
  const rest = bodyWasRead
    ? ' What the body itself says is read below.'
    : ' The body was not read either, so nothing below describes it.';
  return {
    id: 'body-only',
    title: 'A message body without its header',
    tone: 'info',
    lede: `${missing}${rest} The full header travels with every message, and mail programs keep it a menu away — paste what these show, whole:`,
    items: [
      {
        label: 'Missing with the header',
        value: 'Sender, recipients, authentication verdicts, tracking identifiers, the delivery route — every finding that needs a header field.',
        level: 'absent',
      },
      // Menu paths rather than keyboard shortcuts, which drift per version.
      { label: 'Apple Mail', value: 'View → Message → All Headers, or Raw Source for the whole message.' },
      // The desktop apps above all have a raw view; their phone apps do not,
      // so each gets its own row rather than a caveat buried in the desktop
      // one — a reader on a phone is looking for their app's name, not a
      // footnote under somebody else's.
      {
        label: 'iPhone Mail',
        value: 'No raw view: drag the message onto a minimised compose window — it attaches as an .eml, saved from there to Files. On iPad, drag it into Files directly in Split View.',
      },
      { label: 'Gmail (web)', value: 'Open the message → ⋮ More → "Show original", then copy the whole page.' },
      {
        label: 'Gmail app',
        value: 'No "Show original" here: open mail.google.com in a browser, request the desktop site, then ⋮ More → "Show original" → Download original.',
      },
      { label: 'Outlook', value: 'Open the message → File → Properties → the "Internet headers" box.' },
      {
        label: 'Outlook app',
        value: 'No such menu in the app either: open Outlook on the web (desktop site) → More actions → Save as → .eml.',
      },
      {
        label: 'Proton app',
        value: '⋮ → View headers → Share, which gives the header alone, not the full message.',
      },
      {
        label: 'An .eml file already in hand',
        value: 'This tool reads it directly — no header to copy, no menu to hunt for.',
      },
    ],
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
function linkFinding(parts, scanOf) {
  const collected = [];
  const formActions = [];
  let base = null;
  let scannerTruncated = false;

  for (const part of parts) {
    if (!part.text) continue;
    if (part.contentType === 'text/html') {
      const scan = scanOf(part);
      base ??= scan.base;
      if (scan.truncated) scannerTruncated = true;
      for (const link of scan.links) collected.push({ href: link.href, text: link.text });
      for (const url of autolinkedUrls(scan)) collected.push({ href: url, text: '' });
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

// ------------------------------------------------------------ what reading reveals

// Hex runs of exactly a digest's length — MD5, SHA-1, SHA-256 — pulled out of
// body URLs as candidates for a hashed address. Guarded on both sides so a
// 64-hex inside a 128-hex run is not three overlapping candidates.
const HEX_TOKEN_RE = /(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])/g;

// Candidate tokens handed to the async hash bridge. The sender writes the
// URL count; the bound keeps the digest work proportionate to a message,
// not to a payload.
const MAX_HASH_TOKENS = 200;

// Query values at least this long and alphabet-shaped are opaque ids — long
// enough that a word, a colour, or a size never qualifies.
const OPAQUE_ID_RE = /^[A-Za-z0-9+/=_.~-]{16,}$/;

/**
 * What reading and clicking this reveals.
 *
 * Nothing here is fetched — these are the wires the message carries, read in
 * place: images whose loading reports the reader, the reader's own address
 * riding inside link URLs (open, percent-encoded, base64, or — via the async
 * bridge — hashed), and header identifiers recurring in link queries, which
 * tie the message in the mailbox to the click.
 */
function trackingFinding(parts, scanOf, headers) {
  const images = [];
  const urls = [];

  for (const part of parts) {
    if (!part.text) continue;
    if (part.contentType === 'text/html') {
      const scan = scanOf(part);
      images.push(...scan.images);
      for (const link of scan.links) urls.push(String(link.href ?? ''));
      urls.push(...autolinkedUrls(scan));
      for (const image of scan.images) urls.push(String(image.src ?? ''));
      for (const form of scan.forms) urls.push(String(form.action ?? ''));
    } else if (part.contentType.startsWith('text/')) {
      urls.push(...extractUrls(part.text));
    }
  }

  const webUrls = urls.filter((url) => /^https?:\/\//i.test(url.trim()));
  const items = [];

  // ---- images: what displaying them reports, before anything is clicked.
  const pixelHosts = new Map(); // host -> { count, opaque }
  const externalHosts = new Set();
  for (const image of images) {
    const src = String(image.src ?? '').trim();
    if (!/^https?:\/\//i.test(src)) continue; // cid:/data: images load nothing remote
    let parsed;
    try {
      parsed = new URL(src);
    } catch {
      continue;
    }
    const host = party(parsed.hostname);
    externalHosts.add(host);

    const width = parseInt(image.width ?? '', 10);
    const height = parseInt(image.height ?? '', 10);
    if (Number.isInteger(width) && Number.isInteger(height) && width <= 1 && height <= 1) {
      const entry = pixelHosts.get(host) ?? { count: 0, opaque: false };
      entry.count += 1;
      if ([...parsed.searchParams.values()].some((value) => OPAQUE_ID_RE.test(value))) {
        entry.opaque = true;
      }
      pixelHosts.set(host, entry);
    }
  }

  for (const [host, { count, opaque }] of pixelHosts) {
    items.push({
      label: count === 1 ? 'A tracking pixel' : `${count} tracking pixels`,
      value: `A ${count === 1 ? '1×1 image' : 'set of 1×1 images'} from ${host}. Displaying images loads ${count === 1 ? 'it' : 'them'}, which reports your IP address and the moment you read this to ${host}. Nothing was loaded here.`,
      level: 'caution',
      emphasis: opaque,
      chips: opaque ? ['carries an id unique to this copy'] : [],
      note: opaque
        ? 'The pixel URL carries an opaque identifier, so the report does not just say that someone read the message — it says that you did.'
        : null,
    });
  }

  if (externalHosts.size) {
    const shown = [...externalHosts].slice(0, 8);
    const more = externalHosts.size - shown.length;
    items.push({
      label: `${images.filter((i) => /^https?:\/\//i.test(String(i.src ?? ''))).length} external image${externalHosts.size === 1 && images.length === 1 ? '' : 's'}`,
      value: `Each one, when displayed, reports your IP address and reading time to: ${shown.join(', ')}${more > 0 ? ` and ${more} more` : ''}. A mail client set to not load remote images reports nothing.`,
    });
  }

  // ---- the reader's own address inside the links, in every cheap spelling.
  // The hash spellings need the async bridge; these three are exact
  // substrings and are searched here, synchronously.
  const addresses = knownRecipientAddresses(headers);
  for (const address of addresses) {
    const spellings = [
      ['open', address],
      ['percent-encoded', address.replace('@', '%40')],
      ['base64', base64Trimmed(address)],
      ['base64, URL-safe', base64Trimmed(address).replace(/\+/g, '-').replace(/\//g, '_')],
    ];
    const found = new Map(); // spelling -> Set of hosts
    for (const url of webUrls) {
      const lower = url.toLowerCase();
      for (const [spelling, needle] of spellings) {
        if (!needle) continue;
        // Base64 is case-significant; the plain spellings are compared
        // case-blind, the way URLs are read.
        const hit = spelling.startsWith('base64') ? url.includes(needle) : lower.includes(needle);
        if (!hit) continue;
        if (!found.has(spelling)) found.set(spelling, new Set());
        found.get(spelling).add(hostOf(url));
      }
    }
    if (found.size) {
      const hosts = [...new Set([...found.values()].flatMap((set) => [...set]))].filter(Boolean);
      items.push({
        label: 'Your address travels inside the links',
        value: `${address} is carried ${[...found.keys()].join(', ')} in ${hosts.length === 1 ? 'a link' : 'links'} to ${hosts.slice(0, 6).join(', ')}.`,
        level: 'caution',
        emphasis: true,
        note: 'Clicking any of these hands the address over as part of the request — no form, no typing. That is how a click gets attributed to you personally.',
      });
    }
  }

  // ---- an id from the header recurring inside the links: the join between
  // the message in the mailbox and the click.
  for (const { token, field } of headerIdentifiers(headers)) {
    const joined = new Set();
    for (const url of webUrls) {
      let parsed;
      try {
        parsed = new URL(url);
      } catch {
        continue;
      }
      // In the path or query only: a token that merely echoes the hostname
      // ties nothing together.
      if ((parsed.pathname + parsed.search).includes(token)) joined.add(party(parsed.hostname));
    }
    if (joined.size) {
      items.push({
        label: 'An id from the header recurs inside the links',
        value: `${clip(token, 60)} appears in ${field} and in ${joined.size === 1 ? 'a link' : 'links'} to ${[...joined].slice(0, 4).join(', ')}. This id ties the message in your mailbox to your click.`,
        mono: true,
        level: 'caution',
      });
    }
  }

  // ---- candidates for the hash bridge: resolved asynchronously by the
  // front ends, exactly like hostsToCheck.
  const hashTokens = [];
  for (const url of webUrls) {
    if (hashTokens.length >= MAX_HASH_TOKENS) break;
    for (const token of url.match(HEX_TOKEN_RE) ?? []) {
      hashTokens.push({ token, host: hostOf(url) });
      if (hashTokens.length >= MAX_HASH_TOKENS) break;
    }
  }

  if (!items.length && !(addresses.length && hashTokens.length)) return null;

  return {
    id: 'body-tracking',
    title: 'What reading and clicking this reveals',
    tone: items.some((item) => item.level === 'bad' || item.emphasis) ? 'alert' : 'info',
    lede: 'Read out of the message in place — nothing below was loaded, and no link was followed. Images report the moment you read; identifiers in the links report that the click was yours.',
    items,
    // Resolved asynchronously against crypto.subtle once the renderer has the
    // card — the hostsToCheck pattern, carrying address-hash candidates.
    hashCheck: addresses.length && hashTokens.length
      ? { addresses, tokens: hashTokens }
      : null,
  };
}

/** Standard base64 of a string, padding trimmed — the substring every variant shares. */
function base64Trimmed(text) {
  try {
    return btoa(text).replace(/=+$/, '');
  } catch {
    return '';
  }
}

/** The party a URL's host belongs to, or null when it does not parse. */
function hostOf(url) {
  try {
    return party(new URL(url).hostname);
  } catch {
    return null;
  }
}

/**
 * Opaque identifiers the header carries — the sender's names for this copy.
 *
 * Sources are the fields whose values are per-message or per-recipient by
 * construction: Feedback-ID segments, the VERP local part's segments, the
 * `id` a Received hop logged, and the Message-ID's local part. Each token
 * must be long enough and digit-bearing enough that a word never qualifies —
 * the cost of a false join is a sentence accusing an innocent link.
 */
function headerIdentifiers(headers) {
  const tokens = new Map(); // token -> field it came from (first wins)
  const offer = (token, field) => {
    const value = String(token ?? '').trim();
    if (value.length < 10 || value.length > 64) return;
    if (!/\d/.test(value)) return;
    if (!/^[A-Za-z0-9._+-]+$/.test(value)) return;
    if (!tokens.has(value)) tokens.set(value, field);
  };

  for (const field of ['feedback-id', 'x-feedback-id']) {
    for (const value of getAll(headers, field)) {
      for (const segment of value.split(/[:\s]+/)) offer(segment, 'Feedback-ID');
    }
  }

  const returnPath = get(headers, 'return-path');
  const local = returnPath.match(/<?([^<>@\s]+)@/)?.[1] ?? '';
  for (const segment of local.split(/[=+]/)) offer(segment, 'Return-Path');

  for (const value of getAll(headers, 'received')) {
    offer(value.match(/\bid\s+([A-Za-z0-9._+-]{10,64})/i)?.[1], 'a Received hop');
  }

  offer(get(headers, 'message-id').match(/<?([^<>@\s]+)@/)?.[1], 'Message-ID');

  return [...tokens].map(([token, field]) => ({ token, field }));
}

// ---------------------------------------------------------------- attachments

// Extensions whose double-click runs code. A file wearing one arrived in
// mail, where no honest workflow sends executables.
const EXECUTABLE_EXT_RE = /\.(exe|scr|com|pif|bat|cmd|msi|jar|js|jse|vbs|vbe|wsf|wsh|hta|ps1|lnk|application)$/i;

// A document-looking extension with an executable one behind it — the oldest
// naming trick in mail, built for clients that hide the real extension.
const DOUBLE_EXTENSION_RE = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|html?|csv|mp3|mp4|zip)\.(exe|scr|com|pif|bat|cmd|msi|jar|js|jse|vbs|vbe|wsf|wsh|hta|ps1|lnk|application)$/i;

// Archives are how executables usually arrive wrapped; worth a line, not an
// accusation — plenty of honest mail ships a zip.
const ARCHIVE_EXT_RE = /\.(zip|rar|7z|iso|img|tar|gz|tgz|cab|ace|arj)$/i;

/**
 * The name the operating system acts on, which is not always the name written.
 *
 * The extension checks anchor on the end of the string, so they see whatever
 * the sender put last. Windows does not: the Win32 path layer strips trailing
 * dots and spaces from the final component, and an NTFS data-stream suffix
 * (`report.exe::$DATA`, `report.exe:x`) names a stream on `report.exe`. So
 * `invoice.pdf.exe `, `report.exe.` and `report.exe::$DATA` all open the
 * executable, while the raw name ends in `.exe `, `.exe.` or `.exe::$DATA` and
 * every `$`-anchored check read it as harmless — the card going silent on a
 * file the system runs, which is the one thing this card exists to prevent.
 *
 * Stripping only ever removes trailing junk or a stream suffix, so it can
 * expose a hidden extension but never invent one: a genuine `.txt` still ends
 * in `.txt` afterwards, so nothing safe is newly accused.
 */
function osResolvedName(name) {
  const base = String(name).split(':')[0]; // an ADS suffix is a stream on the base name
  return base.replace(/[.\s]+$/, ''); // trailing dots and spaces the OS drops
}

// The magic numbers this card can recognise in a part's first bytes. Small on
// purpose: only signatures unambiguous enough that a mismatch is a statement,
// not a guess.
const MAGIC = [
  ['a Windows program (MZ)', [0x4d, 0x5a]],
  ['a Linux program (ELF)', [0x7f, 0x45, 0x4c, 0x46]],
  ['a PDF', [0x25, 0x50, 0x44, 0x46]],
  ['a ZIP archive', [0x50, 0x4b, 0x03, 0x04]],
  ['a RAR archive', [0x52, 0x61, 0x72, 0x21]],
  ['a 7z archive', [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]],
  ['a gzip stream', [0x1f, 0x8b]],
  ['a PNG image', [0x89, 0x50, 0x4e, 0x47]],
  ['a JPEG image', [0xff, 0xd8, 0xff]],
  ['a GIF image', [0x47, 0x49, 0x46, 0x38]],
];

// What the declared type's first bytes should be, where that is knowable.
// ZIP answers for the whole OOXML family — a .docx *is* a zip.
const DECLARED_MAGIC = [
  [/^application\/pdf$/, 'a PDF'],
  [/^image\/png$/, 'a PNG image'],
  [/^image\/jpe?g$/, 'a JPEG image'],
  [/^image\/gif$/, 'a GIF image'],
  [/^application\/(zip|x-zip-compressed|vnd\.openxmlformats-officedocument\..+)$/, 'a ZIP archive'],
];

function magicOf(head) {
  const bytes = head ?? [];
  for (const [name, signature] of MAGIC) {
    if (signature.length <= bytes.length && signature.every((byte, i) => bytes[i] === byte)) {
      return name;
    }
  }
  return null;
}

/**
 * The attachment inventory: names, declared types, sizes, and the tells.
 *
 * Described, never opened: nothing is decoded beyond the first bytes every
 * part already carries, and those are read only to ask whether they agree
 * with the declared type. Deliberately not examined — and said so on the
 * card rather than hidden in code: calendar parts that add themselves, AMP
 * parts, inline cid: image mapping, and any archive's contents.
 */
function attachmentFinding(parts) {
  // Attachments by declaration, by name, or by being an opaque non-text part
  // — a PDF nobody labelled is still a PDF that arrived. Inline parts are the
  // message's own furniture (cid: images) and stay off the inventory.
  const attached = parts.filter((part) => part.disposition !== 'inline'
    && (part.disposition === 'attachment'
      || Boolean(part.filename)
      || (!part.contentType.startsWith('text/') && !part.contentType.startsWith('multipart/'))));
  if (!attached.length) return null;

  const items = [];
  for (const part of attached) {
    const name = part.filename ?? '(unnamed)';
    const size = Number.isSafeInteger(part.bytesDeclared)
      ? `${part.bytesDeclared.toLocaleString('en')} bytes`
      : 'size unstated';

    // Judge the name the OS would act on, not the bytes as written — otherwise a
    // trailing dot, space or `::$DATA` stream suffix hides the real extension.
    const runs = osResolvedName(name);
    const disguised = runs !== name && runs.length
      ? ' Its trailing characters — dots, spaces, or an NTFS stream suffix — are stripped by the operating system before it opens the file, so the extension shown here is the one that runs.'
      : '';

    const tells = [];
    if (DOUBLE_EXTENSION_RE.test(runs)) {
      tells.push({
        level: 'bad',
        note: `The name wears two extensions — a document's in the middle, an executable's at the end. Clients that hide known extensions show only the harmless half, which is the point of naming it this way.${disguised}`,
      });
    } else if (EXECUTABLE_EXT_RE.test(runs)) {
      tells.push({
        level: 'bad',
        note: `The extension is one the operating system runs rather than opens. No honest workflow sends executables by mail.${disguised}`,
      });
    } else if (ARCHIVE_EXT_RE.test(runs)) {
      tells.push({
        level: 'caution',
        note: `An archive. Its contents are not examined here — an archive is also how an executable usually arrives wrapped.${disguised}`,
      });
    }

    // The first bytes against the declared type — the one look inside this
    // card takes, and the only one. Every sentence here says "declared", so
    // every one of them reads the declaration: `contentType` is how the part
    // was read, and where content outranked the declaration the two differ. A
    // `.txt` attachment holding markup is read as text/html, and this card
    // reported "Declared as text/html" over a part that declared text/plain —
    // a false claim about the message, in the one card whose whole subject is
    // what a part says about itself versus what it is.
    const stated = part.declaredType ?? part.contentType;
    const actual = magicOf(part.head);
    const expected = DECLARED_MAGIC.find(([re]) => re.test(stated))?.[1];
    if (actual && /program/.test(actual) && !/octet-stream/.test(stated)) {
      tells.push({
        level: 'bad',
        note: `Declared as ${stated}, but its first bytes are those of ${actual}. Whatever the name and type say, this is code.`,
      });
    } else if (expected && actual && expected !== actual) {
      tells.push({
        level: 'caution',
        note: `Declared as ${stated}, but its first bytes are those of ${actual}, not ${expected}. The type a mail client shows is the declared one; the type that matters is what the bytes are.`,
      });
    }

    const worst = tells.find((tell) => tell.level === 'bad') ?? tells[0];
    items.push({
      label: name,
      value: `Declared as ${stated}, ${size}.${part.clipped ? ' Larger than what was read.' : ''}`,
      mono: true,
      level: worst?.level ?? null,
      emphasis: worst?.level === 'bad',
      note: tells.map((tell) => tell.note).join(' ') || null,
    });
  }

  return {
    id: 'attachments',
    title: 'What travels attached to this message',
    tone: items.some((item) => item.level === 'bad') ? 'alert' : 'info',
    lede: 'Named and described, never opened: nothing here was decoded beyond each part\'s first bytes, which were read only to check that they agree with the declared type. Not examined at all: archive contents, calendar parts that add themselves, AMP parts, and inline image wiring.',
    items,
  };
}

// ------------------------------------------------------- plain/html divergence

/**
 * Links the HTML carries that the plain-text version never mentions.
 *
 * A message's two renderings are supposed to say the same thing. Targets
 * compared where the reader would land — redirects unwrapped, by registrable
 * domain — so a tracked link and its plain-text twin count as the same
 * destination, and only genuinely absent ones diverge.
 */
function divergenceFinding(parts, scanOf) {
  // Paired by what the message offered each part as, not by how it ended up
  // being read. A text/plain part that mentions a `<table>` in prose is read
  // as markup — correctly, since that is how its hrefs would be found — and
  // pairing on the reading then left the message with no plain version at all,
  // so this card silently stopped comparing.
  const offeredAs = (part) => part.declaredType ?? part.contentType;
  const plainParts = parts.filter((part) => offeredAs(part) === 'text/plain' && part.text);
  const htmlParts = parts.filter((part) => offeredAs(part) === 'text/html' && part.text);
  if (!plainParts.length || !htmlParts.length) return null;

  const destination = (url) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return null;
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    const unwrapped = unwrapRedirect(parsed.href)?.destination;
    if (unwrapped) {
      try {
        return party(new URL(unwrapped).hostname);
      } catch {
        /* fall through to the visible host */
      }
    }
    return party(parsed.hostname);
  };

  // Every place a part can send a reader, however that part is read — so the
  // two sides are compared on the same terms.
  const reachableFrom = (part) => {
    if (part.contentType !== 'text/html') return extractUrls(part.text);
    const scan = scanOf(part);
    return [...scan.links.map((link) => String(link.href ?? '').trim()), ...autolinkedUrls(scan)];
  };

  const plainTargets = new Set();
  for (const part of plainParts) {
    for (const url of reachableFrom(part)) {
      const target = destination(url);
      if (target) plainTargets.add(target);
    }
  }

  const htmlOnly = new Set();
  for (const part of htmlParts) {
    for (const url of reachableFrom(part)) {
      const target = destination(url);
      if (target && !plainTargets.has(target)) htmlOnly.add(target);
    }
  }
  if (!htmlOnly.size) return null;

  const shown = [...htmlOnly].slice(0, 8);
  return {
    id: 'divergence',
    title: 'The two versions of this message do not say the same thing',
    tone: 'info',
    lede: 'A message usually carries its content twice — once as HTML, once as plain text — and a reader only ever sees one. Links that exist in the HTML alone are invisible to anyone reading the plain version, and to most preview and quoting tools.',
    items: [{
      label: `${htmlOnly.size} destination${htmlOnly.size === 1 ? '' : 's'} only the HTML links to`,
      value: `${shown.join(', ')}${htmlOnly.size > shown.length ? ` and ${htmlOnly.size - shown.length} more` : ''}`,
      mono: true,
      level: 'caution',
      note: 'What you see in a plain-text client is not what the HTML clicks. Redirects were unwrapped before comparing, so a tracked link and its plain twin count as one destination.',
    }],
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
