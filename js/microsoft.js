// Microsoft 365's anti-spam verdict vocabulary.
//
// A lookup table rather than analysis, which is why it sits beside senders.js
// instead of inside findings.js: the header names and codes are Microsoft's,
// and the only work done here is translating them into sentences.

import { clip } from './decode.js';
import { emptyTable, table } from './lookup.js';
import { get } from './unfold.js';

// Field meanings follow Microsoft's published reference for anti-spam message
// headers: https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo
//
// Worth decoding because Outlook and Microsoft 365 carry an enormous share of
// mail, and because these are among the few headers that record a *decision*
// rather than a fact. The interesting verdicts are not only "this is spam" but
// also "filtering was skipped", which is what a mail flow rule looks like from
// the inside — and which is how a hostile message gets waved through.

// The threat category (CAT) and filter verdict (SFV) vocabularies. Two
// namespaces in one lookup: the codes do not collide, and every one of them
// answers the same question — what did the filter decide.
//
// The entries that matter most are the ones saying filtering did not happen.
// SFE, SKA, SKI, SKN and IPV:CAL each mean a message reached the inbox because
// something waved it through before any check ran. That is what a mail flow
// rule, an over-broad allow list, or a user's own safe-senders entry looks like
// from the inside, and it is the case this module exists to surface.
const SPAM_VERDICTS = table({
  // Threat categories (CAT).
  AMP: ['Anti-malware caught something in this message.', 'bad'],
  BIMP: ['The message impersonated a brand.', 'bad'],
  BULK: ['Classified as bulk mail rather than spam.', null],
  DIMP: ['The message imitated a domain the recipient deals with.', 'bad'],
  FTBP: ['The message carried an attachment of a type the organisation blocks outright.', 'bad'],
  GIMP: ['Mailbox intelligence flagged the sender as unusual for this recipient.', 'caution'],
  HPHISH: ['The filter classified this message as phishing, with high confidence.', 'bad'],
  HPHSH: ['The filter classified this message as phishing, with high confidence.', 'bad'],
  HSPM: ['The filter classified this message as spam, with high confidence.', 'bad'],
  INTOS: ['Phishing that claimed to come from inside the recipient’s own organisation.', 'bad'],
  MALW: ['The message carried malware.', 'bad'],
  OSPM: ['Outbound spam — recorded as sent from this organisation rather than to it.', 'bad'],
  PHSH: ['The filter classified this message as phishing.', 'bad'],
  SAP: ['Safe Attachments opened something in this message and did not like what it did.', 'bad'],
  SPM: ['The filter classified this message as spam.', 'bad'],
  SPOOF: ['The sender address appeared to be forged.', 'bad'],
  UIMP: ['The message imitated a person the recipient deals with.', 'bad'],

  // Filter verdicts (SFV).
  BLK: ['Filtering was skipped and the message blocked: the sender is on the recipient’s own blocked list.', 'caution'],
  NSPM: ['Inspected by the spam filter and not classified as spam.', null],
  SFE: ['Filtering was skipped because the sender is on the recipient’s own Safe Senders list. No check ran on this message.', 'caution'],
  SKA: ['Filtering was skipped because an allow-list entry in the anti-spam policy matched, so this reached the inbox unchecked.', 'caution'],
  SKB: ['Marked as spam by a block-list entry in the anti-spam policy.', 'caution'],
  SKI: ['Filtering was skipped because the connecting IP is on the allow list in the connection filter policy.', 'caution'],
  SKN: ['Filtering was bypassed by a mail flow rule — someone configured mail of this kind to skip inspection.', 'caution'],
  SKQ: ['Someone released this message from quarantine.', 'caution'],
  SKS: ['Marked as spam before filtering ran, by a mail flow rule or by an on-premises verdict.', 'caution'],
});

// Three values exist today. 9.11, 9.21 and 9.22 were carried here from an older
// revision of Microsoft's table and are absent from the current one; 9.11 in
// particular rendered ordinary bulk mail as an emphasised red phishing verdict.
//
// 9.25 is not an accusation. Microsoft's own wording is that it "might be an
// indication of a suspicious or phishing message" — it fires on the first
// message from any new correspondent, which is most of them.
const IMPERSONATION_SAFETY = table({
  '9.19': ['domain impersonation — the sending domain resembles one the organisation protects', 'bad'],
  '9.20': ['user impersonation — the sender resembles someone in the recipient’s organisation', 'bad'],
  '9.25': ['first contact — nobody here has corresponded with this sender before', 'caution'],
});

// Recorded when a decision was made somewhere other than the filter.
const IP_VERDICT = table({
  CAL: ['Filtering was skipped because the connecting IP address is on an allow list.', 'caution'],
});

// Direction. `INB` on a message you received is the ordinary case and says
// nothing worth a row. `INT` means Microsoft treated the message as internal to
// the organisation, which on something that arrived from outside is the shape
// of a successful self-to-self spoof rather than a fact about the sender.
const DIRECTION = table({
  OUT: ['Recorded as leaving the organisation rather than arriving.', 'caution'],
  INT: ['Treated as internal mail. On a message that reached you from outside, that is what a successful self-to-self spoof looks like.', 'caution'],
});

/** Split `KEY:VALUE;KEY:VALUE;` into a lookup, uppercasing the keys. */
function parseReport(value) {
  const fields = emptyTable();
  for (const pair of String(value ?? '').split(';')) {
    const [key, ...rest] = pair.split(':');
    if (!key?.trim()) continue;
    fields[key.trim().toUpperCase()] = rest.join(':').trim();
  }
  return fields;
}

/**
 * Did Microsoft's filter actually classify this message as unwanted?
 *
 * The category, not the score. `SCL` used to answer this and no longer can:
 * Microsoft's reference states that in cloud organisations the value "doesn't
 * determine whether the message is identified as spam or the action taken on
 * it" and directs readers to `CAT` and `DIR` instead. A message can carry
 * `CAT:BIMP` — brand impersonation — beside `SCL:1`.
 */
export function filedAsUnwanted(headers) {
  const forefront = parseReport(get(headers, 'x-forefront-antispam-report'));
  const category = forefront.CAT?.toUpperCase();
  return Boolean(category && SPAM_VERDICTS[category]?.[1] === 'bad');
}

/**
 * One of Microsoft's numeric scores, or null when the field does not hold one.
 *
 * Both scores were read with `Number()` and then walked down a chain of `<=`
 * comparisons. Every comparison against NaN is false, so a field holding
 * anything that is not a number fell through the whole chain into its last
 * branch — and the last branch is the most severe reading each score has.
 * `SCL:abc` printed "Scored as spam with high confidence", and `BCL:xyz`
 * printed "Bulk mail that recipients complain about often", the latter without
 * even the caution mark that a genuine high score carries. A verdict about the
 * message, asserted from a field that made no such claim.
 *
 * The range is checked as well as the type, for the same reason: Microsoft
 * defines SCL as -1 to 9 and BCL as 0 to 9, and `SCL:-5` read as "Scored as
 * not spam" because it satisfied `n <= 1`. A value outside the vocabulary is
 * not the nearest value inside it.
 *
 * The pattern is `signatureTime` in js/findings.js: return null, and let the
 * caller say the field is not a score rather than invent a reading for it.
 */
function score(raw, { min, max }) {
  const text = String(raw ?? '').trim();
  if (!/^-?\d+$/.test(text)) return null;
  const value = Number(text);
  return value >= min && value <= max ? value : null;
}

/** The row for a score field whose contents are not one of its defined values. */
function unreadableScore(name, raw, range) {
  return {
    label: `${name} ${clip(raw, 40)}`,
    value: `Not one of the values this score is defined to take (${range}), so nothing about the message can be read from it.`,
    note: 'Microsoft writes this field. A value outside its own vocabulary means either that the field was not written by the filter, or that it was altered after it was.',
    level: 'caution',
  };
}

/** Verdict items from the Microsoft 365 anti-spam headers, or [] when absent. */
export function microsoftVerdicts(headers) {
  // The field objects, not just the first value: where a report sits and how
  // many there are carry as much meaning as what it says. Reading `get()`
  // alone meant a message that never crossed Microsoft, carrying a fabricated
  // CAT:NONE;SCL:1, rendered "Scored as not spam" with Microsoft's authority —
  // and when a real report sat below a smuggled one, the real verdict
  // (CAT:PHSH;SCL:9 in the probe) was not merely unreported but unreachable.
  const reports = headers.filter((h) => h.name.toLowerCase() === 'x-forefront-antispam-report');
  const forefront = parseReport(reports[0]?.value ?? '');
  const antispam = parseReport(get(headers, 'x-microsoft-antispam'));
  const items = [];

  const scl = forefront.SCL ?? get(headers, 'x-ms-exchange-organization-scl');
  if (scl !== undefined && String(scl).trim() !== '') {
    const n = score(scl, { min: -1, max: 9 });
    if (n === null) {
      items.push(unreadableScore('Spam Confidence Level', scl, '-1 to 9'));
    } else {
    const meaning =
      n === -1 ? 'Filtering was skipped entirely, so this score reflects a rule rather than an inspection.'
        : n <= 1 ? 'Scored as not spam.'
          : n <= 4 ? 'Scored with no verdict either way.'
            : n <= 6 ? 'Scored as spam.'
              : 'Scored as spam with high confidence.';
    items.push({
      label: `Spam Confidence Level ${scl}`,
      value: meaning,
      // Deliberately colourless except for -1. On a cloud mailbox this number no
      // longer decides anything, and a green `SCL:1` sitting beside `CAT:BIMP`
      // is the tool contradicting itself in the sender's favour.
      note: 'Microsoft states that on cloud mailboxes this score does not determine whether a message is treated as spam — the category below does. It survives for on-premises Exchange.',
      level: n === -1 ? 'caution' : null,
    });
    }
  }

  const bcl = antispam.BCL ?? forefront.BCL;
  if (bcl !== undefined && String(bcl).trim() !== '') {
    const n = score(bcl, { min: 0, max: 9 });
    items.push(n === null ? unreadableScore('Bulk Complaint Level', bcl, '0 to 9') : {
      label: `Bulk Complaint Level ${n}`,
      value: n === 0
        ? 'Not sent in bulk.'
        : n <= 3 ? 'Bulk mail that few recipients complain about.'
          : n <= 7 ? 'Bulk mail with a mixed complaint history.'
            : 'Bulk mail that recipients complain about often.',
      note: 'Scored from the sender\'s complaint history across all of Microsoft\'s customers, not from this message.',
      level: n >= 8 ? 'caution' : null,
    });
  }

  for (const [field, label] of [['CAT', 'Category'], ['SFV', 'Filter verdict'], ['SRV', 'Filter verdict']]) {
    const code = forefront[field];
    const known = SPAM_VERDICTS[code?.toUpperCase()];
    if (!known) continue;
    items.push({
      label: `${label}: ${code}`,
      value: known[0],
      level: known[1],
      emphasis: known[1] === 'bad',
    });
  }

  for (const [field, table_, label] of [['IPV', IP_VERDICT, 'IP reputation'], ['DIR', DIRECTION, 'Direction']]) {
    const code = forefront[field];
    const known = table_[code?.toUpperCase()];
    if (!known) continue;
    items.push({
      label: `${label}: ${code}`,
      value: known[0],
      level: known[1],
    });
  }

  const safety = IMPERSONATION_SAFETY[forefront.SFTY];
  if (safety) {
    items.push({
      label: `Safety verdict ${forefront.SFTY}`,
      value: `Flagged as ${safety[0]}.`,
      level: safety[1],
      emphasis: safety[1] === 'bad',
    });
  }

  if (forefront.CTRY) {
    items.push({
      label: 'Connecting country',
      value: forefront.CTRY,
      note: 'Where the sending server was, by IP. Not where the sender is, and trivially changed by relaying.',
    });
  }

  // Where the report sat, said once, under the rows that rest on it — the same
  // treatment Authentication-Results already gets, because the two fields are
  // written by the same filter and forged by the same hand. In the real M365
  // fixture the report sits above the first Received; one sitting below a
  // Received was added before the delivering hop, which is ordinary on mail
  // forwarded out of a Microsoft mailbox and is also the only place a
  // fabricated report can sit.
  const firstHop = headers.findIndex((h) => h.name.toLowerCase() === 'received');
  if (reports.length && firstHop !== -1 && headers.indexOf(reports[0]) > firstHop) {
    items.push({
      label: 'This filter report was not written by the last hop',
      value: 'The X-Forefront-Antispam-Report sits below a Received, so it was added earlier in the chain than the server that delivered this message. That is ordinary on mail forwarded out of a Microsoft mailbox — and it is also where a fabricated report would sit, because the sender writes everything below their own hop.',
      note: 'Read these rows as worth whatever the hop that wrote them is worth.',
      level: 'caution',
    });
  }

  if (reports.length > 1) {
    items.push({
      label: `X-Forefront-Antispam-Report appears ${reports.length} times`,
      value: 'Only the first was read. A receiver prepends its report above what is already there, so the first is the newest — the rows above describe that copy alone, and anything the copies below say differently is not shown here.',
      level: 'caution',
    });
  }

  return items;
}
