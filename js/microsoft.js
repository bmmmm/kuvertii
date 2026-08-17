// Microsoft 365's anti-spam verdict vocabulary.
//
// A lookup table rather than analysis, which is why it sits beside senders.js
// instead of inside findings.js: the header names and codes are Microsoft's,
// and the only work done here is translating them into sentences.

import { get } from './unfold.js';

// Field meanings follow Microsoft's published reference for anti-spam message
// headers: https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo
//
// Worth decoding because Outlook and Microsoft 365 carry an enormous share of
// mail, and because these are among the few headers that record a *decision*
// rather than a fact. The interesting verdicts are not only "this is spam" but
// also "filtering was skipped", which is what a mail flow rule looks like from
// the inside — and which is how a hostile message gets waved through.

const SPAM_VERDICTS = {
  SPM: ['The filter classified this message as spam.', 'bad'],
  HSPM: ['The filter classified this message as spam, with high confidence.', 'bad'],
  BLK: ['The sender was on a block list.', 'bad'],
  PHSH: ['The filter classified this message as phishing.', 'bad'],
  HPHSH: ['The filter classified this message as phishing, with high confidence.', 'bad'],
  HPHISH: ['The filter classified this message as phishing, with high confidence.', 'bad'],
  MALW: ['The message carried malware.', 'bad'],
  SPOOF: ['The sender address appeared to be forged.', 'bad'],
  DIMP: ['The message imitated a domain the recipient deals with.', 'bad'],
  UIMP: ['The message imitated a person the recipient deals with.', 'bad'],
  GIMP: ['Mailbox intelligence flagged the sender as unusual for this recipient.', 'caution'],
  BULK: ['Classified as bulk mail rather than spam.', null],
  NSPM: ['Not classified as spam.', null],
  SKA: ['Filtering was skipped because an allow list matched.', 'caution'],
  SKN: ['Filtering was skipped — a mail flow rule marked this safe before any check ran.', 'caution'],
  SKS: ['A mail flow rule marked this as spam before any check ran.', 'caution'],
  SKB: ['A block list matched.', 'bad'],
  SKQ: ['Someone released this message from quarantine.', 'caution'],
  SKI: ['Filtering was skipped.', 'caution'],
};

const IMPERSONATION_SAFETY = {
  '9.19': 'domain impersonation — the sending domain resembles one the organisation deals with',
  '9.20': 'user impersonation — the display name resembles someone the recipient knows',
  '9.11': 'bulk mail',
  '9.21': 'the message claimed to come from inside the organisation',
  '9.22': 'the message claimed to come from a domain that did not authorise it',
};

/** Split `KEY:VALUE;KEY:VALUE;` into a lookup, uppercasing the keys. */
function parseReport(value) {
  const fields = {};
  for (const pair of String(value ?? '').split(';')) {
    const [key, ...rest] = pair.split(':');
    if (!key?.trim()) continue;
    fields[key.trim().toUpperCase()] = rest.join(':').trim();
  }
  return fields;
}

/** Verdict items from the Microsoft 365 anti-spam headers, or [] when absent. */
export function microsoftVerdicts(headers) {
  const forefront = parseReport(get(headers, 'x-forefront-antispam-report'));
  const antispam = parseReport(get(headers, 'x-microsoft-antispam'));
  const items = [];

  const scl = forefront.SCL ?? get(headers, 'x-ms-exchange-organization-scl');
  if (scl !== undefined && scl !== '') {
    const n = Number(scl);
    const meaning =
      n === -1 ? 'Filtering was skipped entirely, so this score reflects a rule rather than an inspection.'
        : n <= 1 ? 'Inspected and not considered spam.'
          : n <= 4 ? 'Inspected, with no verdict either way.'
            : n <= 6 ? 'Considered spam.'
              : 'Considered spam with high confidence.';
    items.push({
      label: `Spam Confidence Level ${scl}`,
      value: meaning,
      note: 'Microsoft 365 scores from -1 to 9. Anything at 5 or above is treated as spam by default.',
      level: n === -1 ? 'caution' : n >= 5 ? 'bad' : n <= 1 ? 'good' : null,
    });
  }

  const bcl = antispam.BCL ?? forefront.BCL;
  if (bcl !== undefined && bcl !== '') {
    const n = Number(bcl);
    items.push({
      label: `Bulk Complaint Level ${bcl}`,
      value: n === 0
        ? 'Not sent in bulk.'
        : n <= 3 ? 'Bulk mail that few recipients complain about.'
          : n <= 7 ? 'Bulk mail with a mixed complaint history.'
            : 'Bulk mail that recipients complain about often.',
      note: 'Scored from the sender\'s complaint history across all of Microsoft\'s customers, not from this message.',
      level: n >= 8 ? 'caution' : null,
    });
  }

  for (const [field, label] of [['SFV', 'Filter verdict'], ['CAT', 'Category']]) {
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

  const safety = forefront.SFTY;
  if (safety && IMPERSONATION_SAFETY[safety]) {
    items.push({
      label: `Safety verdict ${safety}`,
      value: `Flagged as ${IMPERSONATION_SAFETY[safety]}.`,
      level: 'bad',
      emphasis: true,
    });
  }

  if (forefront.CTRY) {
    items.push({
      label: 'Connecting country',
      value: forefront.CTRY,
      note: 'Where the sending server was, by IP. Not where the sender is, and trivially changed by relaying.',
    });
  }

  return items;
}

