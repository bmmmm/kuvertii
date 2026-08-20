// The reader's address as a hash — ad-tech's favourite spelling of identity.
//
// MD5 or SHA-256 of a lowercased email address is the currency of identity
// resolution (Gravatar, LiveRamp, UID2): "hashed for privacy" in the privacy
// policy, a stable cross-site identifier in practice, because the same
// address always yields the same value. A body link carrying one is carrying
// the reader, in a form no substring search for the address will ever find.
//
// This module is the bridge that closes that gap, shaped like the blocklist
// bridge: the analysis stays synchronous and collects candidate tokens; the
// front ends call this afterwards and append what it returns. Async because
// the browser only has crypto.subtle, and one implementation for both front
// ends because a check that exists on one and not the other is two different
// answers to the same message. Node ships the same global, so nothing here
// imports `node:` anything.
//
// crypto.subtle cannot compute MD5 — deliberately, everywhere. Rather than
// hand-roll the digest, the gap is stated on the card: an MD5-shaped token
// is reported as unchecked, never silently skipped. See mdGapRow.

// What crypto.subtle can compute, with the hex length each produces.
const ALGORITHMS = [
  ['SHA-1', 40],
  ['SHA-256', 64],
];

// The hex length of an MD5 — checkable nowhere offline in the browser.
export const MD5_HEX_LENGTH = 32;

/** Lowercase hex of one digest over UTF-8 text. */
async function hexDigest(algorithm, text) {
  const digest = await globalThis.crypto.subtle.digest(algorithm, new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Rows for every candidate token that is a hash of a known address.
 *
 * `addresses` are the recipient-side addresses (already lowercased by
 * findAddresses); `tokens` are [{ token, host }] — hex runs of a digest
 * length pulled out of body URLs, with the registrable domain of the link
 * they rode in. Hashing convention across the industry is lowercase-trimmed
 * address, lowercase hex; both sides are normalised to that before comparing.
 *
 * Returns finding items, worst first: confirmed matches, then the MD5 gap
 * when MD5-shaped tokens were present and could not be checked.
 */
export async function hashedAddressRows({ addresses = [], tokens = [] } = {}) {
  if (!addresses.length || !tokens.length) return [];

  const byLength = new Map();
  for (const { token, host } of tokens) {
    const normalised = token.toLowerCase();
    if (!byLength.has(normalised.length)) byLength.set(normalised.length, []);
    byLength.get(normalised.length).push({ token: normalised, host });
  }

  const rows = [];
  const seen = new Set();
  for (const address of addresses) {
    const canonical = address.trim().toLowerCase();
    for (const [algorithm, length] of ALGORITHMS) {
      const candidates = byLength.get(length);
      if (!candidates?.length) continue;
      const digest = await hexDigest(algorithm, canonical);
      for (const { token, host } of candidates) {
        if (token !== digest) continue;
        const key = `${canonical} ${algorithm} ${host}`;
        if (seen.has(key)) continue;
        seen.add(key);
        rows.push({
          label: 'Your address travels as a fingerprint',
          value: `A link to ${host} carries the ${algorithm} hash of ${canonical}.`,
          level: 'bad',
          emphasis: true,
          note: 'Hashing is not anonymising: the same address always yields the same value, which is exactly what makes it useful for recognising you across sites. Clicking hands the identifier over; so does complaining to the wrong party about it.',
        });
      }
    }
  }

  // Named, not skipped: a 32-hex token has the shape of an MD5 — the oldest
  // and most common spelling of this trick — and the one digest this tool
  // cannot compute offline in the browser. Saying nothing would read as
  // "checked and clean".
  if (byLength.has(MD5_HEX_LENGTH)) {
    const hosts = [...new Set(byLength.get(MD5_HEX_LENGTH).map(({ host }) => host))];
    rows.push({
      label: 'An MD5-shaped id could not be checked',
      value: `Links to ${hosts.slice(0, 4).join(', ')} carry 32-character hex ids — the shape of an MD5, the hash most often used for email addresses. This tool cannot compute MD5 offline here, so whether they encode your address went unchecked.`,
      level: 'absent',
    });
  }

  return rows;
}
