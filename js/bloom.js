// Bloom filter shared by the build script and the browser.
//
// A blocklist of ~400k hostnames is 8 MB as text. As a Bloom filter it is
// ~540 KB, which is small enough to ship as a static asset — and shipping it
// is the point: a lookup service would have to be told which domain you are
// asking about, and that is the one thing this tool refuses to reveal.
//
// The trade-off is false positives (a clean domain reported as listed). There
// are no false negatives: a hit means "possibly listed", a miss means
// "definitely not in this snapshot".

export const FALSE_POSITIVE_RATE = 0.005;

/** Bit count and hash count for n entries at the target error rate. */
export function dimension(n, p = FALSE_POSITIVE_RATE) {
  const bits = Math.ceil((-n * Math.log(p)) / Math.LN2 ** 2);
  const hashes = Math.max(1, Math.round((bits / n) * Math.LN2));
  return { bits, hashes };
}

// Two independent 32-bit hashes, combined per Kirsch–Mitzenmacher. Chosen over
// a 64-bit hash because BigInt in a hot loop is markedly slower in browsers.
function fnv1a(text) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function djb2(text) {
  let hash = 5381;
  for (let i = 0; i < text.length; i++) {
    hash = (Math.imul(hash, 33) ^ text.charCodeAt(i)) >>> 0;
  }
  return hash >>> 0;
}

/** Bit positions this key occupies. */
export function positions(key, bits, hashes) {
  const h1 = fnv1a(key);
  const h2 = djb2(key) | 1; // odd, so the stride never degenerates
  const out = new Array(hashes);
  for (let i = 0; i < hashes; i++) {
    out[i] = ((h1 + Math.imul(i, h2)) >>> 0) % bits;
  }
  return out;
}

export function add(bytes, key, bits, hashes) {
  for (const position of positions(key, bits, hashes)) {
    bytes[position >>> 3] |= 1 << (position & 7);
  }
}

export function has(bytes, key, bits, hashes) {
  for (const position of positions(key, bits, hashes)) {
    if ((bytes[position >>> 3] & (1 << (position & 7))) === 0) return false;
  }
  return true;
}

/**
 * Normalise a hostname for lookup.
 *
 * The blocklist stores bare hostnames, lowercase, no trailing dot, no port.
 * Both sides must agree exactly or every lookup silently misses.
 *
 * IPv6 literals are the case the two obvious regexes get wrong. Stripping
 * ":digits" off the end of `[2001:db8::1]` eats the last hextet, and stripping
 * a leading `[` and a trailing `]` independently leaves the closing bracket
 * standing whenever a port follows it. What came out — `2001:db8:`, `::1]` —
 * was then reported on as if it were the host the reader asked about. The
 * brackets are a unit: URL syntax adds them precisely so a port can follow an
 * address that is itself full of colons.
 */
export function normaliseHost(host) {
  const text = String(host ?? '').toLowerCase().trim();

  // A bracketed literal: the address is exactly what is between the brackets,
  // and nothing after them but an optional port is well-formed.
  const bracketed = text.match(/^\[([^\][]*)\](?::\d+)?$/);
  if (bracketed) return bracketed[1];

  // A bare IPv6 literal has more than one colon and no port; only a single
  // colon followed by digits at the end is a port worth removing.
  const stripped = /^[^:]+:\d+$/.test(text) ? text.replace(/:\d+$/, '') : text;

  return stripped
    .replace(/\.$/, '')
    .replace(/^www\./, '');
}
