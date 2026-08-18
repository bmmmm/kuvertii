// What the blocklist snapshot can honestly be asked, and what it may answer.
//
// This is everything about the phishing snapshot except how the bytes arrive.
// The page fetches them, the command reads them from disk, and until this file
// existed each carried its own copy of the rest — the same lookup written
// twice, the same sentences written twice, and one of the two already drifted:
// the page ended its false-alarm note with "Verify at {homepage} before
// concluding." and the command did not. Nobody decided that. It is simply what
// happens to two copies of one claim.
//
// The other half of the split was worse than untidy. js/blocklist.js refused a
// filter whose metadata did not match its bytes, on the stated grounds that
// answering from a broken filter is worse than not answering — and the command
// mirrored the lookup without the refusal, so a truncated .bin beside intact
// metadata made it report "not in the blocklist snapshot" for every host it was
// shown. A miss it had no basis for, phrased exactly like one it did.

import { has, normaliseHost } from './bloom.js';

/** Proof that a snapshot came through `validate`. Not exported: that is why it works. */
const CHECKED = Symbol('validated snapshot');

/**
 * Refuse a filter that cannot answer correctly.
 *
 * A Bloom filter has no way to notice that its own parameters are wrong, and
 * both failure modes here are silent and severe. `bits: 0` makes every position
 * `x % 0`, which is NaN, so every probe reads bit 0 of byte 0 — and depending
 * on that single bit, either every domain in the world comes back listed or
 * none of them ever can. `hashes: 0` empties the loop and does the same. A
 * `.bin` truncated beside a fresh `.json` fails the other way: every lookup
 * misses, and the answer is "not in the snapshot" for a domain that is in it.
 *
 * Throwing is the right response to all of them, because both callers turn a
 * throw into "no check was made" — which is true, and is the only honest thing
 * to say.
 */
export function validate(meta, bytes) {
  const fail = (why) => { throw new Error(`blocklist is unusable: ${why}`); };

  if (!Number.isInteger(meta?.bits) || meta.bits <= 0) fail(`bits is ${meta?.bits}`);
  if (!Number.isInteger(meta?.hashes) || meta.hashes < 1 || meta.hashes > 32) fail(`hashes is ${meta?.hashes}`);
  if (!Number.isFinite(meta?.entries) || meta.entries <= 0) fail(`entries is ${meta?.entries}`);
  if (!(meta?.falsePositiveRate > 0)) fail(`falsePositiveRate is ${meta?.falsePositiveRate}`);
  if (typeof meta?.source?.name !== 'string') fail('source.name is missing');
  // The two files are written together and must stay in step; a mismatch means
  // one of them is stale or was cut short in transit.
  if (bytes.length !== Math.ceil(meta.bits / 8)) {
    fail(`the filter is ${bytes.length} bytes and its metadata describes ${Math.ceil(meta.bits / 8)}`);
  }

  // Branded, and the brand is the point. A caller cannot assemble this object
  // by hand, so `lookup` below can insist on having been given one — which
  // turns "remember to validate first" from a rule someone has to keep into a
  // thing the code cannot do without. The command-line build skipped exactly
  // that step for months, and reported a miss it had no basis for.
  return Object.freeze({ meta, bytes, [CHECKED]: true });
}

/**
 * Look one hostname up, and report how hard it had to look.
 *
 * The walk goes up the labels: a listed parent domain covers its subdomains,
 * while a listed subdomain — common on shared hosting — does not implicate the
 * parent. `probes` is the number of Bloom queries that actually happened, and
 * it is returned rather than recomputed because every honest statement about
 * the false-alarm rate depends on it.
 */
export function lookup(snapshot, hostname) {
  if (!snapshot?.[CHECKED]) {
    throw new TypeError('lookup needs a snapshot from validate(); an unchecked filter cannot answer honestly');
  }
  const { bytes, meta } = snapshot;
  const host = normaliseHost(hostname);
  if (!host) return { host, listed: false, probes: 0 };

  const labels = host.split('.');
  let probes = 0;
  for (let i = 0; i + 1 < labels.length; i++) {
    const candidate = labels.slice(i).join('.');
    probes += 1;
    if (has(bytes, candidate, meta.bits, meta.hashes)) {
      return { host, listed: true, matched: candidate, probes, meta };
    }
  }
  return { host, listed: false, probes, meta };
}

/**
 * How often a clean host produces a hit anyway, for a lookup of this shape.
 *
 * The figure in the metadata is the rate of a single Bloom probe. A lookup is
 * not a single probe — it is one per label boundary — so the reader was being
 * told 1 in 200 for something that, on the four-label hostnames ESP click
 * trackers actually use, happens about 1 in 65. Measured against the shipped
 * filter with 200,000 clean hosts per depth: 1 in 193, 1 in 96, 1 in 65, 1 in
 * 49 for two, three, four and five labels.
 *
 * Under-reporting a false-alarm rate is the direction that costs someone
 * something: it is what turns "this might be nothing" into "this is a phishing
 * domain" in the reader's head.
 */
export function falseAlarmOdds(meta, probes) {
  const perProbe = meta.falsePositiveRate;
  const chance = 1 - ((1 - perProbe) ** Math.max(probes, 1));
  return Math.round(1 / chance);
}

/**
 * The verdict as finding items — one wording, both renderers.
 *
 * Asymmetric on purpose, and the asymmetry is the point of the whole feature: a
 * hit is a strong warning, a miss is not an all-clear, and an unavailable
 * snapshot is neither.
 */
export function verdictRows(results) {
  return results.map((result) => {
    if (result.unavailable) {
      return {
        label: `Blocklist check unavailable (${result.host})`,
        value: result.why ?? 'No check was made.',
        level: 'caution',
      };
    }

    if (result.listed) {
      const odds = falseAlarmOdds(result.meta, result.probes);
      return {
        label: `${result.matched} is on a phishing blocklist`,
        value: `Snapshot of ${result.meta.source.name}, ${result.meta.entries.toLocaleString('en')} domains, built ${result.meta.builtAt}. Treat this link as hostile.`,
        note: `Matching is probabilistic — this lookup made ${result.probes} probe${result.probes === 1 ? '' : 's'}, so roughly 1 in ${odds} such lookups of a clean host raises this warning anyway. Verify at ${result.meta.source.homepage} before concluding.`,
        level: 'bad',
        emphasis: true,
      };
    }

    return {
      label: `${result.host} is not in the blocklist snapshot`,
      value: 'This is not a clean bill of health. The snapshot is a point-in-time copy, and phishing domains are typically hours old — the dangerous ones are precisely those no list has caught yet.',
      note: result.meta
        ? `${result.meta.source.name}, built ${result.meta.builtAt}, ${result.meta.entries.toLocaleString('en')} domains.`
        : null,
    };
  });
}
