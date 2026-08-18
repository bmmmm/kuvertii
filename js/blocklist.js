// Lazy access to the baked-in phishing blocklist.
//
// The filter is a static asset served from this origin. It is fetched only when
// a link is actually inspected, and the hostname being checked never leaves the
// browser — the whole filter comes to it, not the other way round.

import { has, normaliseHost } from './bloom.js';

let loading = null;

/**
 * Refuse a filter that cannot answer correctly.
 *
 * A Bloom filter has no way to notice that its own parameters are wrong, and
 * both failure modes here are silent and severe. `bits: 0` makes every position
 * `x % 0`, which is NaN, so every probe reads bit 0 of byte 0 and **every
 * domain in the world comes back listed** — the tool would accuse each host it
 * was shown. `hashes: 0` empties the loop and does the same. A `.bin` truncated
 * beside a fresh `.json` fails the other way: every lookup misses, and the page
 * reports "not in the snapshot" for a domain that is in it.
 *
 * Throwing is the right response to both, because `checkHost` turns a throw
 * into `{unavailable: true}` and the renderers already say "no check was made"
 * — which is true, and is the only honest thing to say. Answering from a broken
 * filter is worse than not answering.
 */
function validate(meta, bytes) {
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

  return { meta, bytes };
}

async function load() {
  if (!loading) {
    loading = (async () => {
      const [meta, buffer] = await Promise.all([
        fetch('data/blocklist.json').then((r) => {
          if (!r.ok) throw new Error(`blocklist.json: HTTP ${r.status}`);
          return r.json();
        }),
        fetch('data/blocklist.bin').then((r) => {
          if (!r.ok) throw new Error(`blocklist.bin: HTTP ${r.status}`);
          return r.arrayBuffer();
        }),
      ]);
      return validate(meta, new Uint8Array(buffer));
    })().catch((error) => {
      loading = null; // let a later attempt retry rather than cache the failure
      throw error;
    });
  }
  return loading;
}

/**
 * Check a hostname against the snapshot.
 *
 * Resolves to {listed, meta} — or {unavailable: true} when the asset could not
 * be loaded, which the UI must render as "unknown", never as "clean".
 */
export async function checkHost(hostname) {
  const host = normaliseHost(hostname);
  if (!host) return { listed: false, host };

  let data;
  try {
    data = await load();
  } catch (error) {
    return { unavailable: true, host, error: error.message };
  }

  const { meta, bytes } = data;
  // Walk up the labels: a listed parent domain covers its subdomains, while a
  // listed subdomain (common on shared hosts) does not implicate the parent.
  const labels = host.split('.');
  for (let i = 0; i + 1 < labels.length; i++) {
    const candidate = labels.slice(i).join('.');
    if (has(bytes, candidate, meta.bits, meta.hashes)) {
      return { listed: true, host, matched: candidate, meta };
    }
  }
  return { listed: false, host, meta };
}
