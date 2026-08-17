// Lazy access to the baked-in phishing blocklist.
//
// The filter is a static asset served from this origin. It is fetched only when
// a link is actually inspected, and the hostname being checked never leaves the
// browser — the whole filter comes to it, not the other way round.

import { has, normaliseHost } from './bloom.js';

let loading = null;

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
      return { meta, bytes: new Uint8Array(buffer) };
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
