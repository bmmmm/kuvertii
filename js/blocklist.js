// Lazy access to the baked-in phishing blocklist.
//
// The filter is a static asset served from this origin. It is fetched only when
// a link is actually inspected, and the hostname being checked never leaves the
// browser — the whole filter comes to it, not the other way round.
//
// Everything this file knows about answering a question lives in js/snapshot.js
// and is shared with the command-line build. What is left here is the one thing
// the two do differently: where the bytes come from.

import { lookup, validate } from './snapshot.js';

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
 * Resolves to the shape js/snapshot.js defines — or {unavailable: true} when
 * the asset could not be loaded or could not be trusted, which the UI must
 * render as "unknown", never as "clean".
 */
export async function checkHost(hostname) {
  let data;
  try {
    data = await load();
  } catch (error) {
    return {
      unavailable: true,
      host: hostname,
      why: `The snapshot could not be loaded, so no check was made: ${error.message}`,
    };
  }

  return lookup(data, hostname);
}
