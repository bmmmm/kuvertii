#!/usr/bin/env node
// Fetch the phishing domain feed and bake it into a Bloom filter asset.
//
// Run by CI on a schedule; the output is committed so the published site never
// needs to reach a third party at runtime.
//
//   node tools/build-blocklist.mjs              download the feed
//   node tools/build-blocklist.mjs feed.txt     use an already-downloaded copy
//
// The file argument exists so the build can be reproduced, and inspected,
// without network access.

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { add, dimension, FALSE_POSITIVE_RATE, normaliseHost } from '../js/bloom.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const SOURCE = {
  name: 'Phishing.Database',
  url: 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
  homepage: 'https://github.com/mitchellkrogza/Phishing.Database',
  license: 'MIT',
};

// Underscores are illegal in a hostname per RFC 1123, but they occur in real
// DNS names and resolvers accept them — the feed carries ~500 such phishing
// hosts. Excluding them would silently drop entries the browser can reach.
// Everything else (URLs with a query, percent-encoded junk, bare IPs with
// parameters) is malformed input and stays out.
const HOSTNAME_RE = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$/;

async function main() {
  const localFile = process.argv[2];
  let body;

  if (localFile) {
    process.stdout.write(`Reading ${localFile}\n`);
    body = await readFile(localFile, 'utf8');
  } else {
    process.stdout.write(`Fetching ${SOURCE.url}\n`);
    const response = await fetch(SOURCE.url);
    if (!response.ok) throw new Error(`${SOURCE.name}: HTTP ${response.status}`);
    body = await response.text();
  }

  const hosts = new Set();
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    // Tolerate hosts-file format (`0.0.0.0 evil.example`) as well as bare lines.
    const candidate = normaliseHost(trimmed.split(/\s+/).pop());
    if (candidate.length > 3 && HOSTNAME_RE.test(candidate)) hosts.add(candidate);
  }

  if (hosts.size < 1000) {
    throw new Error(`only ${hosts.size} usable hosts — refusing to publish a truncated list`);
  }

  const { bits, hashes } = dimension(hosts.size);
  const bytes = new Uint8Array(Math.ceil(bits / 8));
  for (const host of hosts) add(bytes, host, bits, hashes);

  const meta = {
    bits,
    hashes,
    entries: hosts.size,
    falsePositiveRate: FALSE_POSITIVE_RATE,
    builtAt: new Date().toISOString().slice(0, 10),
    source: SOURCE,
  };

  await mkdir(join(ROOT, 'data'), { recursive: true });
  await writeFile(join(ROOT, 'data/blocklist.bin'), bytes);
  await writeFile(join(ROOT, 'data/blocklist.json'), `${JSON.stringify(meta, null, 2)}\n`);

  const kib = (bytes.length / 1024).toFixed(0);
  process.stdout.write(
    `${hosts.size} hosts → ${kib} KiB, ${hashes} hashes, p≈${FALSE_POSITIVE_RATE}\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`build-blocklist failed: ${error.message}\n`);
  process.exit(1);
});
