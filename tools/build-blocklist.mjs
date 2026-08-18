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
import { isPublicSuffix } from '../js/links.js';
import { createHash } from 'node:crypto';

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

// Names that must never enter the filter, whatever the feed says.
//
// Lookups walk up the labels, so a listed parent covers every host beneath it.
// One line reading `co.uk` therefore flags the whole registry, and one reading
// `google.com` flags all of Google. Reproduced with this builder: four such
// lines prepended to a 1,504-line feed cleared the entry floor and made
// bbc.co.uk, myproject.github.io, mail.google.com and www.paypal.com all come
// back FLAGGED.
//
// This is not primarily an anti-tampering measure. An upstream data error
// produces the identical result, and the daily rebuild would ship it inside
// twenty-four hours either way.
//
// Public suffixes are rejected by asking the Public Suffix List rather than by
// keeping a second hand-written list beside it. That leaves only the handful of
// names that are ordinary registrable domains and still must not be smeared.
export const NEVER_LIST = new Set([
  'google.com', 'googlemail.com', 'gmail.com', 'youtube.com',
  'microsoft.com', 'outlook.com', 'live.com', 'hotmail.com', 'office.com',
  'apple.com', 'icloud.com', 'me.com',
  'amazon.com', 'amazonaws.com', 'aws.amazon.com',
  'paypal.com', 'stripe.com',
  'facebook.com', 'instagram.com', 'whatsapp.com', 'linkedin.com', 'x.com', 'twitter.com',
  'cloudflare.com', 'akamai.com', 'fastly.net',
  'github.com', 'gitlab.com', 'wikipedia.org', 'mozilla.org',
  'sendgrid.net', 'mailchimp.com', 'list-manage.com', 'mailgun.org',
]);

// Bounds on how far one build may differ from the last. The floor alone waved
// through both directions of nonsense: a feed that had collapsed to 1,001
// entries, and one that had grown sevenfold into a 4 MB asset every visitor
// downloads whole.
const MIN_RATIO = 0.5;
const MAX_RATIO = 2.0;


/**
 * Would listing this name tar hosts that are not the one being reported?
 *
 * Exported so the rule can be tested without running a build. Public suffixes
 * are asked of the Public Suffix List rather than of a second hand-written
 * list; NEVER_LIST covers the ordinary registrable domains that must not be
 * smeared even though nothing about their structure protects them.
 */
export function wouldSmear(host) {
  return isPublicSuffix(host) || NEVER_LIST.has(host);
}

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
  const rejected = [];
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    // Tolerate hosts-file format (`0.0.0.0 evil.example`) as well as bare lines.
    const candidate = normaliseHost(trimmed.split(/\s+/).pop());
    if (candidate.length <= 3 || !HOSTNAME_RE.test(candidate)) continue;
    if (wouldSmear(candidate)) {
      rejected.push(candidate);
      continue;
    }
    hosts.add(candidate);
  }

  // Named, not silently dropped. A feed that starts listing registries is a
  // feed worth looking at, and a build that quietly cleaned up after it would
  // be hiding the one signal that something upstream had gone wrong.
  if (rejected.length) {
    process.stdout.write(`Refused ${rejected.length} entry/entries that would tar a whole registry or a major provider: ${rejected.slice(0, 20).join(', ')}${rejected.length > 20 ? ' …' : ''}\n`);
  }

  if (hosts.size < 1000) {
    throw new Error(`only ${hosts.size} usable hosts — refusing to publish a truncated list`);
  }

  // Compared against the last build rather than against a constant, because the
  // feed grows and a fixed ceiling would need moving. A collapse is as much a
  // fault as a flood: both mean the file is not what it was yesterday.
  const previous = await readFile(join(ROOT, 'data/blocklist.json'), 'utf8')
    .then((text) => JSON.parse(text).entries)
    .catch(() => null);
  if (Number.isFinite(previous) && previous > 0) {
    const ratio = hosts.size / previous;
    if (ratio < MIN_RATIO || ratio > MAX_RATIO) {
      throw new Error(
        `${hosts.size} hosts against ${previous} last time (${ratio.toFixed(2)}x) — refusing to publish a list that changed this much in one build`,
      );
    }
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
    // The feed is a mutable branch ref with no signature, so this cannot prove
    // the content is right. What it does is make two builds comparable: an
    // unexplained asset change can be traced to the input it came from.
    sourceSha256: createHash('sha256').update(body).digest('hex'),
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

// Only when run directly, so importing this module for its rules does not
// start a build.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    process.stderr.write(`build-blocklist failed: ${error.message}\n`);
    process.exit(1);
  });
}
