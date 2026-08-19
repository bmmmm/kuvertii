#!/usr/bin/env node
// Bake the Public Suffix List into a source module.
//
//   node tools/build-psl.mjs                    download the list
//   node tools/build-psl.mjs public_suffix_list.dat   use a local copy
//
// The output, js/psl.js, is committed. That is deliberate and differs from
// data/blocklist.bin, which is built in CI and gitignored, for two reasons.
//
// First, `registrableDomain()` is called synchronously from deep inside
// `analyse()`. Fetching the list at runtime would make it async and ripple
// through every caller in both front ends, to save a file that changes a few
// times a week.
//
// Second, absence has different consequences. A missing blocklist means one
// check is reported as unavailable, which the tool says plainly. A missing
// suffix list would mean every domain comparison silently reverts to guessing,
// and the guess is wrong in the direction that renders a phishing link green.
// Nothing that load-bearing should depend on a build step having run.
//
// Both published sections are used, and only their rules of two labels or more.
// Single-label rules — `com`, `de` — are omitted because the algorithm's
// default rule for an unmatched name is `*`, which produces exactly the same
// answer, at a third of the size.

import { writeFile } from 'node:fs/promises';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const SOURCE = {
  name: 'Public Suffix List',
  url: 'https://publicsuffix.org/list/public_suffix_list.dat',
  homepage: 'https://publicsuffix.org/',
  licence: 'MPL-2.0',
  sections: ['ICANN', 'PRIVATE'],
};

// Both published sections are used. ICANN alone answers "which registry sold
// this name", which is the DMARC organisational-domain question — but the
// question this tool asks is "are these two names the same party", and for
// anything hosted on a platform the answer lives in the PRIVATE section.
// Without it `alice.github.io` and `evil.github.io` both reduce to `github.io`,
// which is the same defect as `bank.com.sg` and `evil.com.sg` sharing `com.sg`.
const SECTIONS = [
  ['===BEGIN ICANN DOMAINS===', '===END ICANN DOMAINS==='],
  ['===BEGIN PRIVATE DOMAINS===', '===END PRIVATE DOMAINS==='],
];

// What one rule may look like: dot-separated labels of letters, digits and
// combining marks, with hyphens inside a label. Combining marks are not
// decoration — six real rules (Thai and Balinese) carry them, and a pattern
// without \p{M} refused all six when measured against the shipped list.
//
// The blocklist builder has always had a shape check (HOSTNAME_RE); this
// builder had none, and here the stakes are higher: every accepted line is
// interpolated into a template literal inside a committed, browser-executed
// source module. A line carrying a backtick or ${ would not be a bad entry in
// a data file — it would be code in js/psl.js.
const LABEL = '[\\p{L}\\p{M}\\p{N}](?:[\\p{L}\\p{M}\\p{N}-]*[\\p{L}\\p{M}\\p{N}])?';
export const RULE_RE = new RegExp(`^${LABEL}(?:\\.${LABEL})*$`, 'u');

/**
 * The bare name a rule speaks for, refusing anything that is not a rule.
 *
 * Refusal throws rather than skips, deliberately differing from the blocklist
 * builder: a dropped feed line loses one warning, while a dropped suffix rule
 * silently moves a party boundary — the error that renders a phishing link
 * green. If the list legitimately grows a new character class some day, the
 * build fails loudly and widening this pattern is a commit somebody writes a
 * reason for.
 */
export function ruleName(rule) {
  const name = rule.startsWith('!') ? rule.slice(1)
    : rule.startsWith('*.') ? rule.slice(2)
      : rule;
  if (!RULE_RE.test(name)) {
    throw new Error(`"${rule}" is not a public-suffix rule — the list format has changed, or the content is not what it claims to be`);
  }
  return name;
}

/** Every section's rules, comments and blank lines removed. */
function publishedRules(body) {
  const lines = body.split('\n');
  return SECTIONS.flatMap(([openMarker, closeMarker]) => {
    const begin = lines.findIndex((line) => line.includes(openMarker));
    const end = lines.findIndex((line) => line.includes(closeMarker));
    if (begin === -1 || end === -1 || end <= begin) {
      throw new Error(`could not find ${openMarker} — the list format has changed`);
    }
    return lines
      .slice(begin + 1, end)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('//'));
  });
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

  const rules = publishedRules(body);
  if (rules.length < 9000) {
    throw new Error(`only ${rules.length} rules — refusing to publish a truncated list`);
  }

  const exact = [];
  const wildcards = [];
  const exceptions = [];

  for (const rule of rules) {
    const name = ruleName(rule);
    if (rule.startsWith('!')) {
      exceptions.push(name);
    } else if (rule.startsWith('*.')) {
      // Stored as the parent the wildcard hangs off, because that is what the
      // lookup has in hand: testing `bar.ck` means asking about `ck`.
      wildcards.push(name);
    } else if (name.includes('.')) {
      exact.push(name);
    }
    // Single-label rules fall through — see the note at the top.
  }

  if (!wildcards.length || !exceptions.length) {
    throw new Error('no wildcard or exception rules found — the list format has changed');
  }

  const set = (name, values) =>
    `export const ${name} = new Set(\`${[...values].sort().join('\n')}\`.split('\\n'));`;

  const module = `// Generated by tools/build-psl.mjs. Do not edit.
//
// ${SOURCE.name} (${SOURCE.sections.join(' + ')} sections), ${SOURCE.licence}, from ${SOURCE.url}
// ${exact.length} suffixes, ${wildcards.length} wildcard rules, ${exceptions.length} exceptions.
//
// Rules of a single label are deliberately absent: the algorithm's default rule
// for an unmatched name is \`*\`, which gives the same answer for every one of
// them. Kept as newline-joined strings rather than array literals because it
// parses faster and is a third of the bytes.

export const SOURCE = ${JSON.stringify(SOURCE, null, 2)};

${set('EXACT', exact)}

${set('WILDCARD', wildcards)}

${set('EXCEPTION', exceptions)}
`;

  const path = join(ROOT, 'js/psl.js');
  await writeFile(path, module);

  const kib = (Buffer.byteLength(module) / 1024).toFixed(0);
  process.stdout.write(
    `${exact.length} suffixes + ${wildcards.length} wildcards + ${exceptions.length} exceptions → js/psl.js, ${kib} KiB\n`,
  );
}

// Only when run directly — the same guard build-blocklist.mjs carries, and it
// was missing here: importing this module for RULE_RE in a test would have
// started a build, network fetch included.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    process.stderr.write(`build-psl failed: ${error.message}\n`);
    process.exit(1);
  });
}
