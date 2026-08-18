#!/usr/bin/env node
// What this project promises, and what would catch it breaking one.
//
//   node tools/promises.mjs
//
// Read out of tools/mutations.js rather than written down beside it. A second
// list of the same claims is a second thing to fall out of date, and the one
// that falls out of date is always the prose — so the prose is generated.
//
// The rule this prints is the one that matters: a promise with no mutation is a
// promise nothing is holding. Everything here has one, because `npm run mutate`
// fails when anything does not.

import { MUTATIONS } from './mutations.js';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const YELLOW = '\x1b[33m';
const OFF = '\x1b[0m';
const colour = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code, text) => (colour ? `${code}${text}${OFF}` : text);

const platformNote = (entry) => (Array.isArray(entry.expectedToSurvive)
  ? `not breakable on ${entry.expectedToSurvive.join(', ')}`
  : entry.expectedToSurvive === true
    ? 'UNGUARDED — a measured gap, not yet closed'
    : null);

const byFile = new Map();
for (const mutation of MUTATIONS) {
  if (!byFile.has(mutation.file)) byFile.set(mutation.file, []);
  byFile.get(mutation.file).push(mutation);
}

process.stdout.write(`${paint(BOLD, `${MUTATIONS.length} promises, each with a way to break it`)}\n`);
process.stdout.write(`${paint(DIM, 'Run `npm run mutate` to check every one of them is still held.')}\n`);

for (const [file, entries] of [...byFile].sort()) {
  process.stdout.write(`\n${paint(BOLD, file)}\n`);
  for (const entry of entries.sort((a, b) => a.id.localeCompare(b.id))) {
    const note = platformNote(entry);
    process.stdout.write(`  ${entry.promise}\n`);
    process.stdout.write(`    ${paint(DIM, `break it: ${entry.id}`)}`);
    process.stdout.write(note ? `  ${paint(YELLOW, note)}\n` : '\n');
    for (const test of entry.mustKill) {
      process.stdout.write(`    ${paint(DIM, `caught by: ${test}`)}\n`);
    }
  }
}

const gaps = MUTATIONS.filter((m) => m.expectedToSurvive === true);
process.stdout.write(`\n${paint(BOLD, 'Unguarded')}: ${gaps.length
  ? gaps.map((m) => m.id).join(', ')
  : 'none — every promise above has a mutation that kills it'}\n`);
