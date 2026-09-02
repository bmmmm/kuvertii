// A fixed slice of tools/fuzz-corpus.mjs, so the generated corpus is a gate and
// not something somebody has to remember to run.
//
// The tool's own job is the long hunt — thousands of messages, a seed on the
// command line. This is the part that has to hold on every commit: a handful of
// seeds whose messages are the same on every machine and every run, pushed
// through the same chain the file picker runs (bytes → textFromMessageBytes →
// pipeline → the terminal renderer AND the page).
//
// A failure here names a seed and an index, never a message. Reproduce it with
//   node tools/fuzz-corpus.mjs --seed <seed> --count <count> --only <index>

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { auditOne, corpus, selfTest } from '../tools/fuzz-corpus.mjs';

const SEEDS = [1, 42, 1337];
const PER_SEED = 12;

test('the invariants can still fail, so a clean run means something', () => {
  // First, always. A probe that cannot say no passes every corpus it is pointed
  // at, and the clean bill below would mean only that it is blind — which is
  // exactly how a suite goes green while the thing it guards is broken.
  assert.deepEqual(selfTest(), []);
});

test('generated messages break no invariant on either screen', async () => {
  const broken = [];
  let fellBack = 0;
  let screens = 0;
  let messages = 0;

  for (const seed of SEEDS) {
    for (const { index, bytes } of corpus(seed, PER_SEED)) {
      const report = await auditOne(bytes);
      messages += 1;
      screens += report.screens;
      if (report.fellBack) fellBack += 1;
      // The seed and the index, not the message: a failure has to be
      // reproducible without this file ever carrying the bytes that caused it.
      for (const b of report.breaks) broken.push(`seed ${seed} #${index}: ${b}`);
    }
  }

  assert.deepEqual(broken, []);
  assert.equal(screens, messages * 3, 'every message reached both terminal renderers and the page');

  // Without this the suite could go green over a corpus that never left the
  // strict UTF-8 path — which is the one path the file seam did not need a
  // probe for.
  assert.ok(fellBack > 0, `no message reached the fallback decoder (${fellBack}/${messages})`);
});
