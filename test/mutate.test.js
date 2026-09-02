// The mutation harness has to be trusted before anything it says can be. Its
// one subtle decision is how it scores a run: a suite that answered is KILLED
// or SURVIVED, but a suite that never reached a verdict — a timeout, a child
// that failed to spawn under the load of a long sweep — is neither. Folding
// that third case into SURVIVED is what let a live mutation be reported as an
// unguarded promise on a byte-identical tree (zero-length-reads-as-partial,
// 2026-08-20: SURVIVED in one full run, KILLED in the next). A gate that scores
// an unasked question as "unguarded" cannot be trusted to go red for the right
// reason, so classifyRun keeps the three outcomes apart, and this holds it to it.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { readFileSync } from 'node:fs';

import { classifyRun } from '../tools/mutate.mjs';
import { MUTATIONS } from '../tools/mutations.js';

test('a run that reached a verdict is killed or survived by its status', () => {
  // The suite ran to completion (a plan line, or at least one failure): a
  // red suite caught the mutation, a green one did not.
  assert.equal(classifyRun({ status: 1, ranToCompletion: true }), 'killed');
  assert.equal(classifyRun({ status: 0, ranToCompletion: true }), 'survived');
});

test('a run that never reached a verdict is inconclusive, never a survivor', () => {
  // The direction that matters. Before the fix `status !== 0 && ranToCompletion`
  // read every one of these — a non-zero exit with no plan and no failure — as
  // `false`, i.e. as SURVIVED, i.e. as an unguarded promise. None of them is:
  // the suite was cut off before it could answer, so the honest verdict is that
  // there is no verdict.
  assert.equal(classifyRun({ status: 1, ranToCompletion: false }), 'inconclusive');
  assert.equal(classifyRun({ status: 124, ranToCompletion: false }), 'inconclusive');
  assert.equal(classifyRun({ status: 'sig:SIGTERM', ranToCompletion: false }), 'inconclusive');
  // A clean exit with no plan is still inconclusive — a spawn that produced no
  // output at all cannot have run the tests, whatever code it returned.
  assert.equal(classifyRun({ status: 0, ranToCompletion: false }), 'inconclusive');
});

test('every mutation still anchors on exactly one place in its file', () => {
  // A registry entry finds its line by text, so any edit near that line can
  // orphan it — and until now nothing said so. `mutate.mjs` throws when it
  // reaches a dead anchor, which means the news arrives twenty minutes into a
  // sweep, on the one CI job that runs it, and only for the mutations before
  // it in the list. Two anchors were orphaned in a single session that way,
  // both by edits two lines from the anchor, and both looked fine because the
  // mutation had been run by id before the edit rather than after it.
  //
  // Exactly one, not at least one: mutate.mjs replaces every occurrence, so a
  // find that matches twice is a mutation whose meaning nobody chose.
  const cache = new Map();
  const source = (file) => {
    if (!cache.has(file)) cache.set(file, readFileSync(new URL(`../${file}`, import.meta.url), 'utf8'));
    return cache.get(file);
  };

  // The one entry a mutation run has deliberately rewritten is not orphaned,
  // it is applied. Checking it anyway made this test go red under every single
  // mutation — which sounds like noise and is not: a mutation that no test
  // catches would then have been reported KILLED by this one, and the sweep
  // would have answered "nothing is unguarded" without being able to say
  // otherwise. mutate.mjs names it in the environment.
  const applied = process.env.KUVERTII_APPLIED_MUTATION || null;

  const wrong = MUTATIONS
    .filter((m) => m.id !== applied)
    .map((m) => ({ id: m.id, file: m.file, hits: source(m.file).split(m.find).length - 1 }))
    .filter(({ hits }) => hits !== 1)
    .map(({ id, file, hits }) => `${id} matches ${hits}x in ${file}`);

  assert.deepEqual(wrong, []);
});
