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

import { classifyRun } from '../tools/mutate.mjs';

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
