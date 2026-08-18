// The blocklist snapshot: what it answers, and what it says about its answer.
//
// One rule drives this file. A number this tool prints about its own accuracy
// has to survive being measured, because the reader has no other way to check
// it — and of the two directions the error can run, under-reporting a
// false-alarm rate is the expensive one. It is what turns "this might be
// nothing" into "this is a phishing domain" in somebody's head.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { add, dimension } from '../js/bloom.js';
import { falseAlarmOdds, lookup, validate, verdictRows } from '../js/snapshot.js';

/**
 * A filter holding `entries` synthetic domains, shaped like the shipped one.
 *
 * Built through `validate`, because that is the only way to get something
 * `lookup` will accept — which is the property the branding exists for, and
 * this helper is the first place it is felt.
 */
function buildFilter(entries, falsePositiveRate = 0.005) {
  const { bits, hashes } = dimension(entries, falsePositiveRate);
  const bytes = new Uint8Array(Math.ceil(bits / 8));
  for (let i = 0; i < entries; i++) add(bytes, `listed-${i}.example`, bits, hashes);

  return validate({
    bits,
    hashes,
    entries,
    falsePositiveRate,
    builtAt: '2026-08-18',
    source: { name: 'Test feed', homepage: 'https://example.invalid' },
  }, bytes);
}

/** Deterministic pseudo-random labels — no Math.random, so failures reproduce. */
function labeller(seed = 1) {
  let state = seed;
  const next = () => (state = (state * 1103515245 + 12345) % 2147483648) / 2147483648;
  return (n) => Array.from({ length: n }, () => 'abcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(next() * 36)]).join('');
}

test('a lookup reports how many probes it made', () => {
  const snap = buildFilter(1000);

  // The walk goes up the labels and stops at the registrable pair, so a
  // four-label host is three questions, not one.
  assert.equal(lookup(snap, 'a.example').probes, 1);
  assert.equal(lookup(snap, 'b.a.example').probes, 2);
  assert.equal(lookup(snap, 'c.b.a.example').probes, 3);
  assert.equal(lookup(snap, 'd.c.b.a.example').probes, 4);
});

test('an unvalidated filter cannot be looked up in at all', () => {
  // The command-line build mirrored the page's lookup without the page's
  // refusal for months, and answered "not in the snapshot" out of a truncated
  // filter. Making that a rule someone has to remember is what produced the
  // bug; making it a shape the code cannot express is the fix.
  const snap = buildFilter(1000);

  assert.throws(() => lookup({ bytes: snap.bytes, meta: snap.meta }, 'a.example'), /needs a snapshot from validate/);
  assert.throws(() => lookup({}, 'a.example'), /needs a snapshot from validate/);
  assert.doesNotThrow(() => lookup(snap, 'a.example'));
});

test('the printed false-alarm rate matches what a measurement finds', () => {
  // The claim under test is the sentence a reader sees beside a FLAGGED
  // verdict. It used to be derived from the per-probe rate in the metadata,
  // which is the rate of one Bloom query — but a lookup is one query per label
  // boundary, so on the four-label hostnames ESP click trackers use, the
  // printed figure understated the real rate by a factor of three.
  const snap = buildFilter(20_000);
  const label = labeller(42);
  const SAMPLES = 20_000;

  for (const depth of [2, 3, 4]) {
    let hits = 0;
    for (let i = 0; i < SAMPLES; i++) {
      const host = [...Array.from({ length: depth - 1 }, () => label(7)), `x${i}`, 'invalid'].slice(-depth).join('.');
      if (lookup(snap, host).listed) hits += 1;
    }

    const measured = hits / SAMPLES;
    const claimed = 1 / falseAlarmOdds(snap.meta, depth - 1);

    // Generous but not vacuous: a factor of two either way. The defect this
    // guards against was a factor of three, and a tighter bound would flap on
    // the sampling noise of 20,000 draws.
    assert.ok(
      measured < claimed * 2 && measured > claimed / 2,
      `${depth}-label hosts: measured 1 in ${Math.round(1 / measured)}, printed 1 in ${falseAlarmOdds(snap.meta, depth - 1)}`,
    );
  }
});

test('the odds get worse with every extra probe, never better', () => {
  const meta = { falsePositiveRate: 0.005 };
  const odds = [1, 2, 3, 4, 5].map((probes) => falseAlarmOdds(meta, probes));
  for (let i = 1; i < odds.length; i++) {
    assert.ok(odds[i] < odds[i - 1], `1 in ${odds[i]} should be worse than 1 in ${odds[i - 1]}`);
  }
  assert.equal(odds[0], 200, 'a single probe is still the metadata figure');
});

test('a hit says how many probes stood behind it', () => {
  const snap = buildFilter(1000);
  const [row] = verdictRows([{
    host: 'x.y.example', listed: true, matched: 'y.example', probes: 2, meta: snap.meta,
  }]);

  assert.match(row.note, /2 probes/);
  assert.match(row.note, /1 in 100/, 'two probes, not the one-probe figure');
  assert.equal(row.level, 'bad');
});

test('an unusable filter is refused rather than answered from', () => {
  const snap = buildFilter(1000);
  const { meta, bytes } = snap;

  assert.throws(() => validate({ ...meta, bits: 0 }, bytes), /bits is 0/);
  assert.throws(() => validate({ ...meta, hashes: 0 }, bytes), /hashes is 0/);
  assert.throws(() => validate(meta, bytes.slice(0, 100)), /the filter is 100 bytes/);
  assert.doesNotThrow(() => validate(meta, bytes));
});

test('an unavailable snapshot is never rendered as a clean result', () => {
  const [row] = verdictRows([{ host: 'x.example', unavailable: true, why: 'no snapshot on disk' }]);

  assert.match(row.label, /unavailable/);
  assert.equal(row.level, 'caution');
  assert.doesNotMatch(`${row.label} ${row.value}`, /\bclean\b|\bsafe\b/i);
});

test('a miss says plainly that it is not an all-clear', () => {
  const snap = buildFilter(1000);
  const [row] = verdictRows([lookup(snap, 'nothing.here.invalid')]);

  assert.match(row.value, /not a clean bill of health/);
  assert.equal(row.level, undefined, 'a miss is not a verdict');
});
