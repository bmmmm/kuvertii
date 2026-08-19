// The rule the blocklist builder applies to a feed it does not control.
//
// The feed is a third party's file on a mutable branch, fetched by CI and baked
// into the published site within the day. Lookups walk up the labels, so one
// line naming a registry covers every domain beneath it. Reproduced with the
// real builder before this guard existed: four lines — co.uk, github.io,
// google.com, paypal.com — prepended to a 1,504-line feed cleared the entry
// floor, and bbc.co.uk, myproject.github.io, mail.google.com and www.paypal.com
// all came back FLAGGED.
//
// Worth stating plainly: this is not mainly about tampering. An upstream data
// error produces the identical result, and the daily rebuild ships it either
// way.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { NEVER_LIST, wouldSmear } from '../tools/build-blocklist.mjs';

test('a public suffix never enters the filter', () => {
  // Asked of the Public Suffix List, so this holds for all 8,806 of them rather
  // than for whichever ones somebody remembered to write down.
  for (const suffix of ['co.uk', 'com.sg', 'github.io', 'blogspot.com', 'org.uk', 'com.au']) {
    assert.ok(wouldSmear(suffix), `${suffix} would tar every domain beneath it`);
  }
});

test('a major provider never enters the filter', () => {
  // These are ordinary registrable domains — nothing structural protects them,
  // so they are named.
  for (const domain of ['google.com', 'paypal.com', 'microsoft.com', 'sendgrid.net']) {
    assert.ok(wouldSmear(domain));
    assert.ok(NEVER_LIST.has(domain));
  }
});

test('an actual phishing domain is not caught by the guard', () => {
  // The guard must not become a hole. A four-label host under a real suffix is
  // exactly what the feed is for.
  for (const host of ['phish1.example', 'login-secure.evil.example', 'paypal.evil.example', 'account.co.uk.evil.example']) {
    assert.ok(!wouldSmear(host), `${host} must still be listable`);
  }
});

test('the guard does not exempt a subdomain of a protected name', () => {
  // `paypal.com` is protected; `phish.paypal.com.evil.example` is not paypal.
  assert.ok(!wouldSmear('phish.paypal.com.evil.example'));
  // And a genuine subdomain of a major provider is still not the provider —
  // listing it tars only itself, which is the intended granularity.
  assert.ok(!wouldSmear('compromised.pages.dev'));
});

// The same question asked of the other builder: what may enter the generated
// module? Here the stakes are higher than a bad list entry. Every accepted
// line is interpolated into a template literal inside js/psl.js — a committed,
// browser-executed source file — so a line carrying a backtick or ${ would not
// be data, it would be code shipped to every visitor.

test('every shipped suffix rule is one the builder would accept', async () => {
  // Couples the shape check to reality: measured before the pattern existed,
  // a version without \p{M} refused six real rules (Thai and Balinese carry
  // combining marks). If either the pattern or the list drifts, this goes red
  // on the shipped bytes rather than on somebody's assumption.
  const { ruleName } = await import('../tools/build-psl.mjs');
  const { EXACT, WILDCARD, EXCEPTION } = await import('../js/psl.js');
  for (const set of [EXACT, WILDCARD, EXCEPTION]) {
    for (const rule of set) assert.equal(ruleName(rule), rule);
  }
});

test('a line that is not a rule stops the build instead of becoming code', async () => {
  const { ruleName } = await import('../tools/build-psl.mjs');
  for (const evil of [
    '${process.env.HOME}.evil',
    'back`tick.example',
    'back\\slash.example',
    'sp ace.example',
    '\u0007bel.example',
    'evil.example\n});import("x',
    '-leading-hyphen.example',
    'trailing-.example',
    '',
  ]) {
    assert.throws(() => ruleName(evil), /not a public-suffix rule/, JSON.stringify(evil));
  }
});

test('rule prefixes name the part the lookup asks about', async () => {
  const { ruleName } = await import('../tools/build-psl.mjs');
  assert.equal(ruleName('!www.ck'), 'www.ck');
  assert.equal(ruleName('*.ck'), 'ck');
  assert.equal(ruleName('co.uk'), 'co.uk');
  assert.equal(ruleName('com'), 'com');
});
