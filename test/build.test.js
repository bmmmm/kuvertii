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
