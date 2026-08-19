import assert from 'node:assert/strict';
import { test } from 'node:test';

import { add, dimension, FALSE_POSITIVE_RATE, has, normaliseHost } from '../js/bloom.js';

function build(keys, p = FALSE_POSITIVE_RATE) {
  const { bits, hashes } = dimension(keys.length, p);
  const bytes = new Uint8Array(Math.ceil(bits / 8));
  for (const key of keys) add(bytes, key, bits, hashes);
  return { bytes, bits, hashes };
}

test('a Bloom filter never produces a false negative', () => {
  const keys = Array.from({ length: 5000 }, (_, i) => `host-${i}.example`);
  const { bytes, bits, hashes } = build(keys);
  for (const key of keys) {
    assert.ok(has(bytes, key, bits, hashes), `${key} must be found`);
  }
});

test('the false positive rate stays near the target', () => {
  const keys = Array.from({ length: 20000 }, (_, i) => `listed-${i}.example`);
  const { bytes, bits, hashes } = build(keys);

  let hits = 0;
  const probes = 20000;
  for (let i = 0; i < probes; i++) {
    if (has(bytes, `clean-${i}.test`, bits, hashes)) hits++;
  }
  const rate = hits / probes;
  // Generous bound: this asserts the maths is wired up, not that the hash is
  // perfect. A broken combiner shows up as a rate orders of magnitude off.
  assert.ok(rate < FALSE_POSITIVE_RATE * 4, `false positive rate ${rate} too high`);
});

test('dimension scales with entry count', () => {
  const small = dimension(1000);
  const large = dimension(100000);
  assert.ok(large.bits > small.bits * 50);
  assert.ok(small.hashes >= 1 && small.hashes <= 16);
});

test('hostnames are normalised identically on both sides', () => {
  assert.equal(normaliseHost('WWW.Example.COM.'), 'example.com');
  assert.equal(normaliseHost('example.com:8443'), 'example.com');
  assert.equal(normaliseHost('  Sub.Example.Org  '), 'sub.example.org');
  assert.equal(normaliseHost(null), '');
});

test('an address literal survives normalisation intact', () => {
  // The port strip read ":digits at the end" and the bracket strip removed the
  // two brackets independently, so `[2001:db8::1]` lost its last hextet and
  // `[::1]:8080` kept a bracket — and the mangled string was then reported on
  // as if it were the host the reader asked about. The whole IPv6 family, not
  // just the reported case: with and without port, with and without brackets,
  // loopback, IPv4-mapped.
  assert.equal(normaliseHost('[2001:db8::1]'), '2001:db8::1');
  assert.equal(normaliseHost('[2001:db8::1]:443'), '2001:db8::1');
  assert.equal(normaliseHost('[::1]:8080'), '::1');
  assert.equal(normaliseHost('::1'), '::1');
  assert.equal(normaliseHost('2001:db8::1'), '2001:db8::1');
  assert.equal(normaliseHost('[::ffff:203.0.113.5]'), '::ffff:203.0.113.5');
  // The still-must-work side: a real port on a name or an IPv4 literal.
  assert.equal(normaliseHost('192.0.2.7:8443'), '192.0.2.7');
  assert.equal(normaliseHost('evil.example:8080'), 'evil.example');
});

test('a host absent from an empty filter is reported absent', () => {
  const { bytes, bits, hashes } = build(['only.example']);
  assert.ok(!has(bytes, 'something-else.example', bits, hashes));
});

// A Bloom filter cannot notice that its own parameters are wrong, and both ways
// of getting them wrong are silent. These are the two that matter.

test('bits of zero would accuse every domain on earth', () => {
  // `position % 0` is NaN, so every probe reads bit 0 of byte 0.
  const bytes = new Uint8Array(64);
  bytes[0] = 0xff;
  for (const host of ['totally-innocent.example', 'google.com', 'a.b.c']) {
    assert.equal(has(bytes, host, 0, 3), true, 'this is why validate() exists');
  }
});

test('no hashes at all does the same', () => {
  const bytes = new Uint8Array(64);
  assert.equal(has(bytes, 'anything.example', 1000, 0), true);
});
