// The address-hash bridge: the reader's address, spelled as a digest.
//
// The reference digests are hard-coded, computed once with a different tool —
// a test that derives its expectation with the same function it checks would
// pass whatever that function does.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { hashedAddressRows, MD5_HEX_LENGTH } from '../js/emailhash.js';

const ADDRESS = 'maja.beispiel@example.org';
const SHA256 = 'e7a86a5c9708e8e51efd427765773b6a9b4e195b8d715832eef94b65873a37ab';
const SHA1 = 'ef6c4bf3f39f403f4d4da004df5e088327988db5';
const MD5 = 'bf84e1ddbbfc5b54d73022b477f0a668';

test('a SHA-256 of the address in a link is named as a fingerprint', async () => {
  const rows = await hashedAddressRows({
    addresses: [ADDRESS],
    tokens: [{ token: SHA256, host: 'tracker.example' }],
  });
  const row = rows.find((r) => r.level === 'bad');
  assert.ok(row, 'a bad row exists');
  assert.match(row.value, /SHA-256/);
  assert.match(row.value, /tracker\.example/);
  assert.match(row.value, /maja\.beispiel@example\.org/);
});

test('a SHA-1 is recognised too', async () => {
  const rows = await hashedAddressRows({
    addresses: [ADDRESS],
    tokens: [{ token: SHA1, host: 't.example' }],
  });
  assert.ok(rows.some((r) => r.level === 'bad' && /SHA-1/.test(r.value)));
});

test('an uppercase hex token still matches — hex has no case', async () => {
  const rows = await hashedAddressRows({
    addresses: [ADDRESS],
    tokens: [{ token: SHA256.toUpperCase(), host: 't.example' }],
  });
  assert.ok(rows.some((r) => r.level === 'bad'));
});

test('a mixed-case address is hashed in its canonical lowercase form', async () => {
  // The industry convention, and the reason the comparison works at all.
  const rows = await hashedAddressRows({
    addresses: ['Maja.Beispiel@Example.org'],
    tokens: [{ token: SHA256, host: 't.example' }],
  });
  assert.ok(rows.some((r) => r.level === 'bad'));
});

test('a digest of something else is not the reader', async () => {
  const rows = await hashedAddressRows({
    addresses: [ADDRESS],
    tokens: [{ token: 'a'.repeat(64), host: 't.example' }],
  });
  assert.equal(rows.some((r) => r.level === 'bad'), false);
});

test('an MD5-shaped token is reported as unchecked, never silently skipped', async () => {
  assert.equal(MD5.length, MD5_HEX_LENGTH, 'sanity: the fixture is MD5-shaped');
  const rows = await hashedAddressRows({
    addresses: [ADDRESS],
    tokens: [{ token: MD5, host: 't.example' }],
  });
  const gap = rows.find((r) => r.level === 'absent');
  assert.ok(gap, 'the gap is stated');
  assert.match(gap.value, /MD5/);
  assert.match(gap.value, /went unchecked/);
  assert.equal(rows.some((r) => r.level === 'bad'), false, 'and nothing is claimed found');
});

test('no MD5-shaped tokens, no gap row', async () => {
  const rows = await hashedAddressRows({
    addresses: [ADDRESS],
    tokens: [{ token: 'b'.repeat(64), host: 't.example' }],
  });
  assert.equal(rows.some((r) => r.level === 'absent'), false);
});

test('the same match is reported once, not per repeated token', async () => {
  const rows = await hashedAddressRows({
    addresses: [ADDRESS],
    tokens: [
      { token: SHA256, host: 't.example' },
      { token: SHA256, host: 't.example' },
    ],
  });
  assert.equal(rows.filter((r) => r.level === 'bad').length, 1);
});

test('empty inputs answer with no rows and no work', async () => {
  assert.deepEqual(await hashedAddressRows({}), []);
  assert.deepEqual(await hashedAddressRows({ addresses: [ADDRESS], tokens: [] }), []);
  assert.deepEqual(await hashedAddressRows({ addresses: [], tokens: [{ token: SHA256, host: 'x' }] }), []);
});
