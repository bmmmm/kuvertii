import assert from 'node:assert/strict';
import { test } from 'node:test';

import { decodeCandidates, findAddresses, readability } from '../js/decode.js';
import { get, getAll, parseHeaders } from '../js/unfold.js';
import {
  BULK_HEADER, CAMPAIGN_SEGMENT, MAILER_SEGMENT, RECIPIENT, UNSUB_TOKEN,
} from './fixtures.js';

test('folded continuation lines are joined into one value', () => {
  const headers = parseHeaders(BULK_HEADER);
  const extra = get(headers, 'X-Mailer-Info-Extra');
  assert.ok(extra.includes(MAILER_SEGMENT), 'first line kept');
  assert.ok(extra.includes(CAMPAIGN_SEGMENT), 'continuation line joined in');
  assert.equal(getAll(headers, 'X-Mailer-Info-Extra').length, 1);
});

test('a uniformly indented paste still parses as separate fields', () => {
  const indented = BULK_HEADER.split('\n').map((l) => (l ? `    ${l}` : l)).join('\n');
  const headers = parseHeaders(indented);
  assert.equal(get(headers, 'Subject'), 'Herzlich willkommen!');
  assert.ok(get(headers, 'To').includes(RECIPIENT));
});

test('repeated fields are all preserved, in order', () => {
  const headers = parseHeaders(BULK_HEADER);
  assert.equal(getAll(headers, 'Received').length, 3);
  assert.equal(getAll(headers, 'Authentication-Results').length, 3);
});

test('a line that lost its field name is kept rather than dropped', () => {
  const headers = parseHeaders(BULK_HEADER);
  const orphan = headers.find((h) => h.synthetic);
  assert.ok(orphan, 'orphan line captured');
  assert.match(orphan.value, /^<mid-/);
});

test('the body after the blank line is not parsed as headers', () => {
  const headers = parseHeaders('To: a@example.org\n\nSubject: not a header, this is the body\n');
  assert.equal(headers.length, 1);
  assert.equal(headers[0].name, 'To');
});

test('reversed base64 with reversed content decodes back to the address', () => {
  const [best] = decodeCandidates(MAILER_SEGMENT);
  assert.ok(best, 'produced a candidate');
  assert.equal(best.text, RECIPIENT);
  assert.match(best.method, /reversed/);
});

test('the unsubscribe token yields the recipient and the campaign', () => {
  const [best] = decodeCandidates(UNSUB_TOKEN);
  assert.ok(best.text.includes(RECIPIENT));
  assert.ok(best.text.includes('newsletter00news20260817'));
});

test('high-entropy blobs are not reported as decoded text', () => {
  // Shaped like the opaque tracking blobs real headers carry.
  const noise = Buffer.from(
    Uint8Array.from({ length: 96 }, (_, i) => (i * 37 + 11) % 256),
  ).toString('base64');
  const meaningful = decodeCandidates(noise).filter((c) => c.score >= 0.5);
  assert.equal(meaningful.length, 0, 'binary noise stays unreported');
});

test('readability separates prose from bytes', () => {
  assert.ok(readability('contact@example.org') > 0.8);
  assert.ok(readability('newsletter campaign') > 0.5);
  assert.equal(readability(''), 0);
});

test('addresses are extracted and normalised', () => {
  assert.deepEqual(findAddresses('To: Maja <MAJA@Example.ORG>, b@x.test'), [
    'maja@example.org',
    'b@x.test',
  ]);
});

test('base64 input of impossible length is rejected, not thrown on', () => {
  assert.doesNotThrow(() => decodeCandidates('QUJDRE'.slice(0, 5)));
});
