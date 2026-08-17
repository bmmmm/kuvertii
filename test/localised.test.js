// Regression tests for the shapes real mail clients actually produce.
// Every case here was found by running a genuine header through the tool, not
// by imagining what a header might look like.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { analyse } from '../js/findings.js';
import { get, parseHeaders } from '../js/unfold.js';

// A German Apple Mail export: localised labels, sender on an unlabelled first
// line, no From: field anywhere.
const GERMAN_PASTE = `  Beispiel <noreply@mail.example.email>
  Herzlich willkommen!
  An: Maja Beispiel <maja@example.org>
  Antwort an: kontakt@unrelated.example
  Betreff: Herzlich willkommen!
  Original-Recipient: rfc822;maja@example.org
`;

test('localised short field names are mapped to their canonical field', () => {
  const headers = parseHeaders(GERMAN_PASTE);
  assert.match(get(headers, 'To'), /maja@example\.org/);
  assert.equal(get(headers, 'Subject'), 'Herzlich willkommen!');
});

test('localised names containing a space are mapped too', () => {
  const headers = parseHeaders(GERMAN_PASTE);
  assert.equal(get(headers, 'Reply-To'), 'kontakt@unrelated.example');
});

test('the original label is retained for display', () => {
  const headers = parseHeaders(GERMAN_PASTE);
  const to = headers.find((h) => h.name === 'To');
  assert.equal(to.displayedAs, 'An');
});

test('an unlabelled leading sender line becomes From', () => {
  const headers = parseHeaders(GERMAN_PASTE);
  const from = headers.find((h) => h.name === 'From');
  assert.ok(from, 'sender line promoted');
  assert.ok(from.inferred, 'marked as inferred rather than stated');
  assert.match(from.value, /noreply@mail\.example\.email/);
});

test('a real From: is never overridden by a leading line', () => {
  const headers = parseHeaders('Someone <a@b.test>\nFrom: real@c.test\nTo: d@e.test\n');
  assert.equal(get(headers, 'From'), 'real@c.test');
});

test('the reply-to mismatch is found in a localised paste', () => {
  const finding = analyse(parseHeaders(GERMAN_PASTE)).find((f) => f.id === 'reply-to');
  assert.ok(finding, 'without From and Reply-To this would silently not fire');
  assert.match(finding.items[1].value, /unrelated\.example/);
});

test('key=value pairs are not mistaken for VERP recipients', () => {
  // The failure this guards against: `header.from=example.org` in an
  // Authentication-Results line being reported as a hidden recipient address.
  const headers = parseHeaders([
    'To: real@example.org',
    'Authentication-Results: mx.test; dmarc=pass header.from=sender.example',
    'X-Dmarc-Info: pass=pass; d=r1; pdomain=sender.example',
    'Received-SPF: pass (mx.test: domain of x designates 1.2.3.4 as permitted sender)'
      + ' receiver=mx.test; helo=relay.sender.example; envelope-from=bounce@sender.example',
  ].join('\n'));

  const labels = analyse(headers).find((f) => f.id === 'recipients').items.map((i) => i.label);
  assert.deepEqual(labels, ['real@example.org']);
});

test('a genuine VERP bounce address yields the recipient', () => {
  const headers = parseHeaders(
    'To: someone@example.net\nX-Track: bounce-alice=example.org@sender.example\n',
  );
  const labels = analyse(headers).find((f) => f.id === 'recipients').items.map((i) => i.label);
  assert.ok(labels.includes('alice@example.org'), 'known bounce prefix stripped');
});

test('an unknown prefix is left on rather than guessed away', () => {
  // Hyphens are legal in a local part, so `id-alice` may genuinely be the
  // recipient. Reporting it verbatim is honest; trimming it would be invention.
  const headers = parseHeaders(
    'To: someone@example.net\nX-Track: id-alice=example.org@sender.example\n',
  );
  const labels = analyse(headers).find((f) => f.id === 'recipients').items.map((i) => i.label);
  assert.ok(labels.includes('id-alice@example.org'));
});

test('BIMI and ARC results are reported without being marked as failures', () => {
  const headers = parseHeaders([
    'To: a@example.org',
    'Authentication-Results: mx.test; bimi=fail reason="invalid evidence"',
    'Authentication-Results: mx.test; arc=none',
    'Authentication-Results: mx.test; spf=pass',
    'Authentication-Results: mx.test; dkim=pass',
  ].join('\n'));

  const items = analyse(headers).find((f) => f.id === 'auth').items;
  const bimi = items.find((i) => i.label.startsWith('BIMI'));
  assert.equal(bimi.level, null, 'a missing brand logo is not a red flag');
  assert.equal(items.find((i) => i.label.startsWith('SPF')).level, 'good');
});
