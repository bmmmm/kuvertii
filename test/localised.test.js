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

// A localised label is a translation of a field, not a competitor to it. The
// alias table exists so that a paste which lost its English labels still
// analyses; it was never meant to arbitrate when both are present, and left to
// do so it preferred whichever came first — which the sender chooses.

test('an aliased label never overrides the real field', () => {
  // `De:` is a syntactically valid optional header. No relay strips it and no
  // client displays it, so the reader sees only its effect.
  const headers = parseHeaders([
    'De: refund-desk@attacker-mail.example',
    'From: PayPal Support <support@paypal.com>',
    'To: you@example.org',
  ].join('\n'));

  assert.equal(get(headers, 'from'), 'PayPal Support <support@paypal.com>');
  assert.ok(headers.some((h) => h.name === 'De'), 'the line is kept, under the name it was written with');
});

test('the reply-to warning survives a smuggled alias', () => {
  // Suppressing this card is what the smuggle buys: with `De:` winning `From`,
  // the sender and the reply address agree and nothing is reported.
  const headers = parseHeaders([
    'De: refund-desk@attacker-mail.example',
    'From: PayPal Support <support@paypal.com>',
    'Reply-To: refund-desk@attacker-mail.example',
    'To: you@example.org',
  ].join('\n'));

  const text = JSON.stringify(analyse(headers));
  assert.match(text, /attacker-mail\.example/);
  assert.match(text, /repl(y|ies)/i);
});

test('a genuine localised paste still resolves every field', () => {
  // The case the alias table exists for: no English label anywhere.
  const headers = parseHeaders([
    'Von: Echte Firma <info@firma.example>',
    'An: du@example.org',
    'Antwort an: service@firma.example',
    'Betreff: Rechnung',
  ].join('\n'));

  assert.equal(get(headers, 'from'), 'Echte Firma <info@firma.example>');
  assert.equal(get(headers, 'to'), 'du@example.org');
  assert.equal(get(headers, 'reply-to'), 'service@firma.example');
});

test('a smuggled alias is reported rather than quietly dropped', () => {
  const findings = analyse(parseHeaders([
    'De: refund-desk@attacker-mail.example',
    'From: PayPal Support <support@paypal.com>',
    'To: you@example.org',
  ].join('\n')));

  const text = JSON.stringify(findings[0]);
  assert.match(text, /written as if it were From/);
});

test('a field that may appear once is reported when it appears twice', () => {
  const findings = analyse(parseHeaders([
    'From: PayPal Support <support@paypal.com>',
    'From: refund-desk@attacker-mail.example',
    'To: you@example.org',
  ].join('\n')));

  assert.match(findings[0].title, /twice/i);
  assert.match(JSON.stringify(findings[0]), /from appears 2 times/);
});
