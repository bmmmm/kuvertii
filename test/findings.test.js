import assert from 'node:assert/strict';
import { test } from 'node:test';

import { analyse } from '../js/findings.js';
import { parseHeaders } from '../js/unfold.js';
import { BULK_HEADER, MICROSOFT_HEADER, RECIPIENT } from './fixtures.js';

const report = () => analyse(parseHeaders(BULK_HEADER));
const byId = (id) => report().find((f) => f.id === id);
const msReport = () => analyse(parseHeaders(MICROSOFT_HEADER));
const msById = (id) => msReport().find((f) => f.id === id);

// Everything a reader sees on a row: label, value, chips and note alike.
const text = (finding) =>
  finding.items
    .map((i) => `${i.label} ${i.value} ${(i.chips ?? []).join(' ')} ${i.note ?? ''}`)
    .join('\n');

test('the recipient is found in every place it hides', () => {
  const finding = byId('recipients');
  assert.ok(finding, 'recipient finding produced');

  const entry = finding.items.find((i) => i.label === RECIPIENT);
  assert.ok(entry, 'the address is reported');
  assert.match(entry.value, /Written openly/);

  // The point of the tool: the same address encoded in the mailer fields, the
  // unsubscribe token and the folded continuation — not just in To:. Each
  // hiding place is its own chip, so the count is legible at a glance.
  const places = entry.chips.join('\n');
  assert.match(places, /X-Mailer-Info/);
  assert.match(places, /List-Unsubscribe/);
  assert.match(places, /reversed/);
  assert.match(entry.note, /further \d+ times|further time/, 'the prose states the count, not the list');
  assert.equal(finding.tone, 'alert');
});

test('the sender address is never mistaken for a recipient', () => {
  const finding = byId('recipients');
  const labels = finding.items.map((i) => i.label);
  assert.ok(!labels.includes('noreply@mail.example.email'));
  assert.ok(!labels.includes('kontakt@unrelated-hotel.example'));
});

test('per-recipient tracking ids are surfaced', () => {
  const finding = byId('tracking');
  assert.ok(finding);
  const body = text(finding);
  assert.match(body, /Return-Path/);
  assert.match(body, /Feedback-ID/);
  assert.match(body, /newsletter00news20260817/, 'campaign name decoded from X-Mailer-Info');
});

test('a reply-to on an unrelated domain is called out', () => {
  const finding = byId('reply-to');
  assert.ok(finding);
  assert.equal(finding.tone, 'alert');
  assert.match(text(finding), /unrelated-hotel\.example/);
});

test('no reply-to finding when it merely differs in subdomain', () => {
  const headers = parseHeaders(
    'From: a@mail.example.org\nReply-To: b@news.example.org\nTo: c@example.net\n',
  );
  assert.equal(analyse(headers).find((f) => f.id === 'reply-to'), undefined);
});

test('passing authentication is reported without being mistaken for safety', () => {
  const finding = byId('auth');
  assert.ok(finding);
  assert.match(finding.title, /proves less/i);
  assert.match(finding.lede, /do not ask whether the mail is wanted|never ask/i);

  const body = text(finding);
  assert.match(body, /SPF = pass/);
  assert.match(body, /DKIM = pass/);
  assert.match(body, /DMARC = pass/);
  assert.match(body, /2026-08-17/, 'DKIM timestamp rendered as a date');
});

test('the route is reported oldest hop first', () => {
  const finding = byId('route');
  assert.ok(finding);
  assert.match(finding.items[0].label, /origin/);
  // The fixture's first hop was injected over HTTPS, not SMTP.
  assert.match(finding.items[0].value, /203\.0\.113\.116/);
  assert.match(finding.lede, /API/i);
  assert.equal(finding.items.length, 3);
});

test('filter verdicts are collected', () => {
  const body = text(byId('judgement'));
  assert.match(body, /Spam flag/);
  assert.match(body, /JUNK/);
});

test('the unsubscribe link is resolved and judged', () => {
  const finding = byId('unsubscribe');
  assert.ok(finding);
  assert.match(finding.lede, /one-click/i);
  assert.ok(finding.hostsToCheck.length > 0, 'hands hostnames to the blocklist stage');
});

test('the list identifier is extracted from its description', () => {
  const finding = byId('list');
  assert.ok(finding, 'list finding produced');

  const id = finding.items.find((i) => i.label === 'List identifier');
  assert.equal(id.value, 'reaktivierung-90d.mail.example.email');

  // The internal segment name is the candid part — it is why this card exists.
  assert.match(id.value, /reaktivierung/);
  assert.match(text(finding), /Beispiel Wochenpost/, 'the sender\'s own description is kept');
  assert.match(text(finding), /archiv/i, 'the public archive is reported');
});

test('list contact addresses are not reported as recipients', () => {
  // List-Owner names the list, not a person this was addressed to.
  const labels = byId('recipients').items.map((i) => i.label);
  assert.ok(!labels.includes('redaktion@mail.example.email'));
});

test('platform recipient ids are named with the platform that keys them', () => {
  const body = text(byId('tracking'));
  assert.match(body, /SendGrid/, 'X-SG-EID attributed');
  assert.match(body, /Marketo/, 'X-MarketoID attributed');
  assert.match(body, /lead id/i, 'and explained in terms of the record it points at');
});

test('an unattributed id header is reported without inventing a platform', () => {
  const item = byId('tracking').items.find((i) => /X-Campaign-Id/i.test(i.label));
  assert.ok(item, 'the generic pattern still fires');
  assert.deepEqual(item.chips, [], 'but claims no platform');
});

test('one payload repeated across mailer fields is reported once', () => {
  // X-Mailer-Info and -Extra carry the same decoded content in the fixture.
  const items = byId('tracking').items.filter((i) => /X-Mailer-Info/.test(i.label));
  assert.equal(items.length, 1, 'grouped rather than listed twice');
  assert.match(items[0].label, /X-Mailer-Info, X-Mailer-Info-Extra/);
});

test('an oversized tracking payload is clipped rather than dumped', () => {
  const headers = parseHeaders(`X-MSFBL: ${'A'.repeat(4000)}\n`);
  const item = analyse(headers).find((f) => f.id === 'tracking').items[0];
  assert.ok(item.value.length < 200, 'clipped for display');
  assert.match(item.value, /\.\.\./);
  assert.match(item.note, /SparkPost|feedback/i);
});

test('the composing machine is described without claiming it is the reader', () => {
  const finding = msById('origin');
  assert.ok(finding);

  const body = text(finding);
  assert.match(body, /198\.51\.100\.77/, 'client IP surfaced');
  assert.match(body, /Outlook 16/, 'mail program surfaced');
  assert.match(body, /UTC\+03:00/, 'timezone read from the Date offset');

  // The honest framing: on received mail this is the sender, not the reader.
  assert.match(finding.lede, /you send/i);
});

test('a UTC offset is not reported as a timezone finding', () => {
  // +0000 means an automated sender and says nothing about a person.
  const headers = parseHeaders('Date: Mon, 17 Aug 2026 17:48:42 +0000\nX-Mailer: Bulk\n');
  const finding = analyse(headers).find((f) => f.id === 'origin');
  assert.ok(!text(finding).includes('timezone'));
});

test('a private client IP is not treated as an exposed address', () => {
  const headers = parseHeaders('X-Originating-IP: [192.168.1.14]\n');
  const item = analyse(headers).find((f) => f.id === 'origin').items[0];
  assert.equal(item.level, null);
  assert.match(item.note, /private/i);
});

test('microsoft 365 verdicts are decoded into words', () => {
  const finding = msById('judgement');
  assert.ok(finding);
  assert.equal(finding.tone, 'alert', 'a phishing verdict raises the card');

  const body = text(finding);
  assert.match(body, /Spam Confidence Level 9/);
  assert.match(body, /high confidence/i);
  assert.match(body, /phishing/i, 'CAT:PHSH translated');
  assert.match(body, /domain impersonation/i, 'SFTY 9.19 translated');
  assert.match(body, /RU/, 'connecting country reported');
});

test('skipped filtering is flagged rather than read as a pass', () => {
  // SCL:-1 with SFV:SKN is what a mail flow rule looks like from the inside.
  const headers = parseHeaders(
    'X-Forefront-Antispam-Report: SCL:-1;SFV:SKN;CAT:NONE\n',
  );
  const items = analyse(headers).find((f) => f.id === 'judgement').items;
  assert.ok(items.every((i) => i.level !== 'good'), 'never reported as clean');

  const scl = items.find((i) => /Confidence Level/.test(i.label));
  assert.equal(scl.level, 'caution');
  assert.match(scl.value, /skipped/i);
  assert.match(text({ items }), /before any check ran/, 'SFV:SKN explained');
});

test('an empty input produces no findings rather than throwing', () => {
  assert.deepEqual(analyse(parseHeaders('')), []);
});

test('a minimal header produces only what it can support', () => {
  const findings = analyse(parseHeaders('From: a@example.org\nTo: b@example.net\n'));
  assert.deepEqual(findings.map((f) => f.id), ['recipients']);
  assert.equal(findings[0].tone, 'info', 'nothing hidden, so no alarm');
});
