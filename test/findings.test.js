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

test('a partial paste is reported as partial', () => {
  // A fragment does not fail loudly — it analyses fine and quietly answers a
  // narrower question than the reader thinks they asked.
  const fragment = parseHeaders(
    'Received-SPF: pass (spf.example.net: domain of news@sender.example designates 1.2.3.4 as permitted sender)\n'
    + 'X-Apple-MoveToFolder: INBOX\n',
  );
  const finding = analyse(fragment).find((f) => f.id === 'completeness');
  assert.ok(finding, 'the shortfall is reported');
  assert.equal(analyse(fragment)[0].id, 'completeness', 'and reported first, before anything it qualifies');

  const named = finding.items.map((i) => i.label).join(' ');
  assert.match(named, /From is missing/);
  assert.match(named, /Received is missing/);
  assert.match(named, /To is missing/);
});

test('a full header is not accused of being partial', () => {
  assert.equal(byId('completeness'), undefined);
  assert.equal(msById('completeness'), undefined);
});

test('one absent field alone is not called a fragment', () => {
  // Plenty of legitimate mail lacks a Message-ID, and a copied header often
  // drops its last line. Only two or more absences mean a fragment.
  const headers = parseHeaders(
    'From: a@example.org\nTo: b@example.net\nDate: Mon, 17 Aug 2026 10:00:00 +0000\n'
    + 'Received: from x by y with SMTP id z; Mon, 17 Aug 2026 10:00:00 +0000\n',
  );
  assert.equal(analyse(headers).find((f) => f.id === 'completeness'), undefined);
});

test('the envelope sender is not read as a hidden recipient', () => {
  // Regression from a real partial paste: with no From: line, the address in
  // envelope-from was reported as a recipient hiding in encoded form — wrong,
  // and exactly backwards.
  const headers = parseHeaders(
    'Received-SPF: pass (spf.example.net: domain of notifications@sender.example '
    + 'designates 1.2.3.4 as permitted sender) envelope-from=notifications@sender.example\n',
  );
  const recipients = analyse(headers).find((f) => f.id === 'recipients');
  assert.equal(recipients, undefined, 'the sender is nobody\'s recipient');
});

const CROWD = `From: org@example.com
To: you@mailbox.example, ${Array.from({ length: 25 }, (_, i) => `person${i + 1}@example.org`).join(', ')}
Date: Mon, 17 Aug 2026 10:00:00 +0000
Message-ID: <a@example.com>
Delivered-To: you@mailbox.example
Received: from x by y with SMTP id z for <you@mailbox.example>; Mon, 17 Aug 2026 10:00:00 +0000
`;

test('a message sent to a crowd says what that cost the reader', () => {
  const finding = analyse(parseHeaders(CROWD)).find((f) => f.id === 'disclosure');
  assert.ok(finding);
  assert.match(finding.title, /shown to 25 other people/);
  assert.match(finding.lede, /Bcc/, 'names the thing the sender could have used');
  assert.equal(finding.tone, 'alert');

  // The reader is not counted among the people they were exposed to.
  assert.ok(!finding.items.some((i) => i.label === 'you@mailbox.example'));
});

test('a crowd is summarised rather than listed twice', () => {
  const findings = analyse(parseHeaders(CROWD));
  const recipients = findings.find((f) => f.id === 'recipients');

  // The delivery fields identify the reader, so the other 25 belong on the
  // disclosure card and are counted here rather than repeated.
  assert.equal(recipients.items.length, 2, 'the reader, plus a count');
  assert.equal(recipients.items[0].label, 'you@mailbox.example');
  assert.match(recipients.items[1].label, /25 further addresses/);

  const listed = findings.find((f) => f.id === 'disclosure').items;
  assert.ok(listed.length <= 7, 'and the disclosure card caps its own list too');
  assert.match(listed.at(-1).label, /and 19 more/);
});

test('an ordinary two-party message triggers neither', () => {
  const headers = parseHeaders(
    'From: a@example.org\nTo: b@example.net\nDate: Mon, 17 Aug 2026 10:00:00 +0000\n'
    + 'Message-ID: <x@example.org>\nReceived: from x by y with SMTP id z; Mon, 17 Aug 2026 10:00:00 +0000\n',
  );
  const ids = analyse(headers).map((f) => f.id);
  assert.ok(!ids.includes('disclosure'), 'one recipient is not a disclosure');
  assert.equal(analyse(headers).find((f) => f.id === 'recipients').items.length, 1);
});

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

test('a failing check is never described in the words of a passing one', () => {
  const finding = msById('auth');
  assert.ok(finding);
  assert.equal(finding.tone, 'alert', 'failures raise the card');
  assert.match(finding.title, /did not check out/);

  const spf = finding.items.find((i) => i.label === 'SPF = fail');
  assert.match(spf.value, /not authorised/, 'says what actually happened');
  assert.equal(spf.level, 'bad');

  const dkim = finding.items.find((i) => i.label === 'DKIM = none');
  assert.match(dkim.value, /no signature/i);

  // The regression this guards: one description per mechanism reads as the
  // pass case and inverts the meaning on a forged message.
  assert.doesNotMatch(spf.value, /was authorised by the domain to send/);
  assert.doesNotMatch(dkim.value, /carries an intact/);
});

test('innocent explanations for a failure are given alongside it', () => {
  // Forwarding breaks SPF routinely; the card must not read as proof of fraud.
  assert.match(msById('auth').lede, /forwarded|innocent/i);
});

test('the SPF explanation is reported, not just the verdict word', () => {
  const body = text(msById('auth'));
  assert.match(body, /Received-SPF: Fail/);
  assert.match(body, /does not designate/, 'the server\'s own wording is kept');
});

test('a hop named after an encoded identifier is decoded', () => {
  // Sending platforms label the first hop with the customer they are billing,
  // base64'd. `MzE4NTk5NDA` is `31859940` — an account number, not a host.
  const headers = parseHeaders(
    'Received-SPF: pass (domain of bounces+31859940-8aa2-user=mailbox.example@em1.sender.example)\n'
    + 'Received: from MzE4NTk5NDA by geopod-ismtpd-40 with HTTP id x; Mon, 17 Aug 2026 22:40:52 +0000\n',
  );
  const hop = analyse(headers).find((f) => f.id === 'route').items[0];
  assert.ok(hop.chips.some((c) => /decodes to 31859940/.test(c)));
  // The same number sits in the bounce address, which is what proves it is an
  // account rather than a coincidence.
  assert.match(hop.note, /account number/);
});

test('an ordinary hostname is never reported as an encoded identifier', () => {
  // Forced through base64 these yield control bytes, not text — the property
  // that separates them, since an account number reads as unremarkable prose.
  const headers = parseHeaders(
    'Received: from o8.ptr6101.mail.example.com by mx.example.net with ESMTPS id a\n'
    + 'Received: by recvd-canary-54f88fd5bd-wpf6s with SMTP id b\n'
    + 'Received: from mta-in-02 by gateway-99 with SMTP id c\n',
  );
  for (const hop of analyse(headers).find((f) => f.id === 'route').items) {
    assert.equal(hop.note, null, `${hop.value} was misread as encoded`);
    assert.ok(!hop.chips.some((c) => /decodes to/.test(c)));
  }
});

test('a VERP address with routing ids folds onto the known recipient', () => {
  // Real schemes wedge ids between the prefix and the address:
  // bounces+31859940-8aa2-alice=example.org@sender. Reported on its own it
  // reads as a second recipient under a name nobody recognises as their own.
  const headers = parseHeaders(
    'To: alice@example.org\n'
    + 'Received-SPF: pass (domain of bounces+31859940-8aa2-alice=example.org@em1.sender.example designates 1.2.3.4)\n',
  );
  const labels = analyse(headers).find((f) => f.id === 'recipients').items.map((i) => i.label);
  assert.deepEqual(labels, ['alice@example.org'], 'one person, not two');

  const entry = analyse(headers).find((f) => f.id === 'recipients').items[0];
  assert.ok(entry.chips.some((c) => /VERP/.test(c)), 'still reported as a hiding place');
});

test('a genuinely different address is still reported separately', () => {
  // The fold must key on the known recipient, not swallow anything similar.
  const headers = parseHeaders(
    'To: alice@example.org\n'
    + 'X-Envelope-To: bounces-bob=example.org@em1.sender.example\n',
  );
  const labels = analyse(headers).find((f) => f.id === 'recipients').items.map((i) => i.label);
  assert.ok(labels.includes('alice@example.org'));
  assert.ok(labels.some((l) => /bob@example\.org/.test(l)), 'bob is not alice');
});

test('a clean message is not told it was filed as junk', () => {
  // The lede's closing clause is a claim about this specific message. The
  // bulk fixture carries X-Spam-Flag, so it earns the strong wording; a
  // message with no verdict at all must not have it asserted about them.
  assert.match(byId('auth').lede, /still filed it as junk/, 'the fixture does carry a verdict');

  const clean = parseHeaders(
    'From: a@example.org\nTo: b@example.net\n'
    + 'Authentication-Results: mx.example.net; spf=pass; dkim=pass; dmarc=pass\n',
  );
  const lede = analyse(clean).find((f) => f.id === 'auth').lede;
  assert.doesNotMatch(lede, /filed it as junk/);
  assert.match(lede, /many do/, 'the general point still lands');
});

test('a partially signed body is reported as such', () => {
  // The l= tag signs only the first n bytes; the rest can be appended freely,
  // so a passing DKIM result stops vouching for the whole message.
  const headers = parseHeaders(
    'DKIM-Signature: a=rsa-sha256; d=example.org; l=1024; b=AAAA\n',
  );
  const item = analyse(headers).find((f) => f.id === 'auth').items
    .find((i) => /Only part/.test(i.label));
  assert.ok(item, 'the length tag is reported');
  assert.match(item.value, /1,024 bytes/);
  assert.equal(item.level, 'caution');
});

test('a full signature produces no length warning', () => {
  // The bulk fixture signs everything — the absence must stay silent.
  const labels = byId('auth').items.map((i) => i.label);
  assert.ok(!labels.some((l) => /Only part/.test(l)));
});

test('a deprecated signing algorithm is called out', () => {
  const headers = parseHeaders('DKIM-Signature: a=rsa-sha1; d=example.org; b=AAAA\n');
  const item = analyse(headers).find((f) => f.id === 'auth').items
    .find((i) => /rsa-sha1/.test(i.label));
  assert.ok(item);
  assert.match(item.value, /RFC 8301|collisions/i);
  assert.equal(item.level, 'caution');
});

test('a current signing algorithm passes without comment', () => {
  const headers = parseHeaders('DKIM-Signature: a=ed25519-sha256; d=example.org; b=AAAA\n');
  const labels = analyse(headers).find((f) => f.id === 'auth').items.map((i) => i.label);
  assert.ok(!labels.some((l) => /Signed with/.test(l)));
});

test('a self-declared urgency is reported as a claim, not a verdict', () => {
  const item = msById('origin').items.find((i) => /urgent/i.test(i.label));
  assert.ok(item, 'X-Priority: 1 is surfaced');
  assert.match(item.note, /self-declaration|nothing checked it/i);
  assert.equal(item.level, undefined, 'stated plainly rather than flagged');
});

test('an ordinary priority is not mentioned at all', () => {
  const headers = parseHeaders('X-Priority: 3 (Normal)\nX-Mailer: Thunderbird\n');
  const finding = analyse(headers).find((f) => f.id === 'origin');
  assert.ok(!text(finding).match(/urgent/i));
});

test('an empty input produces no findings rather than throwing', () => {
  assert.deepEqual(analyse(parseHeaders('')), []);
});

test('a minimal header produces only what it can support', () => {
  const findings = analyse(parseHeaders('From: a@example.org\nTo: b@example.net\n'));
  // Two lines are a fragment, and saying so is the first thing to report.
  assert.deepEqual(findings.map((f) => f.id), ['completeness', 'recipients']);

  const recipients = findings.find((f) => f.id === 'recipients');
  assert.equal(recipients.tone, 'info', 'nothing hidden, so no alarm');
});
