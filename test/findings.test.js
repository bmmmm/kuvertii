import assert from 'node:assert/strict';
import { test } from 'node:test';

import { ALL_CLEAR_TITLE, analyse, guardSection } from '../js/findings.js';
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

test('a header missing only its display fields is not called a fragment', () => {
  // Mail clients render From, To, Subject and Date above the header block, so
  // a complete copy of "all headers" arrives without them. Thirty-eight fields
  // is not a truncated paste, and telling the reader it is misleads them.
  const many = [
    'Return-Path: <bounces-x=mailbox.example@sender.example>',
    'Original-Recipient: rfc822;x@mailbox.example',
    'Authentication-Results: mx.example; dkim=pass; spf=pass',
    'Received: from a by b with SMTP id c; Mon, 17 Aug 2026 10:00:00 +0000',
    ...Array.from({ length: 15 }, (_, i) => `X-Filler-${i}: value`),
  ].join('\n');

  const finding = analyse(parseHeaders(`${many}\n`)).find((f) => f.id === 'completeness');
  assert.ok(finding, 'still reported, since the fields do matter');
  assert.match(finding.title, /kept a few fields to itself/);
  assert.match(finding.lede, /not a truncated paste/);
  assert.doesNotMatch(finding.lede, /several dozen/, 'no nonsense about its size');
});

test('a bounce subdomain is not a person', () => {
  // Nobody has a mailbox at bounce.linkedin.com. The envelope-sender scan
  // catches this address when the header labels it; a partial paste does not
  // label it, and it was surfacing as the reader.
  const headers = parseHeaders(
    'To: you@mailbox.example\n'
    + 'X-Whatever: m-j7q2rwb8aca3ozj7n0uy4hluj7tlsdydo5j1tw9dvhagtr25o3b@bounce.linkedin.com\n',
  );
  const labels = analyse(headers).find((f) => f.id === 'recipients').items.map((i) => i.label);
  assert.ok(!labels.some((l) => /bounce\.linkedin\.com/.test(l)));
  assert.ok(labels.includes('you@mailbox.example'));
});

test('an ordinary subdomain is still a person', () => {
  // The rule keys on return-path subdomains, not on subdomains in general.
  const headers = parseHeaders(
    'To: you@mailbox.example\nX-Envelope-To: someone@mail.university.example\n',
  );
  const labels = analyse(headers).find((f) => f.id === 'recipients').items.map((i) => i.label);
  assert.ok(labels.includes('someone@mail.university.example'));
});

test('DMARC reporting addresses are not recipients', () => {
  // rua=/ruf= name whoever runs the sending domain. Reading them as recipients
  // puts a stranger's postmaster among the people this was addressed to.
  const headers = parseHeaders(
    'From: news@sender.example\nTo: you@mailbox.example\n'
    + 'Date: Mon, 17 Aug 2026 10:00:00 +0000\nMessage-ID: <a@sender.example>\n'
    + 'Received: from a by b with SMTP id c; Mon, 17 Aug 2026 10:00:00 +0000\n'
    + 'X-Dmarc-Policy: v=DMARC1;p=reject;rua=mailto:dmarc@sender.example;ruf=mailto:dmarc@sender.example\n',
  );
  const labels = analyse(headers).find((f) => f.id === 'recipients').items.map((i) => i.label);
  assert.deepEqual(labels, ['you@mailbox.example']);
});

test('an absence is marked as one, not as a failure', () => {
  // A missing field and an unsigned message are things the analysis could not
  // do, not faults in the mail. Marking them like a forged sender would put
  // them on a level they do not belong on.
  const fragment = analyse(parseHeaders('X-Apple-MoveToFolder: INBOX\n'));
  const missing = fragment.find((f) => f.id === 'completeness').items;
  assert.ok(missing.every((i) => i.level === 'absent'), 'every missing field is marked absent');

  const auth = analyse(parseHeaders(
    'Authentication-Results: mx.example; spf=fail; dkim=none; dmarc=fail; bimi=pass\n',
  )).find((f) => f.id === 'auth');
  const level = (label) => auth.items.find((i) => i.label === label).level;

  assert.equal(level('SPF = fail'), 'bad', 'a failure is a failure');
  assert.equal(level('DKIM = none'), 'absent', 'nothing to check is not a failure');
  assert.equal(level('BIMI = pass'), 'good', 'a pass counts even where a failure would not');
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
  assert.equal(scl.level, 'caution', 'SCL:-1 is the one score that still means something');
  assert.match(scl.value, /skipped/i);
  assert.match(text({ items }), /mail flow rule/i, 'SFV:SKN named for what it is');
});

test('a category verdict outranks the score that no longer decides', () => {
  // Microsoft's reference: on cloud mailboxes SCL "doesn't determine whether
  // the message is identified as spam ... use the CAT and DIR values instead".
  // This header is what a waved-through brand impersonation looks like, and it
  // used to render as a single green "Inspected and not considered spam".
  const headers = parseHeaders(
    'X-Forefront-Antispam-Report: CIP:1.2.3.4;CTRY:RU;SFV:SFE;SRV:BULK;CAT:BIMP;SFTY:9.25;SCL:1;IPV:CAL\n',
  );
  const items = analyse(headers).find((f) => f.id === 'judgement').items;

  assert.ok(items.every((i) => i.level !== 'good'), 'nothing here is a clean bill');
  assert.equal(items.find((i) => /Confidence Level/.test(i.label)).level, null, 'SCL carries no colour');
  assert.equal(items.find((i) => /BIMP/.test(i.label))?.level, 'bad', 'the category does');

  // Both bypasses are surfaced; each used to be dropped entirely.
  const all = text({ items });
  assert.match(all, /Safe Senders list/);
  assert.match(all, /IP address is on an allow list/);
});

test('a first-contact tip is not an accusation', () => {
  // 9.25 fires on the first message from any new correspondent. 9.11, 9.21 and
  // 9.22 are gone from Microsoft's table; 9.11 rendered bulk mail as red.
  const items = analyse(parseHeaders('X-Forefront-Antispam-Report: SFTY:9.25;SCL:1\n'))
    .find((f) => f.id === 'judgement').items;
  assert.equal(items.find((i) => /Safety verdict/.test(i.label)).level, 'caution');

  const stale = analyse(parseHeaders('X-Forefront-Antispam-Report: SFTY:9.11;SCL:1\n'))
    .find((f) => f.id === 'judgement').items;
  assert.ok(!stale.some((i) => /Safety verdict/.test(i.label)), 'a retired code states nothing');
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

test('a current signing algorithm is never flagged as a problem', () => {
  // The commonest current choice says nothing at all.
  const rsa = analyse(parseHeaders('DKIM-Signature: a=rsa-sha256; d=example.org; b=AAAA\n'))
    .find((f) => f.id === 'auth').items;
  assert.ok(!rsa.some((i) => /Signed with/.test(i.label)));

  // Ed25519 gets a sentence, but a colourless one: without it the `a=` branch
  // only ever spoke to accuse, and a sender who did the modern thing was met
  // with the same silence as one who did nothing.
  const ed = analyse(parseHeaders('DKIM-Signature: a=ed25519-sha256; d=example.org; b=AAAA\n'))
    .find((f) => f.id === 'auth').items;
  const row = ed.find((i) => /Signed with/.test(i.label));
  assert.match(row.label, /ed25519/);
  assert.equal(row.level, undefined, 'RFC 8463 is current, not a fault');
});

test('an expired signature is reported against the arrival time', () => {
  // DKIM replay: one correctly signed message re-sent to thousands of others,
  // where the signature keeps verifying because it covers nothing about who it
  // was addressed to. `x=` is the answer to that, and was parsed for nothing.
  const expired = analyse(parseHeaders([
    'DKIM-Signature: a=rsa-sha256; d=example.org; s=k1; t=1767225600; x=1767229200; b=AAAA',
    'Received: from a.example by b.example; Wed, 15 Jul 2026 12:00:00 +0000',
  ].join('\n'))).find((f) => f.id === 'auth').items;

  const row = expired.find((i) => /expir/i.test(i.label));
  assert.equal(row.level, 'caution');
  assert.match(row.note, /no signature at all/);

  // The same signature, arriving inside its window, is not a complaint.
  const fresh = analyse(parseHeaders([
    'DKIM-Signature: a=rsa-sha256; d=example.org; s=k1; t=1767225600; x=1767229200; b=AAAA',
    'Received: from a.example by b.example; Thu, 1 Jan 2026 00:30:00 +0000',
  ].join('\n'))).find((f) => f.id === 'auth').items;
  assert.equal(fresh.find((i) => /expiry/i.test(i.label))?.level, null);
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

// ------------------------------------------------ what the receiver decided

const auth = (...lines) => {
  const finding = analyse(parseHeaders(`${lines.join('\n')}\n`)).find((f) => f.id === 'auth');
  return { items: finding.items, all: text(finding), lede: finding.lede };
};

test('the published policy is read from the DMARC result, not from the whole line', () => {
  // `=` is legal in a local part, and Gmail-class receivers echo the envelope
  // sender verbatim into the SPF parenthetical — which comes first. Scraping
  // /p=(\w+)/ over the whole string let the sender write this row.
  const { all } = auth(
    'Authentication-Results: spf=fail (sender IP is 1.2.3.4)'
    + ' smtp.mailfrom=p=reject@evil.example; dmarc=fail (p=NONE sp=NONE dis=NONE)'
    + ' header.from=victim.example',
  );
  assert.match(all, /Published DMARC policy/);
  assert.doesNotMatch(all, /policy.*reject/is, 'the envelope sender cannot dictate the policy row');
});

test('a policy in test mode is not a policy', () => {
  // RFC 9989 §5.5.1 replaced pct= with t=. A domain can advertise p=reject and
  // ask in the same breath that nothing be rejected.
  const { all } = auth('Authentication-Results: mx.example; dmarc=fail (p=reject t=y) header.from=a.example');
  assert.match(all, /test mode/i);
  assert.match(all, /protects nothing/);
});

test('what the receiver did is separated from what the domain asked for', () => {
  const { all } = auth('Authentication-Results: mx.example; dmarc=fail action=oreject header.from=a.example');
  assert.match(all, /What this receiver did/);
  assert.match(all, /overrode it, delivering anyway/);
});

test('composite authentication is read, and its reason code explained', () => {
  // The largest receiver kuvertii meets records its identity decision here, and
  // the mechanism scanner structurally cannot see it.
  const { items, all } = auth(
    'Authentication-Results: spf=fail; dkim=none; dmarc=fail; compauth=fail reason=010',
  );
  assert.equal(items.find((i) => /Composite authentication/.test(i.label)).level, 'bad');
  assert.match(all, /Reason 010/);
  assert.match(all, /self-to-self spoofing|inside/i);
});

test('an unlisted reason code still says something, from its leading digit', () => {
  const { all } = auth('Authentication-Results: mx.example; compauth=pass reason=104');
  assert.match(all, /Reason 104/);
});

test('ARC is not called noise while it is explaining the failure', () => {
  const failing = auth('Authentication-Results: mx.example; spf=fail; dmarc=fail; arc=pass');
  const arc = failing.items.find((i) => /^ARC/.test(i.label));
  assert.doesNotMatch(arc.note, /Informational/);
  assert.match(arc.note, /forwarder/i);

  // With no DMARC failure to explain, it goes back to being informational.
  const passing = auth('Authentication-Results: mx.example; spf=pass; dmarc=pass; arc=pass');
  assert.match(passing.items.find((i) => /^ARC/.test(i.label)).note, /Informational/);
});

test('a fabricated one-click header buys no endorsement', () => {
  // RFC 8058 §3 defines exactly one value. A substring test accepted anything.
  const fake = analyse(parseHeaders([
    'From: a@b.example',
    'List-Unsubscribe: <https://evil.example/login>',
    'List-Unsubscribe-Post: definitely-not-one-click',
  ].join('\n')));
  assert.doesNotMatch(JSON.stringify(fake), /8058/);

  const real = analyse(parseHeaders([
    'From: a@b.example',
    'List-Unsubscribe: <https://b.example/unsubscribe>',
    'List-Unsubscribe-Post: List-Unsubscribe=One-Click',
  ].join('\n')));
  assert.match(JSON.stringify(real), /8058/);
});

test('the one-click claim does not promise privacy it cannot deliver', () => {
  // RFC 8058 §3.1: the POST goes to the same address as the link, so the
  // per-recipient id travels either way. What it drops is the context.
  const real = JSON.stringify(analyse(parseHeaders([
    'From: a@b.example',
    'List-Unsubscribe: <https://b.example/unsubscribe>',
    'List-Unsubscribe-Post: List-Unsubscribe=One-Click',
  ].join('\n'))));
  assert.doesNotMatch(real, /skips the click tracker/);
  assert.match(real, /same address/);
});

test('a sender asking for unencrypted delivery is reported', () => {
  // RFC 8689. Its whole function is to ask relays to ignore the recipient's own
  // MTA-STS and DANE policy.
  const finding = analyse(parseHeaders('From: a@b.example\nTLS-Required: No\n'))
    .find((f) => f.id === 'origin');
  const row = text(finding);
  assert.match(row, /travel unencrypted/i);
  assert.match(row, /8689/);

  // Any other value, including the header's absence, says nothing.
  const quiet = analyse(parseHeaders('From: a@b.example\nTLS-Required: Yes\n'))
    .find((f) => f.id === 'origin');
  assert.ok(!quiet || !/travel unencrypted/i.test(text(quiet)));
});

test('a hop says whether it was encrypted, not merely which verb it used', () => {
  const finding = analyse(parseHeaders([
    'From: a@b.example',
    'Received: from a.example by b.example with ESMTPS; Mon, 1 Jan 2026 00:00:02 +0000',
    'Received: from c.example by a.example with ESMTPA; Mon, 1 Jan 2026 00:00:00 +0000',
  ].join('\n'))).find((f) => f.id === 'route');

  const all = text(finding);
  assert.match(all, /encrypted hop/);
  // ESMTPA is authenticated, not encrypted — the `S` is the one that means TLS.
  assert.match(all, /unencrypted hop/);
});

test('a message signed only under the DKIM2 draft is not met with silence', () => {
  // draft-ietf-dkim-dkim2-spec is an active Internet-Draft with no RFC. The
  // card used to return null unless one of the three classic inputs was
  // present, so such a message produced no authentication section at all.
  const finding = analyse(parseHeaders([
    'From: a@b.example',
    'DKIM2-Signature: i=1; d=b.example; s=k1; b=AAAA',
    'Message-Instance: i=1; h=abc',
  ].join('\n'))).find((f) => f.id === 'auth');

  assert.ok(finding, 'the card exists');
  const row = finding.items.find((i) => /DKIM2/.test(i.label));
  assert.equal(row.level, undefined, 'a draft is not a verdict');
  assert.match(row.note, /no published RFC/);
});

// ------------------------------------------------------- faults are findings

test('a timestamp too large to be a time is named, not thrown on', () => {
  // `t=` is decimal seconds and the sender writes it. The pattern reading it
  // has no upper bound and Date does, so this reached toISOString() and threw
  // a RangeError out of analyse, out of report, and out of the process — one
  // field a spammer controls, and the whole report was suppressed.
  const findings = analyse(parseHeaders([
    'From: a@b.example',
    'DKIM-Signature: v=1; a=rsa-sha256; d=b.example; s=s1; t=99999999999999; bh=abc; b=def',
  ].join('\n')));

  const auth = findings.find((f) => f.id === 'auth');
  assert.ok(auth, 'the section still exists');
  assert.ok(!findings.some((f) => String(f.id).startsWith('fault:')), 'and did not merely fail politely');

  const row = auth.items.find((i) => /not a time/.test(i.label));
  assert.ok(row, 'the impossible timestamp is reported');
  assert.equal(row.value, 't=99999999999999');
});

test('an expiry too large to be a time does not silently answer "not expired"', () => {
  // The comparison against an invalid Date returns false whichever way it is
  // asked, so the dangerous reading — "this signature is still valid" — is the
  // one that would have been printed.
  const findings = analyse(parseHeaders([
    'From: a@b.example',
    'Received: from x by y; Mon, 17 Aug 2026 09:14:02 -0700',
    'DKIM-Signature: v=1; a=rsa-sha256; d=b.example; s=s1; x=99999999999999; bh=abc; b=def',
  ].join('\n')));

  const auth = findings.find((f) => f.id === 'auth');
  const row = auth.items.find((i) => /expiry is not a time/.test(i.label));
  assert.ok(row, 'the impossible expiry is reported');
  assert.equal(row.level, 'caution');
  assert.ok(
    !auth.items.some((i) => /carries an expiry|had expired/.test(i.label)),
    'and no verdict about expiry is stated alongside it',
  );
});

test('a section that throws costs that section and nothing else', () => {
  // The boundary is only reachable through a producer that throws, and the
  // bugs that used to provide one are fixed. Driving it directly is what keeps
  // it from rotting: delete the try/catch and this test is what goes red.
  const finding = guardSection('demonstration', () => {
    throw new RangeError('Invalid time value');
  });

  assert.equal(finding.tone, 'alert');
  assert.equal(finding.items[0].level, 'fault', 'not absent — absent is about the mail, this is about us');
  assert.match(finding.items[0].label, /demonstration/);
  assert.match(finding.items[0].value, /RangeError: Invalid time value/);
  assert.match(finding.items[0].note, /bug in kuvertii/);
});

test('a section that returns nothing is still nothing', () => {
  assert.equal(guardSection('quiet', () => null), null);
});

test('no fixture makes the analysis fault', () => {
  // The boundary must never be load-bearing for input we already understand.
  // If this goes red, a producer started throwing on ordinary mail and the
  // report has been quietly narrower ever since.
  for (const header of [BULK_HEADER, MICROSOFT_HEADER]) {
    const faults = analyse(parseHeaders(header)).filter((f) => String(f.id).startsWith('fault:'));
    assert.deepEqual(faults, [], `a producer threw on a fixture: ${faults.map((f) => f.id).join(', ')}`);
  }
});

test('a hop encrypted with TLS is not reported as plaintext', () => {
  // The protocol token was read from the first `with` in the line, and RFC 5322
  // comments can contain anything — `(Postfix with SMTP)` answered before
  // `with ESMTPS` was reached. A TLS 1.3 hop was reported to the reader as
  // unencrypted, in the card about the route the message took.
  const finding = analyse(parseHeaders([
    'From: a@b.example',
    'Received: from mail.example.com (Postfix with SMTP)',
    '        by mx.test.com with ESMTPS id abc123',
    '        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384);',
    '        Mon, 17 Aug 2026 09:14:02 -0700 (PDT)',
  ].join('\n'))).find((f) => f.id === 'route');

  const hop = finding.items[0];
  assert.match(hop.value, /ESMTPS/, 'the protocol comes from the clause, not the comment');
  assert.ok(hop.chips.includes('encrypted hop'));
  assert.ok(!hop.chips.includes('unencrypted hop'));
});

test('a hop that only mentions TLS in a comment is described as exactly that', () => {
  // RFC 3848 says a hop that used TLS should say ESMTPS. One that writes
  // `with ESMTP (using TLSv1.2 …)` is being sloppy rather than plaintext, and
  // calling it unencrypted would be the same kind of wrong in the other
  // direction — so the two are told apart instead of merged.
  const finding = analyse(parseHeaders([
    'From: a@b.example',
    'Received: from mail.example.com by mx.test.com with ESMTP (using TLSv1.2);',
    '        Mon, 17 Aug 2026 09:14:02 -0700 (PDT)',
  ].join('\n'))).find((f) => f.id === 'route');

  const hop = finding.items[0];
  assert.ok(
    hop.chips.some((chip) => /according to a comment/.test(chip)),
    `chips were ${JSON.stringify(hop.chips)}`,
  );
});

test('an address hidden two layers deep is counted, not just displayed', () => {
  // A click tracker puts the destination in base64 and the address inside that
  // in percent-encoding, because it sits in a query parameter. One decode pass
  // found the URL and stopped — so the tool printed the address plainly in the
  // decoded destination and, four lines above it, reported one fewer hidden
  // copy than it had just shown.
  const inner = 'https://shop.example/abmelden?u=reader%40example.org';
  const token = Buffer.from(inner).toString('base64');
  const finding = analyse(parseHeaders([
    'From: Shop <news@shop.example>',
    'To: reader@example.org',
    `List-Unsubscribe: <https://u1.ct.sendgrid.net/ls/click?upn=${token}>`,
  ].join('\n'))).find((f) => f.id === 'recipients');

  const row = finding.items.find((i) => i.label === 'reader@example.org');
  assert.ok(row, 'the recipient row exists');
  assert.ok(
    (row.chips ?? []).some((chip) => /percent-encoded/.test(chip)),
    `the nested copy is named: ${JSON.stringify(row.chips)}`,
  );
});

test('a TLS-shaped hostname does not make a plaintext hop encrypted', () => {
  // `from` in a Received line is the name the connecting client supplied, so a
  // sender picks it. The first version of the comment check tested the whole
  // clause rather than its comments, and `from tls.attacker.example … with SMTP`
  // — no encryption anywhere — was reported as an encrypted hop. A false claim
  // about a security property, from attacker-controlled input, in the direction
  // that reassures.
  const finding = analyse(parseHeaders([
    'From: a@b.example',
    'Received: from tls.attacker.example by mx.example.net with SMTP id 42;',
    '        Mon, 17 Aug 2026 10:00:00 +0000',
  ].join('\n'))).find((f) => f.id === 'route');

  assert.ok(finding.items[0].chips.includes('unencrypted hop'), JSON.stringify(finding.items[0].chips));
});

test('a Microsoft 365 hop declaring TLS1_2 is not called plaintext', () => {
  // Exchange writes `version=TLS1_2`, and the pattern guarding this required a
  // word boundary after the version — which `1` and `_` never provide. So the
  // guard written to stop exactly this did not fire on a single real hop, and
  // every internal Microsoft hop was labelled unencrypted.
  const finding = analyse(parseHeaders([
    'From: a@b.example',
    'Received: from mail.example.com (10.0.0.1) by mx.example.net with Microsoft SMTP Server',
    '        (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7897.20;',
    '        Mon, 17 Aug 2026 10:00:00 +0000',
  ].join('\n'))).find((f) => f.id === 'route');

  assert.ok(
    finding.items[0].chips.some((chip) => /according to a comment/.test(chip)),
    JSON.stringify(finding.items[0].chips),
  );
});

test('an address written in the open is never called a hidden one', () => {
  // A decoder returns the whole value with one part changed, so anything
  // plainly written beside an encoded token rides along in the result. With
  // percent-decoding added, one `%20` anywhere qualified a whole field — and an
  // address sitting in the clear was reported as "never written openly,
  // recoverable only by decoding".
  const finding = analyse(parseHeaders([
    'From: shop@sender.example',
    'To: reader@example.org',
    'X-Campaign: campaign=summer%20sale&to=reader@example.org',
  ].join('\n'))).find((f) => f.id === 'recipients');

  const row = finding.items.find((i) => i.label === 'reader@example.org');
  assert.match(row.value, /Written openly/);
  assert.doesNotMatch(text(finding), /recoverable only by decoding/);
  assert.deepEqual(row.chips ?? [], [], 'no field is named as having hidden it');
  assert.doesNotMatch(finding.lede, /appears \d+ more time/, 'and the count is not inflated');
  assert.doesNotMatch(text(finding), /Carried \d+ further time/);
});

test('an unbalanced parenthesis does not erase the receiving server', () => {
  // Comments are stripped before the clause is read, and an unterminated one
  // swallowed everything after it — so a single stray `(`, written by whoever
  // sent the message, removed the `by` host and the protocol from the route
  // card. The hop rendered as an origin with no destination and no encryption
  // verdict at all. A comment that never closes is not a comment.
  const finding = analyse(parseHeaders([
    'From: a@b.example',
    'Received: from evil.example (unterminated by mx.bank.example with ESMTPS;',
    '        Mon, 17 Aug 2026 10:00:00 +0000',
  ].join('\n'))).find((f) => f.id === 'route');

  // The finding value, not the rendered line: defanging happens in the
  // renderers, so a finding-level test that expects brackets is testing the
  // wrong layer — as the first version of this one was.
  assert.match(finding.items[0].value, /mx\.bank\.example/, 'the receiving server survives');
  assert.match(finding.items[0].value, /ESMTPS/, 'and so does the protocol');
});

test('a semicolon inside a comment is not mistaken for the date separator', () => {
  // RFC 5322 puts exactly one `;` between the route tokens and the date, and
  // everything left of it may carry comments holding semicolons of their own.
  // `lastIndexOf` answered with whichever sat furthest right: a comment written
  // after the date — the shape Postfix and Exim both emit — moved the split
  // past it, and the route card printed the tail of that comment as the hop's
  // timestamp.
  const dated = analyse(parseHeaders([
    'From: a@b.example',
    'Received: from mail.example.com by mx.bank.example with ESMTPS;'
    + ' Mon, 17 Aug 2026 10:00:00 +0000 (envelope-from <c@d.example>; helo=mail.example.com)',
  ].join('\n'))).find((f) => f.id === 'route');

  assert.match(dated.items[0].chips.join(' '), /Mon, 17 Aug 2026 10:00:00/, 'the date is the date');

  // And the harm the same defect does with no date present at all: the split
  // lands inside the comment, `withoutComments` is handed an unbalanced
  // fragment, and `by` and `with` end up on the far side of the separator —
  // the receiving server and the encryption verdict gone from the card again,
  // by the one route the unbalanced-parenthesis fix did not cover.
  const undated = analyse(parseHeaders([
    'From: a@b.example',
    'Received: from evil.example (a;b) by mx.bank.example with ESMTPS',
  ].join('\n'))).find((f) => f.id === 'route');

  assert.match(undated.items[0].value, /mx\.bank\.example/, 'the receiving server survives');
  assert.match(undated.items[0].value, /ESMTPS/, 'and so does the protocol');
  assert.match(undated.items[0].chips.join(' '), /encrypted hop/, 'and the encryption verdict is reached');
});

test('a comment in the route cannot suppress an expired signature', () => {
  // `receivedDates` split on the same naive `lastIndexOf`, so the same stray
  // semicolon left the newest hop unparseable — and with nothing to compare
  // against, "had expired before this message arrived" quietly became "carries
  // an expiry". A sender-written parenthesis removing a security warning.
  const withComment = analyse(parseHeaders([
    'From: a@b.example',
    'DKIM-Signature: v=1; a=rsa-sha256; d=b.example; x=1700000000; b=AAAA',
    'Received: from mail.example.com by mx.bank.example with ESMTPS;'
    + ' Mon, 17 Aug 2026 10:00:00 +0000 (envelope-from <c@d.example>; helo=mail.example.com)',
  ].join('\n'))).find((f) => f.id === 'auth');

  const expiry = withComment.items.find((i) => /expir/i.test(i.label));
  assert.match(expiry.label, /had expired before this message arrived/);
  assert.equal(expiry.level, 'caution');
});

test('a second DKIM signature is described, not hidden behind the first', () => {
  // RFC 6376 §4 permits any number of signatures and ordinary mail uses the
  // permission. Reading only the first meant a sender could put a clean
  // signature above a weak one: `l=`, `x=` and `a=rsa-sha1` on the second went
  // unreported, and the card named the wrong signing domain while doing it.
  const finding = analyse(parseHeaders([
    'From: a@b.example',
    'DKIM-Signature: v=1; a=rsa-sha256; d=harmless.example; b=AAAA',
    'DKIM-Signature: v=1; a=rsa-sha1; d=real-sender.example; l=42; b=BBBB',
  ].join('\n'))).find((f) => f.id === 'auth');

  const shown = text(finding);
  assert.match(shown, /harmless\.example/, 'the first signature is still described');
  assert.match(shown, /real-sender\.example/, 'and so is the second');
  assert.match(shown, /rsa-sha1/, 'the prohibited algorithm is named');
  assert.match(shown, /first 42 bytes/, 'and so is the partial signing');

  // Each warning says which signature it is about, because a weak signature
  // beside a strong one is exactly where an unlabelled row reads as both.
  const sha1 = finding.items.find((i) => /rsa-sha1/.test(i.label));
  assert.match(sha1.label, /real-sender\.example/);

  // But only where that distinction exists. The RSA-and-ed25519 pair one sender
  // publishes so older receivers can still verify shares a domain, and stamping
  // it onto every row would assert a difference that is not there.
  const onePair = analyse(parseHeaders([
    'From: a@b.example',
    'DKIM-Signature: v=1; a=rsa-sha256; d=b.example; t=1755000000; b=AAAA',
    'DKIM-Signature: v=1; a=ed25519-sha256; d=b.example; t=1755000000; b=BBBB',
  ].join('\n'))).find((f) => f.id === 'auth');
  assert.ok(
    onePair.items.every((i) => !/ — /.test(i.label)),
    'one sender, two algorithms: nothing to disambiguate',
  );
});

test('a flood of DKIM signatures is bounded, and the warnings survive it', () => {
  // Reading only the first signature held the row count at one by accident.
  // Reading all of them removed the bound, and the number of signatures is
  // written by the sender: 500 fabricated fields produced 1,500 rows. Ordering
  // the warnings first does not fix that on its own — `l=1` on all 500 makes
  // every one of them "say something" — so the count itself is capped.
  const harmless = Array.from({ length: 50 }, (_, i) =>
    `DKIM-Signature: v=1; a=rsa-sha256; d=s${i}.example; b=X`);
  const finding = analyse(parseHeaders([
    'From: a@b.example',
    ...harmless,
    'DKIM-Signature: v=1; a=rsa-sha1; d=real-sender.example; l=42; b=Y',
  ].join('\n'))).find((f) => f.id === 'auth');

  assert.ok(finding.items.length < 20, `bounded, got ${finding.items.length} rows`);

  // Prepending harmless signatures until the warning falls off the end is the
  // attack, so the ones that say something are described whatever their position.
  const shown = text(finding);
  assert.match(shown, /rsa-sha1/, 'the 51st signature is still described');
  assert.match(shown, /first 42 bytes/);

  // And the quantity is reported rather than silently dropped — a report that
  // shows six of fifty-one without saying so is the narrower answer this whole
  // project is written against.
  const counted = finding.items.find((i) => /51 DKIM signatures/.test(i.label));
  assert.ok(counted, 'the count is stated');
  assert.equal(counted.level, 'caution');

  // Nothing changes for a message signed the ordinary number of times.
  const ordinary = analyse(parseHeaders([
    'From: a@b.example',
    'DKIM-Signature: v=1; a=rsa-sha256; d=b.example; b=AAAA',
    'DKIM-Signature: v=1; a=ed25519-sha256; d=b.example; b=BBBB',
  ].join('\n'))).find((f) => f.id === 'auth');
  assert.equal(ordinary.items.filter((i) => /DKIM signatures/.test(i.label)).length, 0);
});

test('a verdict written below a Received is reported as not the last hop\'s', () => {
  // A receiving server prepends its Authentication-Results above every Received
  // it also writes, so a field below one was added earlier in the chain. The
  // field costs nothing to write: a message carrying nothing but a fabricated
  // `spf=pass; dkim=pass; dmarc=pass` earned the full green headline with three
  // good rows quoting the sender.
  const below = analyse(parseHeaders([
    'From: "PayPal" <service@paypal.com>',
    'Received: from evil.example by mx.example.net with ESMTP; Mon, 17 Aug 2026 10:00:00 +0000',
    'Authentication-Results: mx.example.net; spf=pass; dkim=pass; dmarc=pass',
  ].join('\n'))).find((f) => f.id === 'auth');

  const row = below.items.find((i) => /not written by the last hop/.test(i.label));
  assert.ok(row, 'the position is stated');
  assert.equal(row.level, 'caution');
  assert.equal(row.label, 'These verdicts were not written by the last hop');

  // Reported, not judged: forwarded mail carries the first provider's honest
  // verdict in exactly this position, so the rows above keep their own levels.
  assert.equal(below.items.find((i) => /SPF/.test(i.label)).level, 'good');

  // The ordinary arrangement says nothing at all.
  const above = analyse(parseHeaders([
    'From: "PayPal" <service@paypal.com>',
    'Authentication-Results: mx.example.net; spf=pass; dkim=pass; dmarc=pass',
    'Received: from mail.paypal.com by mx.example.net with ESMTP; Mon, 17 Aug 2026 10:00:00 +0000',
  ].join('\n'))).find((f) => f.id === 'auth');
  assert.equal(above.items.find((i) => /not written by the last hop/.test(i.label)), undefined);

  // And the label names only the rows it applies to. Saying "these verdicts"
  // over a card whose SPF and DMARC came from the delivering server argues
  // against rows that are sound.
  const mixed = analyse(parseHeaders([
    'From: "PayPal" <service@paypal.com>',
    'Authentication-Results: mx.example.net; spf=fail; dmarc=fail',
    'Received: from evil.example by mx.example.net with ESMTP; Mon, 17 Aug 2026 10:00:00 +0000',
    'Authentication-Results: mx.example.net; dkim=pass',
  ].join('\n'))).find((f) => f.id === 'auth');
  assert.equal(
    mixed.items.find((i) => /not written by the last hop/.test(i.label)).label,
    'The DKIM verdict was not written by the last hop',
  );
});

test('ordinary mail does not trip the last-hop check', () => {
  // The false-positive side of the same rule, on the two real headers the suite
  // carries. Both put their Authentication-Results above the first Received,
  // which is what an honest receiver does — and if that ever stops being true
  // of them, this row would appear on mail that did nothing wrong.
  for (const header of [BULK_HEADER, MICROSOFT_HEADER]) {
    const card = analyse(parseHeaders(header)).find((f) => f.id === 'auth');
    assert.equal(
      card.items.find((i) => /not written by the last hop/.test(i.label)),
      undefined,
    );
  }
});

test('an Authentication-Results mid-chain is not accused — internal hops stack above it', () => {
  // The corpus made this concrete: the caution fired on all 25 real messages,
  // 17 of them delivered directly with no forwarding, each time accusing the
  // delivering provider's own results. The reason is the same one already
  // proven wrong for Received-SPF and the Forefront report — a receiver writes
  // its Authentication-Results above the Received it stamps, but internal hops
  // after the check stack their own Received on top, so a genuine, honest A-R
  // sits BELOW the first Received on every ordinary delivery. Only below EVERY
  // Received is the position no receiver produces. The two fixtures this suite
  // carried never had a Received above their A-R, so 431 tests never saw it.
  const midChain = analyse(parseHeaders([
    'From: "PayPal" <service@paypal.com>',
    'Received: by relay.icloud.example (LMTP) id 42; Mon, 17 Aug 2026 10:00:02 +0000',
    'Authentication-Results: mx.icloud.example; spf=pass; dkim=pass; dmarc=pass',
    'Received: from mail.paypal.com by mx.icloud.example; Mon, 17 Aug 2026 10:00:00 +0000',
  ].join('\n'))).find((f) => f.id === 'auth');
  assert.equal(
    midChain.items.find((i) => /not written by the last hop/.test(i.label)),
    undefined,
    'a field with a Received below it was written on the delivery path, not before it',
  );

  // And the genuine target survives the correction: an A-R below EVERY Received
  // — nothing was delivered before the first hop, so a field there was placed by
  // the sender or a forwarder — still earns the caution. Same header, the A-R
  // moved below the last hop.
  const belowEvery = analyse(parseHeaders([
    'From: "PayPal" <service@paypal.com>',
    'Received: by relay.icloud.example (LMTP) id 42; Mon, 17 Aug 2026 10:00:02 +0000',
    'Received: from mail.paypal.com by mx.icloud.example; Mon, 17 Aug 2026 10:00:00 +0000',
    'Authentication-Results: mx.icloud.example; spf=pass; dkim=pass; dmarc=pass',
  ].join('\n'))).find((f) => f.id === 'auth');
  assert.equal(
    belowEvery.items.find((i) => /not written by the last hop/.test(i.label))?.level,
    'caution',
    'a field below every Received is still reported as pre-delivery-path',
  );
});

test('a bad reason row denies the all-clear headline, even when every verdict passed', () => {
  // A generative probe over full messages found this: Microsoft's
  // `compauth=pass reason=000` writes a good compauth row AND a bad row saying
  // the message failed authentication outright. SPF/DKIM/DMARC all passing, the
  // headline read the verdict words and printed "every check passed" directly
  // over that red row. The headline must read the rows the tone already reads.
  const card = analyse(parseHeaders(
    'From: Support <a@sender.example>\n'
    + 'Authentication-Results: mx.example; dkim=pass header.d=sender.example '
    + 'dmarc=pass header.from=sender.example compauth=pass reason=000\n',
  )).find((f) => f.id === 'auth');

  assert.ok(card.items.some((i) => i.level === 'bad'), 'the reason=000 row is bad');
  assert.notEqual(card.title, ALL_CLEAR_TITLE, 'so the card must not headline all-clear');
  assert.equal(card.tone, 'alert', 'and it is toned alert, as any card with a bad row is');
});

test('every verdict passing with no bad row keeps the all-clear headline', () => {
  // The other direction, so the fix is a scalpel and not a hammer: the same
  // shape with a reason code that carries no failure (109 = would have passed
  // under a DMARC record) still earns the headline it has always had.
  const card = analyse(parseHeaders(
    'From: Support <a@sender.example>\n'
    + 'Authentication-Results: mx.example; dkim=pass header.d=sender.example '
    + 'dmarc=pass header.from=sender.example compauth=pass reason=109\n',
  )).find((f) => f.id === 'auth');

  assert.ok(!card.items.some((i) => i.level === 'bad'), 'nothing on the card is bad');
  assert.equal(card.title, ALL_CLEAR_TITLE, 'so the all-clear headline stands');
});

test('a decisive verdict spelled with a space around = is still read as a failure', () => {
  // RFC 8601 §2.2: methodspec is `method [CFWS] "=" [CFWS] result`, so the space
  // is legal. A bare-`=` scanner missed `dkim = fail`, and because the missed
  // verdict was decisive, the two that remained earned "every check passed"
  // printed over a failure the card never showed — the cardinal error (a false
  // reassurance), reachable with one space. No real message uses the spacing,
  // which is why 432 fixtures never caught it; the reproduction did.
  const auth = (ar) => analyse(parseHeaders(
    `From: "PayPal" <service@paypal.com>\nAuthentication-Results: ${ar}\n`
    + 'Received: from mail.paypal.com by mx.icloud.example; Mon, 17 Aug 2026 10:00:00 +0000',
  )).find((f) => f.id === 'auth');

  for (const spacing of ['dkim = fail', 'dkim\t=\tfail', 'dkim =fail', 'dkim= fail']) {
    const card = auth(`mx.icloud.example; spf=pass; ${spacing}; dmarc=pass`);
    assert.notEqual(card.title, ALL_CLEAR_TITLE, `"${spacing}" must lose the headline`);
    assert.ok(
      card.items.some((i) => i.level === 'bad' && /DKIM = fail/.test(i.label)),
      `"${spacing}" must print a DKIM = fail row`,
    );
  }

  // compauth and its reason code ride the same gap: a spaced compauth=fail, or a
  // spaced bad reason under a passing compauth, must still deny the headline.
  const composite = auth('mx; spf=pass; dkim=pass; dmarc=pass; compauth = fail reason=000');
  assert.ok(composite.items.some((i) => i.level === 'bad'), 'compauth = fail is a bad row');
  assert.notEqual(composite.title, ALL_CLEAR_TITLE);

  const spacedReason = auth('mx; spf=pass; dkim=pass; dmarc=pass; compauth=pass reason = 000');
  assert.ok(spacedReason.items.some((i) => i.level === 'bad'), 'reason = 000 is a bad row');
  assert.notEqual(spacedReason.title, ALL_CLEAR_TITLE);

  // Scalpel, not hammer: the ordinary space-free all-pass header is unchanged —
  // the widened `=` must not have started swallowing the next token as a verdict.
  const clean = auth('mx.icloud.example; spf=pass; dkim=pass; dmarc=pass');
  assert.equal(clean.title, ALL_CLEAR_TITLE, 'the space-free all-pass headline still stands');
  assert.ok(!clean.items.some((i) => i.level === 'bad'), 'and nothing on it is bad');
});

test('a score that is not a score is not read as the worst one', () => {
  // Both Microsoft scores were read with `Number()` and then walked down a
  // chain of `<=`. Every comparison against NaN is false, so a field holding
  // anything but a number fell through the whole chain into its last branch —
  // and the last branch is the most severe reading each score has. The tool
  // asserted a verdict from a field that had made no such claim, in the
  // sender's disfavour, which is still the tool being wrong.
  const judgement = (report) =>
    analyse(parseHeaders(`From: a@b.example\nX-Forefront-Antispam-Report: ${report}`))
      .find((f) => f.id === 'judgement');

  const scl = judgement('CIP:1.2.3.4;SCL:abc').items[0];
  assert.match(scl.value, /Not one of the values/);
  assert.doesNotMatch(scl.value, /high confidence/);
  assert.equal(scl.level, 'caution');

  const bcl = judgement('CIP:1.2.3.4;BCL:xyz').items[0];
  assert.match(bcl.value, /Not one of the values/);
  assert.doesNotMatch(bcl.value, /complain about often/);

  // The range is checked as well as the type, for the same reason: `SCL:-5`
  // satisfied `n <= 1` and read as "Scored as not spam". A value outside the
  // vocabulary is not the nearest value inside it.
  assert.match(judgement('SCL:-5').items[0].value, /Not one of the values/);
  assert.match(judgement('SCL:99').items[0].value, /Not one of the values/);

  // And every defined value still reads exactly as it did.
  const reads = (report) => judgement(report).items[0].value;
  assert.match(reads('SCL:-1'), /Filtering was skipped entirely/);
  assert.match(reads('SCL:1'), /Scored as not spam/);
  assert.match(reads('SCL:4'), /no verdict either way/);
  assert.match(reads('SCL:5'), /Scored as spam\./);
  assert.match(reads('SCL:9'), /high confidence/);
  assert.match(reads('BCL:0'), /Not sent in bulk/);
  assert.match(reads('BCL:9'), /complain about often/);
});

test('a signed length that is not a length is not printed as a figure', () => {
  // `l=` is matched by `\d+`, which has no upper bound, and read by `Number`,
  // which does. A 25-digit length printed as 10,000,000,000,000,000,000,000,000
  // — a figure that was not in the header, because everything past 2^53 rounds
  // — and 400 digits printed as "the first ∞ bytes of the body".
  const row = (l) => analyse(parseHeaders(
    `From: a@b.example\nDKIM-Signature: v=1; a=rsa-sha256; d=b.example; l=${l}; b=X`,
  )).find((f) => f.id === 'auth').items.find((i) => !/Signed by domain/.test(i.label));

  for (const huge of ['9'.repeat(25), '9'.repeat(400), '9007199254740993']) {
    const it = row(huge);
    assert.match(it.label, /not a length/);
    assert.doesNotMatch(it.value, /∞/, 'no infinity is printed as a byte count');
    assert.doesNotMatch(it.value, /bytes of the body/);
    assert.equal(it.level, 'caution');
  }

  // l=0 is the opposite mistake: the most serious value the tag can take — no
  // part of the body is signed, so all of it can be replaced while the
  // signature keeps verifying — described by the mildest sentence on the card.
  const zero = row('0');
  assert.match(zero.label, /None of the message body is signed/);
  assert.equal(zero.level, 'caution');

  // Ordinary lengths still read exactly as they did, up to the last one that
  // survives the round trip.
  assert.match(row('42').value, /first 42 bytes/);
  assert.match(row('9007199254740991').value, /9,007,199,254,740,991 bytes/);
});

// ------------------------------------------------------- fields the sender can repeat
//
// get() on a repeatable field reads whichever copy sits first, and the header's
// order is the one part the sender does not fully control: a receiver prepends
// what it writes. These three fields carried a receiver's authority while
// nothing checked whether a receiver wrote them.

test('a Received-SPF below a Received is not quoted as the receiver\'s words', () => {
  // The row's note read "The receiving server's own words, recorded as it made
  // the decision" — for a field that costs a sender one line to write. RFC
  // 7208 §9.1 has the receiver prepend it above its own Received, so one
  // sitting below a Received was written before the delivering hop.
  const forged = analyse(parseHeaders([
    'Received: from mail.evil.example (mail.evil.example [203.0.113.9]) by mx.victim.example with ESMTPS; Mon, 17 Aug 2026 10:00:00 +0000',
    'Received-SPF: pass (mx.victim.example: domain of paypal.com designates 203.0.113.9 as permitted sender)',
    'From: security@paypal.com',
    'To: reader@example.org',
  ].join('\n'))).find((f) => f.id === 'auth');

  const row = forged.items.find((i) => /^Received-SPF/.test(i.label));
  assert.equal(row.level, 'caution');
  assert.match(row.note, /below every Received/);
  assert.doesNotMatch(row.note, /receiving server's own words/);

  // The side that must stay quiet: in its genuine position, above the first
  // Received, the attribution stands and no caution is raised.
  const genuine = analyse(parseHeaders([
    'Received-SPF: pass (mx.victim.example: domain of b.example designates 203.0.113.9 as permitted sender)',
    'Received: from mail.b.example (mail.b.example [203.0.113.9]) by mx.victim.example with ESMTPS; Mon, 17 Aug 2026 10:00:00 +0000',
    'From: a@b.example',
  ].join('\n'))).find((f) => f.id === 'auth');

  const genuineRow = genuine.items.find((i) => /^Received-SPF/.test(i.label));
  assert.notEqual(genuineRow.level, 'caution');
  assert.match(genuineRow.note, /receiving server's own words/);
});

test('a Received-SPF mid-chain is not accused — internal hops stack above it', () => {
  // Found on a real, directly delivered iCloud message the day the check
  // shipped: iCloud's smtpin host records Received-SPF, then its internal
  // mailgateway stamps a Received on top, so the receiver's own field sits
  // below the first Received on every ordinary delivery. The first cut asked
  // "below the first Received?" and marked it — a fix inheriting its example,
  // where the probe had only ever built one-Received headers. Only a field
  // below EVERY Received is one no server on the path can have written.
  const midChain = analyse(parseHeaders([
    'Received: from smtpin.mx.example by gateway.mx.example with SMTP; Wed, 19 Aug 2026 11:02:57 +0000',
    'Received-SPF: pass (mx.example: domain of b.example designates 203.0.113.9 as permitted sender)',
    'Received: from mail.b.example (mail.b.example [203.0.113.9]) by smtpin.mx.example with ESMTPS; Wed, 19 Aug 2026 11:02:51 +0000',
    'From: a@b.example',
  ].join('\n'))).find((f) => f.id === 'auth');

  const row = midChain.items.find((i) => /^Received-SPF/.test(i.label));
  assert.notEqual(row.level, 'caution');
  assert.match(row.note, /receiving server's own words/);
});

test('a forefront report below a Received is marked as an earlier hop\'s', () => {
  // A message that never crossed Microsoft, carrying a fabricated
  // CAT:NONE;SCL:1, rendered "Scored as not spam" with nothing beside it —
  // Microsoft's authority lent to a sentence the sender wrote. Any header the
  // sender writes ends up below the first Received, because the receiving
  // server prepends its own; that is where the mark hangs.
  const forged = analyse(parseHeaders([
    'Received: from mail.evil.example by mx.victim.example with ESMTPS; Mon, 17 Aug 2026 10:00:00 +0000',
    'X-Forefront-Antispam-Report: CIP:203.0.113.9;CTRY:US;CAT:NONE;SCL:1;DIR:INB',
    'From: a@b.example',
  ].join('\n')));

  const rows = forged.flatMap((f) => f.items);
  const mark = rows.find((i) => /not written by any hop above/.test(i.label) && /Forefront/.test(i.value));
  assert.ok(mark, 'the position is pointed out');
  assert.equal(mark.level, 'caution');

  // The genuine shape — the real fixture has the report above the first
  // Received — carries no such row.
  const genuineRows = msReport().flatMap((f) => f.items);
  assert.ok(!genuineRows.some((i) => /not written by any hop above/.test(i.label)));

  // And the shape real M365 mail actually has: internal prod.outlook.com hops
  // stamp their Received above the report after filtering, so the receiver's
  // own report sits mid-chain on every ordinary delivery. Measured for the
  // same structure on a real iCloud Received-SPF — "below the first Received"
  // would cry wolf here.
  const midChain = analyse(parseHeaders([
    'Received: from internal.prod.example by mailbox.prod.example with SMTP; Mon, 17 Aug 2026 10:00:02 +0000',
    'X-Forefront-Antispam-Report: CIP:203.0.113.9;CTRY:US;CAT:NONE;SCL:1;DIR:INB',
    'Received: from mail.b.example by protection.example with ESMTPS; Mon, 17 Aug 2026 10:00:00 +0000',
    'From: a@b.example',
  ].join('\n'))).flatMap((f) => f.items);
  assert.ok(!midChain.some((i) => /not written by any hop above/.test(i.label)));
});

test('a second forefront report is named, not silently unreachable', () => {
  // With two reports the first is the newest — a receiver prepends — so
  // reading it is right; reading it silently was not. The probe that found
  // this put CAT:NONE;SCL:1 above Microsoft's real CAT:PHSH;SCL:9 and the
  // phishing verdict became unreachable without a trace.
  const rows = analyse(parseHeaders([
    'X-Forefront-Antispam-Report: CIP:203.0.113.9;CTRY:US;CAT:NONE;SCL:1;DIR:INB',
    'Received: from a by b with ESMTP; Mon, 17 Aug 2026 10:00:00 +0000',
    'X-Forefront-Antispam-Report: CIP:198.51.100.7;CTRY:RU;CAT:PHSH;SCL:9;DIR:INB',
    'From: a@b.example',
  ].join('\n'))).flatMap((f) => f.items);

  const dup = rows.find((i) => /X-Forefront-Antispam-Report appears 2 times/.test(i.label));
  assert.ok(dup, 'the second copy is pointed out');
  assert.equal(dup.level, 'caution');
  assert.match(dup.value, /first is the newest/);

  // One report — the ordinary case — says nothing about copies.
  const single = msReport().flatMap((f) => f.items);
  assert.ok(!single.some((i) => /appears \d+ times/.test(i.label) && /Forefront/.test(i.label)));
});

test('a receiver\'s copy of the whole DMARC record is read, never printed raw', () => {
  // iCloud writes X-DMARC-Policy carrying the record it fetched, verbatim. A
  // real message rendered the whole thing — "v=DMARC1; p=reject; adkim=s;
  // aspf=r; rf=afrf; pct=100;." — as the value of "Published DMARC policy",
  // where the reader was owed one word.
  const rows = analyse(parseHeaders([
    'From: a@b.example',
    'Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass',
    'X-DMARC-Policy: v=DMARC1; p=reject; adkim=s; aspf=r; rf=afrf; sp=none; pct=100;',
  ].join('\n'))).find((f) => f.id === 'auth').items;

  const row = rows.find((i) => i.label === 'Published DMARC policy');
  assert.match(row.value, /^reject\./);
  assert.doesNotMatch(row.value, /v=DMARC1|adkim|rf=|pct/);
  // The record is the source for the policy tags too, not just the p= word.
  assert.match(row.value, /Subdomains: none/);

  // A receiver that writes just the bare word is still read.
  const bare = analyse(parseHeaders([
    'From: a@b.example',
    'Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass',
    'X-DMARC-Policy: quarantine',
  ].join('\n'))).find((f) => f.id === 'auth').items;
  assert.match(bare.find((i) => i.label === 'Published DMARC policy').value, /^quarantine\./);
});

test('a recipient named only in Original-Recipient is named in the clear', () => {
  // From a real iCloud message: no To: at all, the recipient openly in
  // Original-Recipient, plus encoded copies. One card said "no recipient is
  // named in the clear, so there is nothing to compare the encoded copies
  // against" while the card beneath it compared those copies against the
  // openly written address it had just read out of Original-Recipient — and
  // the recipient card's lede leaned on "the visible To: field" of a message
  // that had none.
  const findings = analyse(parseHeaders([
    'From: news@list.example',
    'Received: from a by b with ESMTPS; Mon, 17 Aug 2026 10:00:00 +0000',
    'Original-Recipient: rfc822;alice@b.example',
    'List-Unsubscribe: <https://x.example/u?e=YWxpY2VAYi5leGFtcGxl>',
  ].join('\n')));

  const completeness = findings.find((f) => f.id === 'completeness');
  if (completeness) {
    assert.ok(
      !completeness.items.some((i) => /named in the clear|nothing to compare/.test(`${i.label} ${i.value}`)),
      'the recipient IS named in the clear, one field over',
    );
  }

  const recipients = findings.find((f) => f.id === 'recipients');
  assert.ok(recipients, 'the encoded copy is still found and attributed');
  assert.match(recipients.lede, /There is no To: field/);
  assert.doesNotMatch(recipients.lede, /visible To: field/);

  // The still-working side: with a To: present, the original lede stands.
  const withTo = analyse(parseHeaders([
    'From: news@list.example',
    'To: alice@b.example',
    'Received: from a by b with ESMTPS; Mon, 17 Aug 2026 10:00:00 +0000',
    'List-Unsubscribe: <https://x.example/u?e=YWxpY2VAYi5leGFtcGxl>',
  ].join('\n'))).find((f) => f.id === 'recipients');
  assert.match(withTo.lede, /visible To: field/);
});

test('two Return-Path lines naming different addresses are pointed out', () => {
  // Return-Path is not a singleton the way From is — each final delivery
  // prepends one, so two copies can be honest. Two copies naming different
  // bounce addresses while nothing says so is the reader being shown one
  // address on a message that carries another.
  const rows = analyse(parseHeaders([
    'Return-Path: <bounce@legit.example>',
    'Return-Path: <collector@evil.example>',
    'From: a@legit.example',
    'Received: from a by b with ESMTPS; Mon, 17 Aug 2026 10:00:00 +0000',
  ].join('\n'))).flatMap((f) => f.items);

  const row = rows.find((i) => /Return-Path appears 2 times/.test(i.label));
  assert.ok(row, 'the disagreement is reported');
  assert.equal(row.level, 'caution');
  assert.match(row.value, /collector@evil\.example/);

  // The honest shapes stay quiet: one copy, and two identical copies from a
  // message delivered twice.
  const once = analyse(parseHeaders('Return-Path: <b@x.example>\nFrom: a@x.example\n')).flatMap((f) => f.items);
  assert.ok(!once.some((i) => /Return-Path appears/.test(i.label)));
  const twiceSame = analyse(parseHeaders(
    'Return-Path: <b@x.example>\nReturn-Path: <b@x.example>\nFrom: a@x.example\n',
  )).flatMap((f) => f.items);
  assert.ok(!twiceSame.some((i) => /Return-Path appears/.test(i.label)));
});
