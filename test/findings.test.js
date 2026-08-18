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
