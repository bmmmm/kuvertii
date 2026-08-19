import assert from 'node:assert/strict';
import { test } from 'node:test';

import { analyse, guardSection } from '../js/findings.js';
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
