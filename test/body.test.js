// The body findings: what the links in a message claim, and where they go.
//
// Both directions throughout — the case that must fire AND the case that must
// stay quiet. A warning printed over honest mail is this project's other
// failure mode, and it is tested as seriously as the miss.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { analyseBody } from '../js/body.js';
import { parseParts, splitMessage } from '../js/mime.js';
import { createRenderer } from '../js/terminal.js';
import { parseHeaders } from '../js/unfold.js';

const htmlPart = (html) => [{
  contentType: 'text/html', charset: 'utf-8', disposition: null, filename: null,
  transferEncoding: null, bytesDeclared: html.length, text: html, head: [], clipped: false,
}];

const plainPart = (text) => [{
  contentType: 'text/plain', charset: 'utf-8', disposition: null, filename: null,
  transferEncoding: null, bytesDeclared: text.length, text, head: [], clipped: false,
}];

const linkCard = (parts) => analyseBody(parts).find((f) => f.id === 'body-links');
const flat = (finding) => finding.items.map((i) => `${i.label} :: ${i.value}`).join('\n');

// ------------------------------------------------------------- text vs href

test('text claiming one domain over a link to another is the top finding', () => {
  const card = linkCard(htmlPart('<a href="https://evil.example/login">https://www.paypal.com/security</a>'));
  const row = card.items.find((i) => i.level === 'bad');
  assert.ok(row, 'a bad row exists');
  assert.match(row.label, /paypal\.com/);
  assert.match(row.label, /evil\.example/);
  assert.equal(card.tone, 'alert');
});

test('a bare familiar domain in the text is a claim too', () => {
  const card = linkCard(htmlPart('<a href="https://evil.example/x">Visit paypal.com for details</a>'));
  assert.ok(card.items.some((i) => i.level === 'bad' && /paypal\.com/.test(i.label)));
});

test('the same registrable domain is never a mismatch', () => {
  // www.paypal.com vs paypal.com is one party; comparing strings would accuse
  // half of all honest mail.
  const card = linkCard(htmlPart('<a href="https://paypal.com/help">www.paypal.com</a>'));
  assert.equal(card.items.some((i) => i.level === 'bad'), false, flat(card));
});

test('a subdomain of the claimed domain is never a mismatch', () => {
  const card = linkCard(htmlPart('<a href="https://email.paypal.com/r/x">paypal.com</a>'));
  assert.equal(card.items.some((i) => i.level === 'bad'), false, flat(card));
});

test('a decodable redirect whose destination matches the text stays quiet', () => {
  // The href hops through a tracker, but the base64 in its path decodes to
  // the very domain the text names: the claim is true, and saying otherwise
  // would put a warning on every tracked newsletter.
  const destination = Buffer.from('https://shop.example/sale').toString('base64url');
  const card = linkCard(htmlPart(
    `<a href="https://click.tracker.example/V${destination}">shop.example</a>`,
  ));
  assert.equal(card.items.some((i) => i.level === 'bad'), false, flat(card));
});

test('an unreadable hop through a known platform is caution, not bad', () => {
  const card = linkCard(htmlPart(
    '<a href="https://click.sendgrid.net/opaque-token-here">paypal.com</a>',
  ));
  const row = card.items.find((i) => /paypal\.com/.test(i.label));
  assert.ok(row, 'the claim is still reported');
  assert.equal(row.level, 'caution');
  assert.match(row.label, /through/i);
});

test('a product name with a dot is not a domain claim', () => {
  // `Node.js` ends in a syntactically valid TLD that no reader's bank uses;
  // accusing it would put a false warning on every tech newsletter.
  const card = linkCard(htmlPart('<a href="https://medium.com/article">Node.js tutorial</a>'));
  assert.equal(card.items.some((i) => i.level === 'bad'), false, flat(card));
});

test('plain link text over any destination stays quiet', () => {
  const card = linkCard(htmlPart('<a href="https://anything.example/x">Read the full story</a>'));
  assert.equal(card.items.some((i) => i.level === 'bad'), false, flat(card));
});

// ----------------------------------------------------------------- the tells

test('a javascript: link is bad', () => {
  const card = linkCard(htmlPart('<a href="javascript:alert(document.cookie)">click</a>'));
  assert.ok(card.items.some((i) => i.level === 'bad' && /javascript:/.test(i.label)));
});

test('a data: link is bad', () => {
  const card = linkCard(htmlPart('<a href="data:text/html;base64,AAAA">open</a>'));
  assert.ok(card.items.some((i) => i.level === 'bad' && /data:/.test(i.label)));
});

test('a form in a mail body is bad, named with its action', () => {
  const card = linkCard(htmlPart('<form action="https://collect.example/pw"><input></form>'));
  const row = card.items.find((i) => /form/i.test(i.label));
  assert.equal(row.level, 'bad');
  assert.match(row.value, /collect\.example/);
});

test('a bare IP destination is bad', () => {
  const card = linkCard(htmlPart('<a href="http://203.0.113.7/pay">invoice</a>'));
  assert.ok(card.items.some((i) => i.level === 'bad' && /IP address/.test(i.label)));
});

test('a punycode hostname is bad', () => {
  const card = linkCard(htmlPart('<a href="https://xn--pypal-4ve.example/x">account</a>'));
  assert.ok(card.items.some((i) => i.level === 'bad' && /Punycode/.test(i.label)));
});

test('a login-shaped path is caution, with the domain named', () => {
  const card = linkCard(htmlPart('<a href="https://service.example/account/login?next=x">sign in</a>'));
  const row = card.items.find((i) => /login or payment/.test(i.label));
  assert.equal(row.level, 'caution');
  assert.match(row.note, /service\.example/);
});

test('bidi controls in the visible text of a link are reported', () => {
  const card = linkCard(htmlPart('<a href="https://evil.example/x">moc.elppa&#x202E;</a>'));
  assert.ok(card.items.some((i) => i.level === 'bad' && /reverses the direction/.test(i.value)));
});

test('userinfo before the hostname is bad', () => {
  const card = linkCard(htmlPart('<a href="https://paypal.com@evil.example/x">account</a>'));
  assert.ok(card.items.some((i) => i.level === 'bad' && /Credentials embedded/.test(i.label)));
});

// ------------------------------------------------------------- the summary

test('destinations are tallied by registrable domain, warnings never crowded out', () => {
  const many = Array.from({ length: 300 }, (_, i) => `<a href="https://news.example/a${i}">story</a>`).join('');
  const card = linkCard(htmlPart(
    `${many}<a href="https://evil.example/login">https://www.paypal.com</a>`,
  ));
  assert.ok(card.items.some((i) => i.level === 'bad'), 'the one warning row survives 300 links');
  const summary = card.items.find((i) => i.label === 'news.example');
  assert.match(summary.value, /300 links/);
});

test('a redirect target is credited to where you land, via where you hop', () => {
  const destination = Buffer.from('https://shop.example/sale').toString('base64url');
  const card = linkCard(htmlPart(
    `<a href="https://click.tracker.example/V${destination}">sale</a>`,
  ));
  const summary = card.items.find((i) => i.label === 'shop.example');
  assert.ok(summary, flat(card));
  assert.match(summary.value, /through.*tracker\.example/);
});

test('plain-text URLs are read from text/plain parts', () => {
  const card = linkCard(plainPart('Read more: https://news.example/story and http://203.0.113.7/x'));
  assert.ok(card.items.some((i) => i.label === 'news.example'));
  assert.ok(card.items.some((i) => /IP address/.test(i.label)));
});

test('every judged host is offered to the blocklist bridge', () => {
  const card = linkCard(htmlPart('<a href="https://a.example/x">a</a><a href="https://b.example/y">b</a>'));
  assert.deepEqual([...card.hostsToCheck].sort(), ['a.example', 'b.example']);
});

test('a body with no links at all produces no card', () => {
  assert.equal(linkCard(plainPart('Nothing to see here, no URLs at all.')), undefined);
  assert.equal(linkCard(htmlPart('<p>Just prose.</p>')), undefined);
});

test('mailto and cid links are not journeys and produce no rows', () => {
  const card = linkCard(htmlPart(
    '<a href="mailto:someone@example.org">write</a><a href="cid:logo">logo</a>'
    + '<a href="https://real.example/x">real</a>',
  ));
  assert.equal(card.items.some((i) => /mailto|cid/.test(i.label)), false);
  assert.ok(card.items.some((i) => i.label === 'real.example'));
});

// -------------------------------------------------------------- body-only

test('a body-only paste leads with the honest notice', () => {
  const findings = analyseBody(plainPart('https://news.example/x'), { bodyOnly: true });
  assert.equal(findings[0].id, 'body-only');
  assert.match(findings[0].lede, /cannot be answered here/);
  assert.ok(findings.some((f) => f.id === 'body-links'));
});

test('a fault in the body costs the body sections, each reported by its own guard', () => {
  // Fault isolation is inherited from guardSection; a part whose text is a
  // getter that throws is the cheapest way to prove the boundary holds. Both
  // body producers read the poisoned part, so both report — as faults in
  // this tool, never as a crash.
  const poisoned = [{
    contentType: 'text/html',
    get text() { throw new Error('deliberate'); },
  }];
  const findings = analyseBody(poisoned);
  assert.ok(findings.length >= 2, 'every section that read the part reports');
  for (const finding of findings) {
    assert.match(finding.items[0].label, /failed/);
    assert.equal(finding.items[0].level, 'fault');
  }
});

test('a body-only HTML paste judges the hrefs, not the decoy text', () => {
  // The end-to-end shape of the bug the type default hid: pasted HTML with no
  // header, a link whose visible text claims dhl.de while its href is a bare
  // IP. Read as plain text this tallied "dhl.de — 1 link" and said nothing
  // about the IP — a false reassurance on exactly the message that matters.
  const { headerText, bodyText, bodyOnly } = splitMessage(
    '<html><body><a href="http://203.0.113.44/track">https://dhl.de/verfolgung</a></body></html>',
  );
  assert.equal(bodyOnly, true);
  const { parts } = parseParts(parseHeaders(headerText), bodyText);
  const findings = analyseBody(parts, { bodyOnly });
  const card = findings.find((f) => f.id === 'body-links');
  assert.ok(card.items.some((i) => i.level === 'bad' && /IP address/.test(i.label)), flat(card));
  assert.ok(card.items.some((i) => i.level === 'bad' && /dhl\.de/.test(i.label)), flat(card));
  assert.equal(card.items.some((i) => i.label === 'dhl.de'), false, 'the decoy is not tallied as a destination');
});

test('an address literal is named whole, never as two octets in a domain suit', () => {
  // registrableDomain reads labels, so handed 203.0.113.44 it answers
  // "113.44" — which the card then printed as where the link goes.
  const card = linkCard(htmlPart('<a href="http://203.0.113.44/track">paypal.com</a>'));
  const mismatch = card.items.find((i) => /The text says/.test(i.label));
  assert.match(mismatch.label, /203\.0\.113\.44/);
  assert.doesNotMatch(flat(card), /(?<!\d\.)113\.44/, 'no two-octet pseudo-domain anywhere on the card');
  assert.ok(card.items.some((i) => i.label === '203.0.113.44'), 'the tally names the address whole');
});

// -------------------------------------------- what reading and clicking reveals

const HEADERS = parseHeaders([
  'From: news@sender.example',
  'To: maja.beispiel@example.org',
  'Feedback-ID: 31859940abc:campaign7:news:esp',
  'Return-Path: <bounces+31859940abc-maja.beispiel=example.org@mail.sender.example>',
  'Message-ID: <mid-9f8e7d6c5b4a3210@mail.sender.example>',
].join('\n'));

const trackingCard = (parts, headers = HEADERS) =>
  analyseBody(parts, { headers }).find((f) => f.id === 'body-tracking');

test('a 1x1 image is named a tracking pixel, with its host', () => {
  const card = trackingCard(htmlPart('<img src="https://track.example/o.gif" width="1" height="1">'));
  const row = card.items.find((i) => /tracking pixel/i.test(i.label));
  assert.equal(row.level, 'caution');
  assert.match(row.value, /track\.example/);
  assert.match(row.value, /Nothing was loaded here/);
});

test('a pixel carrying an opaque id is marked as identifying this copy', () => {
  const card = trackingCard(htmlPart(
    '<img src="https://track.example/o.gif?u=SdBcviQ29tZXMtaGVyZTAx" width="1" height="1">',
  ));
  const row = card.items.find((i) => /tracking pixel/i.test(i.label));
  assert.ok(row.chips.some((c) => /unique to this copy/.test(c)));
  assert.equal(row.emphasis, true);
});

test('an ordinary product image is not a pixel, but its host is counted', () => {
  const card = trackingCard(htmlPart('<img src="https://img.shop.example/shoe.jpg" width="480" height="320">'));
  assert.equal(card.items.some((i) => /tracking pixel/i.test(i.label)), false);
  const row = card.items.find((i) => /external image/.test(i.label));
  assert.match(row.value, /shop\.example/);
  assert.match(row.value, /reports your IP address/);
});

test('cid: and data: images load nothing and are not counted as external', () => {
  const card = trackingCard(htmlPart('<img src="cid:logo" width="1" height="1"><img src="data:image/gif;base64,AAAA">'));
  assert.equal(card, undefined);
});

test('the reader\'s address is found open inside a link', () => {
  const card = trackingCard(htmlPart(
    '<a href="https://news.example/read?user=maja.beispiel@example.org">read</a>',
  ));
  const row = card.items.find((i) => /Your address travels inside the links/.test(i.label));
  assert.match(row.value, /open/);
  assert.match(row.value, /news\.example/);
});

test('the percent-encoded spelling is found too', () => {
  const card = trackingCard(htmlPart(
    '<a href="https://t.example/c?u=maja.beispiel%40example.org">read</a>',
  ));
  const row = card.items.find((i) => /address travels/.test(i.label));
  assert.match(row.value, /percent-encoded/);
});

test('the base64 spellings are found, both alphabets', () => {
  const standard = Buffer.from('maja.beispiel@example.org').toString('base64').replace(/=+$/, '');
  const urlsafe = standard.replace(/\+/g, '-').replace(/\//g, '_');
  const card = trackingCard(htmlPart(
    `<a href="https://t.example/c?u=${urlsafe}">read</a>`,
  ));
  const row = card.items.find((i) => /address travels/.test(i.label));
  assert.ok(row, 'the base64url spelling is found');
  assert.match(row.value, /base64/);
});

test('someone else\'s address in a link is not called yours', () => {
  const card = trackingCard(htmlPart(
    '<a href="https://t.example/c?u=someone.else@another.example">read</a>',
  ));
  assert.equal(card?.items.some((i) => /address travels/.test(i.label)) ?? false, false);
});

test('with no header there is no address to search for, and no claim is made', () => {
  const card = trackingCard(
    htmlPart('<a href="https://t.example/c?u=maja.beispiel@example.org">read</a>'),
    [],
  );
  assert.equal(card?.items.some((i) => /address travels/.test(i.label)) ?? false, false);
});

test('a Feedback-ID segment recurring in a link query is the join, named', () => {
  const card = trackingCard(htmlPart(
    '<a href="https://click.sender.example/r?fid=31859940abc&x=1">offer</a>',
  ));
  const row = card.items.find((i) => /recurs inside the links/.test(i.label));
  assert.match(row.value, /31859940abc/);
  assert.match(row.value, /Feedback-ID/);
  assert.match(row.value, /ties the message in your mailbox to your click/);
});

test('the Message-ID local part recurring in a link is a join too', () => {
  const card = trackingCard(htmlPart(
    '<a href="https://click.sender.example/open/mid-9f8e7d6c5b4a3210">view online</a>',
  ));
  assert.ok(card.items.some((i) => /recurs inside the links/.test(i.label) && /Message-ID/.test(i.value)));
});

test('an id that merely echoes the hostname joins nothing', () => {
  // The token must sit in the path or query — matching the hostname would
  // accuse every link on the sender's own numbered subdomain.
  const headers = parseHeaders([
    'From: news@sender.example',
    'Feedback-ID: em1234567890:c:n:e',
  ].join('\n'));
  const card = analyseBody(
    htmlPart('<a href="https://em1234567890.sender.example/plain">read</a>'),
    { headers },
  ).find((f) => f.id === 'body-tracking');
  assert.equal(card?.items.some((i) => /recurs inside/.test(i.label)) ?? false, false);
});

test('a wordlike segment without digits never qualifies as an id', () => {
  const headers = parseHeaders([
    'From: news@sender.example',
    'Feedback-ID: newsletterweekly:campaign:news:esp',
  ].join('\n'));
  const card = analyseBody(
    htmlPart('<a href="https://x.example/read/newsletterweekly">read</a>'),
    { headers },
  ).find((f) => f.id === 'body-tracking');
  assert.equal(card?.items.some((i) => /recurs inside/.test(i.label)) ?? false, false);
});

test('hex tokens of digest length are offered to the hash bridge', () => {
  const card = trackingCard(htmlPart(
    `<a href="https://t.example/u/${'ab12'.repeat(16)}">read</a>`,
  ));
  assert.ok(card.hashCheck, 'the card carries candidates');
  assert.equal(card.hashCheck.tokens[0].token, 'ab12'.repeat(16));
  assert.ok(card.hashCheck.addresses.includes('maja.beispiel@example.org'));
});

test('hex inside a longer hex run is not a candidate', () => {
  const card = trackingCard(htmlPart(
    `<a href="https://t.example/u/${'a'.repeat(128)}">read</a><img src="https://t.example/p.gif" width="1" height="1">`,
  ));
  assert.equal(card.hashCheck, null);
});

test('a body with no tracking shape at all yields no tracking card', () => {
  assert.equal(trackingCard(htmlPart('<p>Just prose, no links, no images.</p>')), undefined);
});

// ------------------------------------------------------------- attachments

const attachment = (over = {}) => [{
  contentType: 'application/pdf', charset: null, disposition: 'attachment',
  filename: 'rechnung.pdf', transferEncoding: 'base64', bytesDeclared: 90210,
  text: null, head: [0x25, 0x50, 0x44, 0x46, 0x2d, 0x31], clipped: false,
  ...over,
}];

const attachmentCard = (parts) => analyseBody(parts).find((f) => f.id === 'attachments');

test('an attachment is inventoried: name, declared type, size', () => {
  const card = attachmentCard(attachment());
  const row = card.items[0];
  assert.equal(row.label, 'rechnung.pdf');
  assert.match(row.value, /application\/pdf/);
  assert.match(row.value, /90,210 bytes/);
  assert.equal(row.level, null, 'a PDF that is a PDF earns no warning');
});

test('a double extension is bad, and the trick is explained', () => {
  const card = attachmentCard(attachment({ filename: 'rechnung.pdf.exe' }));
  const row = card.items[0];
  assert.equal(row.level, 'bad');
  assert.match(row.note, /two extensions/);
  assert.equal(card.tone, 'alert');
});

test('a bare executable extension is bad', () => {
  const card = attachmentCard(attachment({ filename: 'update.js', contentType: 'text/javascript' }));
  assert.equal(card.items[0].level, 'bad');
  assert.match(card.items[0].note, /runs rather than opens/);
});

test('an archive is a caution, not an accusation', () => {
  const card = attachmentCard(attachment({ filename: 'fotos.zip', contentType: 'application/zip', head: [0x50, 0x4b, 0x03, 0x04] }));
  assert.equal(card.items[0].level, 'caution');
  assert.match(card.items[0].note, /not examined/);
});

test('a declared PDF whose first bytes are a program is code, said plainly', () => {
  const card = attachmentCard(attachment({ head: [0x4d, 0x5a, 0x90, 0x00] }));
  const row = card.items[0];
  assert.equal(row.level, 'bad');
  assert.match(row.note, /first bytes are those of a Windows program/);
});

test('a declared PDF that begins like a PNG is a mismatch, stated as one', () => {
  const card = attachmentCard(attachment({ head: [0x89, 0x50, 0x4e, 0x47] }));
  const row = card.items[0];
  assert.equal(row.level, 'caution');
  assert.match(row.note, /those of a PNG image, not a PDF/);
});

test('unknown first bytes accuse nobody', () => {
  const card = attachmentCard(attachment({ head: [0x01, 0x02, 0x03, 0x04] }));
  assert.equal(card.items[0].level, null);
});

test('a docx is a zip by construction, never a mismatch', () => {
  const card = attachmentCard(attachment({
    filename: 'brief.docx',
    contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    head: [0x50, 0x4b, 0x03, 0x04],
  }));
  assert.equal(card.items[0].level, null, 'PK bytes are what a docx should carry');
});

test('inline furniture stays off the inventory; text parts too', () => {
  assert.equal(attachmentCard([
    { contentType: 'image/png', disposition: 'inline', filename: 'logo.png', head: [], text: null },
    { contentType: 'text/plain', disposition: null, filename: null, head: [], text: 'hello' },
  ]), undefined);
});

test('an unnamed opaque part is still inventoried', () => {
  const card = attachmentCard(attachment({ filename: null }));
  assert.equal(card.items[0].label, '(unnamed)');
});

// ------------------------------------------------------ plain/html divergence

const alternative = (plainText, html) => [
  { contentType: 'text/plain', disposition: null, filename: null, text: plainText, head: [], clipped: false },
  { contentType: 'text/html', disposition: null, filename: null, text: html, head: [], clipped: false },
];

const divergenceCard = (parts) => analyseBody(parts).find((f) => f.id === 'divergence');

test('a destination only the HTML links to is named', () => {
  const card = divergenceCard(alternative(
    'Read more: https://news.example/story',
    '<a href="https://news.example/story">story</a><a href="https://hidden.example/collect">.</a>',
  ));
  assert.match(card.items[0].label, /1 destination only the HTML links to/);
  assert.match(card.items[0].value, /hidden\.example/);
  assert.doesNotMatch(card.items[0].value, /news\.example/);
  assert.equal(card.items[0].level, 'caution');
});

test('matching versions diverge nowhere and say nothing', () => {
  assert.equal(divergenceCard(alternative(
    'Read: https://news.example/story',
    '<a href="https://news.example/other-path">story</a>',
  )), undefined, 'same registrable domain is the same destination');
});

test('a decodable redirect counts as where it lands, not where it hops', () => {
  const destination = Buffer.from('https://news.example/story').toString('base64url');
  assert.equal(divergenceCard(alternative(
    'Read: https://news.example/story',
    `<a href="https://click.tracker.example/V${destination}">story</a>`,
  )), undefined, 'the tracked link and its plain twin are one destination');
});

test('with only one version present there is nothing to compare', () => {
  assert.equal(divergenceCard([
    { contentType: 'text/html', disposition: null, filename: null, text: '<a href="https://x.example/a">a</a>', head: [] },
  ]), undefined);
});

// ------------------------------------------------- the rendering invariants

test('body findings render with no control byte and no live URL', () => {
  const { headerText, bodyText } = splitMessage([
    'From: a@sender.example',
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<a href="https://evil.example/login?u=1">https://www.paypal.com&#x202E;</a>',
    '<form action="https://collect.example/pw"></form>',
  ].join('\n'));
  const { parts } = parseParts(parseHeaders(headerText), bodyText);
  const findings = analyseBody(parts);

  for (const colour of [false, true]) {
    const out = createRenderer({ colour, width: 80 }).render(findings);
    const senderBytes = out.replace(/\x1b\[[0-9;]*m/g, '');
    assert.doesNotMatch(senderBytes, /(?![\t\n])[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}]/u);
    assert.doesNotMatch(out, /https?:\/\//, 'no clickable URL survives defanging');
    assert.match(out, /hxxps:\/\/evil\[\.\]example/, 'the destination is still legible');
  }
});
