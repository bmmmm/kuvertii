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

// ------------------------------------------- urls a client turns into links

test('a url written into the visible text of an HTML part is a destination', () => {
  // Only hrefs and form actions were read, so a message whose one destination
  // was typed out in a paragraph — which every client autolinks, and which a
  // great deal of ordinary bulk mail does — produced no link card at all. The
  // real binary printed nothing whatever about tracker.evil.example.
  const card = linkCard(htmlPart('<p>Restore it here:</p><p>https://tracker.evil.example/click?u=abc</p>'));
  assert.ok(card, 'the card exists at all');
  assert.match(flat(card), /evil\.example/);
});

test('a link\'s own text is a claim, never counted as a place the message goes', () => {
  // The other half of the rule above: the anchor text is what the link says
  // about itself, judged against the href by the mismatch check. Collecting it
  // as a destination too would put the decoy back on the card as somewhere the
  // reader can actually land.
  const card = linkCard(htmlPart('<a href="https://evil.example/login">https://www.paypal.com/security</a>'));
  const destinations = card.items.filter((i) => /^\d+ links?/.test(String(i.value))).map((i) => i.label);
  assert.deepEqual(destinations, ['evil.example']);
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
  assert.match(findings[0].lede, /is read below/);
  assert.ok(findings.some((f) => f.id === 'body-links'));
});

test('the notice does not promise a reading that did not happen', () => {
  // "What the body itself says is read below" was printed unconditionally.
  // Under --headers-only there is no body part, and when parseParts degrades
  // there is none either — so the one card on screen announced a reading, and
  // then the report ended. Found by running the real binary:
  // `kuvertii --headers-only` over a body-only paste.
  const findings = analyseBody([], { bodyOnly: true });
  assert.equal(findings.length, 1, 'the notice is all there is');
  assert.doesNotMatch(findings[0].lede, /is read below/);
  assert.match(findings[0].lede, /nothing below describes it/);
});

test('the notice says where mail programs keep the header', () => {
  // "Paste the full output" without saying where to find it left the reader
  // exactly where they started. Menu paths, not shortcuts — those drift.
  const [notice] = analyseBody([], { bodyOnly: true });
  const labels = notice.items.map((i) => i.label);
  for (const client of ['Apple Mail', 'Gmail (web)', 'Outlook']) {
    assert.ok(labels.includes(client), `${client} is named`);
  }
});

test('the notice tells a phone reader where the raw message hides', () => {
  // The desktop menu paths above are unreachable from a phone: none of these
  // apps expose a raw view there. A reader on a phone needs their own app
  // named, not a hunt through desktop instructions that do not apply.
  const [notice] = analyseBody([], { bodyOnly: true });
  const labels = notice.items.map((i) => i.label);
  for (const client of ['iPhone Mail', 'Gmail app', 'Outlook app', 'Proton app']) {
    assert.ok(labels.includes(client), `${client} is named`);
  }
  const byLabel = Object.fromEntries(notice.items.map((i) => [i.label, i.value]));
  assert.match(byLabel['iPhone Mail'], /\.eml/);
  assert.match(byLabel['iPhone Mail'], /iPad/);
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

test('a name the OS strips to an executable is not read as harmless', () => {
  // The extension checks anchor on the end of the string; Windows does not.
  // The Win32 path layer strips trailing dots and spaces from the final
  // component, and `report.exe::$DATA` / `report.exe:x` names a stream on
  // `report.exe`, so each of these opens the executable — while the `$`-anchored
  // checks read `.exe `, `.exe.`, `.exe\t` or `.exe::$DATA` and the card stayed
  // silent on a file the system runs, the one thing this card exists to prevent.
  for (const filename of [
    'rechnung.pdf.exe ', 'rechnung.pdf.exe.', 'update.exe ', 'update.exe.',
    'update.exe\t', 'update.exe::$DATA', 'update.exe:evil', 'update.scr. .',
  ]) {
    const card = attachmentCard(attachment({ filename, contentType: 'application/octet-stream', head: null }));
    assert.equal(card.items[0].level, 'bad', `${JSON.stringify(filename)} runs as an executable`);
    assert.match(card.items[0].note, /stripped by the operating system/);
    assert.equal(card.tone, 'alert');
  }

  // Stripping only exposes a hidden extension, it never invents one: a name
  // whose resolved form ends in a safe extension stays safe, trailing space and
  // all. Without this the fix would cry wolf on ordinary mail.
  for (const filename of ['notes.txt ', 'report.exe.txt', 'photo.jpg.', 'letter.pdf ']) {
    const card = attachmentCard(attachment({ filename, contentType: 'application/octet-stream', head: null }));
    assert.equal(card.items[0].level, null, `${JSON.stringify(filename)} resolves to a safe extension`);
  }
});

test('a language-tagged encoded-word filename is decoded before the danger check', () => {
  // RFC 2231 §5 lets a sender decorate the charset with a language tag —
  // `=?utf-8*en?B?…?=` — and a conformant client drops the `*en` and decodes the
  // word. kuvertii's `TextDecoder('utf-8*en')` threw, so the word was kept raw: a
  // filename encoding `report.exe` stayed `=?utf-8*en?B?…?=`, the `$`-anchored
  // executable check saw a string ending in `?=`, and the card went silent on a
  // file the client saves and runs as report.exe — the cardinal direction, and
  // the same crying-wolf class the plain encoded-word already covered, one tag
  // over. Driven through the real parseParts → analyseBody path, not a pre-set
  // filename, because the gap is in the decoding of the header field itself.
  const enc = (s) => Buffer.from(s, 'utf8').toString('base64');
  const cardFor = (filenameField) => {
    const { headerText, bodyText } = splitMessage([
      'Content-Type: multipart/mixed; boundary="B"',
      '',
      '--B',
      'Content-Type: text/plain',
      '',
      'See attached.',
      '--B',
      'Content-Type: application/octet-stream',
      `Content-Disposition: attachment; filename="${filenameField}"`,
      'Content-Transfer-Encoding: base64',
      '',
      'AAAAAA==',
      '--B--',
    ].join('\n'));
    const { parts } = parseParts(parseHeaders(headerText), bodyText);
    return analyseBody(parts).find((f) => f.id === 'attachments');
  };

  for (const field of [
    `=?utf-8*en?B?${enc('report.exe')}?=`,
    `=?UTF-8*de?B?${enc('rechnung.pdf.scr')}?=`,
    '=?utf-8*en?Q?update.bat?=',
  ]) {
    const card = cardFor(field);
    assert.equal(card.items[0].level, 'bad', `${JSON.stringify(field)} decodes to an executable`);
  }

  // The boundary, both ways. A safe name under a language tag is not newly
  // accused, and a genuinely unknown charset (no tag to strip) is still left raw
  // rather than force-decoded into a wrong reading.
  assert.equal(cardFor(`=?utf-8*en?B?${enc('notes.txt')}?=`).items[0].level, null, 'a safe name stays quiet');
  assert.equal(cardFor(`=?utf-8?B?${enc('report.exe')}?=`).items[0].level, 'bad', 'the plain form still fires');
});

test('a filename split across RFC 2231 continuation segments is reassembled first', () => {
  // RFC 2231 §3: a long or non-ASCII parameter is split across numbered
  // segments — `filename*0="report."; filename*1="exe"` — and a conformant
  // client concatenates them in index order before acting on the result. The
  // tool read only `filename=` and the single `filename*=`, so the split name
  // matched neither, the part came out unnamed, and the `$`-anchored executable
  // check ran on "(unnamed)" — silent on a file the client runs as report.exe.
  // The same false reassurance as the language-tag gap, one RFC section over.
  // Driven through the real parseParts → analyseBody path.
  const card = (disposition, contentType = 'application/octet-stream') => {
    const { headerText, bodyText } = splitMessage([
      'Content-Type: multipart/mixed; boundary="B"',
      '',
      '--B',
      'Content-Type: text/plain',
      '',
      'See attached.',
      '--B',
      `Content-Type: ${contentType}`,
      disposition,
      'Content-Transfer-Encoding: base64',
      '',
      'AAAAAA==',
      '--B--',
    ].join('\n'));
    const { parts } = parseParts(parseHeaders(headerText), bodyText);
    const inv = analyseBody(parts).find((f) => f.id === 'attachments');
    return { level: inv.items[0].level, name: parts.find((p) => p.disposition === 'attachment')?.filename };
  };

  // Literal, percent-encoded, out-of-order, and a multibyte escape split across
  // the boundary — every form a client reassembles, the tool now does too.
  let c = card('Content-Disposition: attachment; filename*0="report."; filename*1="exe"');
  assert.equal(c.level, 'bad', 'literal continuation runs as report.exe');
  assert.equal(c.name, 'report.exe');

  c = card("Content-Disposition: attachment; filename*0*=utf-8''report.; filename*1*=scr");
  assert.equal(c.level, 'bad', 'encoded continuation runs as report.scr');

  c = card('Content-Disposition: attachment; filename*1="exe"; filename*0="update."');
  assert.equal(c.name, 'update.exe', 'segments reassemble by index, not by order written');

  c = card("Content-Disposition: attachment; filename*0*=utf-8''caf%C3; filename*1*=%A9.exe");
  assert.equal(c.name, 'café.exe', 'a percent escape split across the boundary still decodes');
  assert.equal(c.level, 'bad');

  // A split name in the Content-Type `name` parameter, not the disposition.
  c = card('Content-Disposition: attachment', 'application/octet-stream; name*0="run."; name*1="bat"');
  assert.equal(c.name, 'run.bat');
  assert.equal(c.level, 'bad');

  // Both boundaries: a safe name split across segments is not newly accused, and
  // the older single forms still resolve exactly as before.
  assert.equal(card('Content-Disposition: attachment; filename*0="quarterly."; filename*1="pdf"').level, null, 'a safe split name stays quiet');
  assert.equal(card('Content-Disposition: attachment; filename="report.exe"').level, 'bad', 'the plain form still fires');
  assert.equal(card("Content-Disposition: attachment; filename*=utf-8''report.exe").level, 'bad', 'the single extended form still fires');
});

test('a charset the browser refuses but mail uses is read before the checks run', () => {
  // `TextDecoder` implements the Encoding Standard, written for browsers: it
  // leaves UTF-7 out and maps ISO-2022-KR and HZ onto a deliberate refusal. Mail
  // clients honour all three, so the tool went blind exactly where a sender
  // would aim. Two consequences, measured on the real pipeline before the fix:
  // an attachment named in an ISO-2022-KR encoded-word left the `$`-anchored
  // executable check reading a string ending in `?=` and the card silent on a
  // file the client saves and runs; and a `charset=utf-7` body whose anchor was
  // written `+ADw-a href…` produced no link card at all.
  //
  // These are the absolute anchors under the twin invariant in
  // test/invariants.test.js: that one compares two spellings of a message
  // against each other, so it stays green if both go silent together. This one
  // says the cards fire at all.
  const b64 = (bytes) => Buffer.from(Uint8Array.from(bytes)).toString('base64');
  const ascii = (text) => [...text].map((c) => c.charCodeAt(0));
  // ESC $ ) C, SO, the KS X 1001 pair for 가, SI, then ".exe" in the clear.
  const koreanExe = [0x1b, 0x24, 0x29, 0x43, 0x0e, 0x30, 0x21, 0x0f, ...ascii('.exe')];

  const { headerText, bodyText } = splitMessage([
    'Content-Type: multipart/mixed; boundary="B"',
    '',
    '--B',
    'Content-Type: text/plain',
    '',
    'See attached.',
    '--B',
    'Content-Type: application/octet-stream',
    `Content-Disposition: attachment; filename="=?ISO-2022-KR?B?${b64(koreanExe)}?="`,
    'Content-Transfer-Encoding: base64',
    '',
    'AAAAAA==',
    '--B--',
  ].join('\n'));
  const { parts } = parseParts(parseHeaders(headerText), bodyText);
  const attachments = analyseBody(parts).find((f) => f.id === 'attachments');
  assert.equal(parts.find((p) => p.disposition === 'attachment').filename, '가.exe');
  assert.equal(attachments.items[0].level, 'bad', 'the executable check reads the name a client shows');
  assert.equal(attachments.tone, 'alert');

  // UTF-7 needs no transfer encoding — that pairing is how it arrives, and it
  // is the path that reached no charset at all.
  const utf7 = (text) => {
    const units = [];
    for (let i = 0; i < text.length; i++) units.push(text.charCodeAt(i) >> 8, text.charCodeAt(i) & 0xff);
    return `+${b64(units).replace(/=+$/, '')}-`;
  };
  const hidden = splitMessage([
    'Content-Type: text/html; charset=utf-7',
    'Content-Transfer-Encoding: 7bit',
    '',
    utf7('<a href="https://secure-paypa1.example/login">Your account</a>'),
  ].join('\n'));
  const links = analyseBody(parseParts(parseHeaders(hidden.headerText), hidden.bodyText).parts)
    .find((f) => f.id === 'body-links');
  assert.ok(links, 'the link card exists at all');
  assert.match(flat(links), /secure-paypa1/, 'the destination a utf-7 client reaches is named');

  // The boundary, and the reason the decode is refused for anything carrying a
  // high byte: all three of these charsets are 7-bit by definition, so a body
  // that declares one and sends UTF-8 is mislabelled — and is still read as the
  // UTF-8 it is, rather than mangled into a second wrong reading. Crying wolf
  // over honest mail is this project's other failure mode.
  const mislabelled = splitMessage([
    'Content-Type: text/plain; charset=utf-7',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from('Grüße aus München', 'utf8').toString('base64'),
  ].join('\n'));
  const { parts: honest } = parseParts(parseHeaders(mislabelled.headerText), mislabelled.bodyText);
  assert.equal(honest[0].text, 'Grüße aus München', 'a mislabelled body is read as what it is');
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

test('the inventory names the type the part declared, not the one it was read as', () => {
  // Every sentence in this card says "declared", so every one of them has to
  // read the declaration. A .txt attachment holding markup is read as
  // text/html — correctly, that is how its hrefs are found — and the row said
  // "Declared as text/html" over a part that declared text/plain: a false
  // claim about the message, in the one card whose whole subject is what a
  // part says about itself against what its bytes are.
  const card = attachmentCard(attachment({
    contentType: 'text/html',
    declaredType: 'text/plain',
    filename: 'invoice.txt',
    head: [0x3c, 0x68, 0x74, 0x6d],
  }));
  assert.match(card.items[0].value, /Declared as text\/plain/);
  assert.doesNotMatch(card.items[0].value, /text\/html/);
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

test('a plain version that mentions a tag is still the plain version', () => {
  // Self-inflicted, and found by probing the fix rather than the bug: once a
  // body that is visibly markup is read as markup whatever it declares, a
  // text/plain part discussing a `<table>` in prose becomes a text/html part —
  // and pairing the two versions on how they are read then left this message
  // with no plain side at all, so the card silently stopped comparing. It
  // pairs on what each part was offered as.
  const { headerText, bodyText } = splitMessage([
    'From: news@shop.example',
    'Content-Type: multipart/alternative; boundary="BB"',
    '',
    '--BB',
    'Content-Type: text/plain; charset="utf-8"',
    '',
    'Our new template uses a <table> layout now.',
    'Read it at https://shop.example/news',
    '',
    '--BB',
    'Content-Type: text/html; charset="utf-8"',
    '',
    '<p>Our template</p><a href="https://shop.example/news">Read</a>'
      + '<a href="https://tracker.adnetwork.example/c?u=9">More</a>',
    '--BB--',
  ].join('\n'));
  const { parts } = parseParts(parseHeaders(headerText), bodyText);
  assert.equal(parts[0].contentType, 'text/html', 'read as markup, because that is what it is');
  assert.equal(parts[0].declaredType, 'text/plain', 'but still offered as the plain version');

  const card = analyseBody(parts).find((f) => f.id === 'divergence');
  assert.ok(card, 'the comparison still happens');
  assert.match(card.items[0].value, /adnetwork\.example/);
  assert.doesNotMatch(card.items[0].value, /shop\.example/, 'the shared destination is not html-only');
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
