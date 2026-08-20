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

test('a fault in the body section costs that section and nothing else', () => {
  // Fault isolation is inherited from guardSection; a part whose text is a
  // getter that throws is the cheapest way to prove the boundary holds.
  const poisoned = [{
    contentType: 'text/html',
    get text() { throw new Error('deliberate'); },
  }];
  const findings = analyseBody(poisoned);
  assert.equal(findings.length, 1);
  assert.match(findings[0].items[0].label, /failed/);
  assert.equal(findings[0].items[0].level, 'fault');
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
