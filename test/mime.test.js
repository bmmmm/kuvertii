// The MIME splitter: a whole pasted message into header text and body parts.
//
// The body is sender-written from the first byte, so most of this file is the
// hostile half: boundary bombs, lying charsets, ceilings that must announce
// themselves, malformed structure that must degrade to something honest
// rather than to a throw.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  bodyClippedNote, looksLikeHeaderBlock, MAX_BODY_BYTES, MAX_DEPTH, MAX_PARTS,
  MAX_PART_TEXT, parseParts, readTally, splitMessage,
} from '../js/mime.js';
import { parseHeaders } from '../js/unfold.js';

const HEAD = [
  'From: Support <support@sender.example>',
  'To: you@example.org',
  'Date: Mon, 1 Jan 2026 00:00:00 +0000',
  'MIME-Version: 1.0',
].join('\n');

const message = (headerLines, body) => `${HEAD}\n${headerLines.join('\n')}\n\n${body}`;

const parts = (headerLines, body) => {
  const raw = message(headerLines, body);
  const { headerText, bodyText } = splitMessage(raw);
  return parseParts(parseHeaders(headerText), bodyText);
};

// ---------------------------------------------------------------- the split

test('a message splits at the first blank line', () => {
  const { headerText, bodyText, bodyOnly } = splitMessage(`${HEAD}\n\nHello body`);
  assert.match(headerText, /^From: Support/);
  assert.doesNotMatch(headerText, /Hello body/);
  assert.equal(bodyText, 'Hello body');
  assert.equal(bodyOnly, false);
});

test('a header-only paste has an empty body', () => {
  const { bodyText, bodyOnly } = splitMessage(HEAD);
  assert.equal(bodyText, '');
  assert.equal(bodyOnly, false);
});

test('a whitespace-only line is the same boundary the header parser uses', () => {
  // js/unfold.js stops reading fields at a line of spaces; if the splitter
  // used a stricter boundary the two would disagree about where the body is.
  const { headerText, bodyText } = splitMessage(`${HEAD}\n   \nBody here`);
  assert.doesNotMatch(headerText, /Body here/);
  assert.equal(bodyText, 'Body here');
});

test('CRLF input splits exactly like LF input', () => {
  const { headerText, bodyText } = splitMessage(`From: a@b.example\r\nTo: c@d.example\r\n\r\nBody`);
  assert.match(headerText, /To: c@d.example/);
  assert.equal(bodyText, 'Body');
});

test('an HTML paste with no header is recognised as a body', () => {
  const { headerText, bodyText, bodyOnly } = splitMessage(
    '<html><body><a href="https://evil.example/x">click</a></body></html>',
  );
  assert.equal(bodyOnly, true);
  assert.equal(headerText, '');
  assert.match(bodyText, /evil\.example/);
});

test('an HTML paste keeps its whole content even past internal blank lines', () => {
  const { bodyText, bodyOnly } = splitMessage(
    '<div>first</div>\n\n<div>second</div>',
  );
  assert.equal(bodyOnly, true);
  assert.match(bodyText, /first/);
  assert.match(bodyText, /second/);
});

test('a localised header paste is still a header, not a body', () => {
  // `Von:` is what a German Apple Mail copies out; the alias table knows it,
  // so the body-detection must too — it asks the real parser.
  const { bodyOnly } = splitMessage('Von: wer@example.org\nBetreff: <b>Hallo</b>\n\n<p>text</p>');
  assert.equal(bodyOnly, false);
});

test('prose with no labelled field is a body, not a mangled header', () => {
  // Revised 2026-08-28: this paste used to stay on the header path ("kept
  // rather than guessed about"), and the report then told the reader their
  // message text looked like part of a header — a factual claim about the
  // paste that was false. A front block in which the parser finds no field
  // written as one is not a header it could be a part of.
  const prose = splitMessage('Sehr geehrter Kunde,\n\nBitte hier klicken: https://x.example/y\n');
  assert.equal(prose.bodyOnly, true);
  assert.match(prose.bodyText, /geehrter/, 'the greeting is body, not a header fragment');

  const note = splitMessage('note to self: buy milk\n\nsecond line');
  assert.equal(note.bodyOnly, true, 'a colon inside prose does not make a field');
});

test('a partial header of unknown but labelled fields is still a header', () => {
  // The completeness card exists for exactly this paste. Only a front block
  // with no labelled field at all flips to the body reading.
  const { bodyOnly } = splitMessage('X-Icl-Score: 4.3\nX-Custom-Trace: abc\n');
  assert.equal(bodyOnly, false);
});

test('an Apple Mail display-lines paste keeps its header reading', () => {
  // The lines a client renders above the header block: an unlabelled sender
  // line the parser promotes to a From. That promotion counts as a field
  // written as one, so the paste is not mistaken for prose.
  const { bodyOnly } = splitMessage('Auszahlungsstelle <x@y.example>\n\nText follows.');
  assert.equal(bodyOnly, false);
});

test('looksLikeHeaderBlock wants a known field, not just a colon', () => {
  assert.equal(looksLikeHeaderBlock('From: a@b.example\nX-Custom: 1'), true);
  assert.equal(looksLikeHeaderBlock('color: red\nfont-size: 12px'), false);
  assert.equal(looksLikeHeaderBlock(''), false);
});

// ----------------------------------------------------------------- the parts

test('a plain body is one text/plain part with its text', () => {
  const { parts: got, notes } = parts([], 'Hello there.\nSecond line.');
  assert.equal(got.length, 1);
  assert.equal(got[0].contentType, 'text/plain');
  assert.match(got[0].text, /Hello there\./);
  assert.equal(got[0].clipped, false);
  assert.deepEqual(notes, []);
});

test('multipart/alternative yields both parts with their types', () => {
  const body = [
    'preamble to be ignored',
    '--BB',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'plain text',
    '--BB',
    'Content-Type: text/html; charset="utf-8"',
    '',
    '<p>html text</p>',
    '--BB--',
    'epilogue to be ignored',
  ].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/alternative; boundary="BB"'], body);
  assert.equal(got.length, 2);
  assert.equal(got[0].contentType, 'text/plain');
  assert.equal(got[1].contentType, 'text/html');
  assert.equal(got[1].charset, 'utf-8');
  assert.match(got[0].text, /plain text/);
  assert.match(got[1].text, /<p>html text<\/p>/);
});

test('a base64 part decodes through the charset it declares', () => {
  const payload = Buffer.from('Grüße aus Köln', 'utf8').toString('base64');
  const body = [
    '--BB',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    payload,
    '--BB--',
  ].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.equal(got[0].text, 'Grüße aus Köln');
  assert.equal(got[0].transferEncoding, 'base64');
});

test('a quoted-printable part reassembles its UTF-8', () => {
  const body = [
    '--BB',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    'Gr=C3=BC=C3=9Fe und ein soft=',
    'break',
    '--BB--',
  ].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.match(got[0].text, /Grüße und ein softbreak/);
});

test('a declared charset that lies yields replacement characters, not a throw', () => {
  // 0xFF 0xFE is not UTF-8; the label says it is.
  const payload = Buffer.from([0xff, 0xfe, 0x41]).toString('base64');
  const body = [
    '--BB',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    payload,
    '--BB--',
  ].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.match(got[0].text, /�/);
  assert.match(got[0].text, /A/);
});

test('a charset this platform does not know falls back to UTF-8', () => {
  const body = [
    '--BB',
    'Content-Type: text/plain; charset=x-no-such-charset',
    '',
    'still readable',
    '--BB--',
  ].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.match(got[0].text, /still readable/);
});

test('an attachment is described, its content never decoded past the head', () => {
  const payload = Buffer.from('%PDF-1.7 rest of a pdf').toString('base64');
  const body = [
    '--BB',
    'Content-Type: application/pdf; name="rechnung.pdf"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="rechnung.pdf"; size=90210',
    '',
    payload,
    '--BB--',
  ].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.equal(got[0].contentType, 'application/pdf');
  assert.equal(got[0].disposition, 'attachment');
  assert.equal(got[0].filename, 'rechnung.pdf');
  assert.equal(got[0].bytesDeclared, 90210);
  assert.equal(got[0].text, null);
  assert.equal(String.fromCharCode(...got[0].head.slice(0, 5)), '%PDF-');
});

test('an attachment with no size= is measured, not called zero bytes', () => {
  // The fixture above states `size=90210`, and that is the whole reason this
  // survived five audit rounds: `size=` is optional and most mailers never
  // write it. `Number(null)` is 0, which passed the safe-integer check as a
  // stated size of zero, so `bytesDeclared` never fell through to the decoded
  // length — and the real binary printed "Declared as application/pdf, 0
  // bytes." over an ordinary invoice.
  const payload = Buffer.from('%PDF-1.7 and a hundred more bytes of it').toString('base64');
  const body = [
    '--BB',
    'Content-Type: application/pdf; name="rechnung.pdf"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="rechnung.pdf"',
    '',
    payload,
    '--BB--',
  ].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.ok(got[0].bytesDeclared > 30, `measured, not zero — got ${got[0].bytesDeclared}`);
});

test('a size= that is not a size is no size at all', () => {
  const body = [
    '--BB',
    'Content-Type: application/pdf',
    'Content-Disposition: attachment; filename="x.pdf"; size=lots',
    '',
    'content',
    '--BB--',
  ].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.equal(got[0].bytesDeclared, 'content'.length, 'falls back to what was actually there');
});

test('a text attachment holding markup still declares what it declared', () => {
  // Read as markup, because that is how its hrefs are found — but the
  // attachment card says "Declared as …" about every part it lists, and the
  // declaration is a different fact from the reading.
  const body = [
    '--BB',
    'Content-Type: text/plain; charset="utf-8"; name="invoice.txt"',
    'Content-Disposition: attachment; filename="invoice.txt"',
    '',
    '<html><body><a href="https://collect.evil.example/x">pay now</a></body></html>',
    '--BB--',
  ].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.equal(got[0].contentType, 'text/html', 'read for what it is');
  assert.equal(got[0].declaredType, 'text/plain', 'described as what it claimed');
});

test('an RFC 2047 filename is decoded into something legible', () => {
  const encoded = `=?utf-8?B?${Buffer.from('Größenwahn.exe', 'utf8').toString('base64')}?=`;
  const body = [
    '--BB',
    'Content-Type: application/octet-stream',
    `Content-Disposition: attachment; filename="${encoded}"`,
    '',
    'AAAA',
    '--BB--',
  ].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.equal(got[0].filename, 'Größenwahn.exe');
});

test('an RFC 2231 extended filename is decoded too', () => {
  const body = [
    '--BB',
    'Content-Type: application/octet-stream',
    "Content-Disposition: attachment; filename*=utf-8''Gr%C3%B6%C3%9Fe.pdf",
    '',
    'AAAA',
    '--BB--',
  ].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.equal(got[0].filename, 'Größe.pdf');
});

test('nested multipart walks to the leaves', () => {
  const body = [
    '--OUT',
    'Content-Type: multipart/alternative; boundary=IN',
    '',
    '--IN',
    'Content-Type: text/plain',
    '',
    'plain',
    '--IN',
    'Content-Type: text/html',
    '',
    '<b>html</b>',
    '--IN--',
    '--OUT',
    'Content-Type: application/pdf; name=a.pdf',
    '',
    'AAAA',
    '--OUT--',
  ].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/mixed; boundary=OUT'], body);
  assert.deepEqual(got.map((p) => p.contentType), ['text/plain', 'text/html', 'application/pdf']);
});

// ------------------------------------------------------------------ ceilings

test('nesting past the depth ceiling is kept unopened, and says so', () => {
  // Each level declares the next boundary; MAX_DEPTH+2 levels deep.
  let body = 'the bottom';
  for (let i = MAX_DEPTH + 2; i >= 1; i--) {
    body = [
      `--B${i}`,
      `Content-Type: multipart/mixed; boundary=B${i + 1}`,
      '',
      body,
      `--B${i}--`,
    ].join('\n');
  }
  const { parts: got, notes } = parts(['Content-Type: multipart/mixed; boundary=B1'], body);
  assert.equal(got.length, 1);
  assert.match(got[0].contentType, /^multipart\//);
  assert.equal(got[0].text, null, 'an unopened multipart is opaque, not text');
  assert.ok(notes.some((n) => /deeper than/.test(n)), 'the ceiling announces itself');
});

test('more parts than the ceiling are counted, not silently dropped', () => {
  const many = [];
  for (let i = 0; i < MAX_PARTS + 7; i++) {
    many.push('--BB', 'Content-Type: text/plain', '', `part ${i}`);
  }
  many.push('--BB--');
  const { parts: got, notes } = parts(['Content-Type: multipart/mixed; boundary=BB'], many.join('\n'));
  assert.equal(got.length, MAX_PARTS);
  assert.ok(notes.some((n) => n.includes('7 more were not')), 'the overflow is a number, not a shrug');
});

test('an oversized body is clipped, and the note says exactly that', () => {
  const huge = `x`.repeat(MAX_BODY_BYTES + 100);
  const { notes } = parts([], huge);
  assert.ok(notes.some((n) => /Only the first 4 MB of the body were read/.test(n)));
});

test('a body under the ceiling earns no note', () => {
  assert.equal(bodyClippedNote(MAX_BODY_BYTES), '');
  assert.equal(bodyClippedNote(10), '');
  assert.match(bodyClippedNote(MAX_BODY_BYTES + 1), /^ Only the first/);
});

test('a single part past the per-part ceiling is clipped and flagged', () => {
  const body = [
    '--BB',
    'Content-Type: text/plain',
    '',
    'y'.repeat(MAX_PART_TEXT + 50),
    '--BB--',
  ].join('\n');
  const { parts: got, notes } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.equal(got[0].clipped, true);
  assert.ok(got[0].text.length <= MAX_PART_TEXT);
  assert.ok(notes.some((n) => /larger than/.test(n)));
});

// ----------------------------------------------------------------- malformed

// A multipart whose parts cannot be told apart used to be kept as one opaque
// part: counted in the tally, its content discarded, and nothing said. Every
// producer skips a part with no text, so one `boundary=` the sender never used
// emptied the whole body report while the tally still read "1 body part read".
// The content is read for what it looks like now, and the structure that could
// not be followed is announced — the way the other three unreadable outcomes
// here already were.

test('a multipart with no boundary parameter is read as one part, and says so', () => {
  const { parts: got, notes } = parts(['Content-Type: multipart/mixed'], 'unstructured content');
  assert.equal(got.length, 1);
  assert.match(got[0].text, /unstructured content/);
  assert.match(notes.join(''), /boundary that never appears/);
});

test('a boundary that never appears keeps the content and announces itself', () => {
  const { parts: got, notes } = parts(
    ['Content-Type: multipart/mixed; boundary=NEVER'],
    'no delimiter anywhere in here',
  );
  assert.equal(got.length, 1);
  assert.match(got[0].text, /no delimiter anywhere in here/);
  assert.match(notes.join(''), /could not be told apart/);
});

test('a lost boundary does not hide the links underneath it', () => {
  const body = '<html><body><a href="https://tracker.evil.example/c">https://www.paypal.com/signin</a></body></html>';
  const { parts: got, notes } = parts(
    ['Content-Type: multipart/alternative; boundary="NEVER-APPEARS"'],
    body,
  );
  assert.equal(got.length, 1);
  assert.equal(got[0].contentType, 'text/html', 'read for what it looks like, not for what was declared');
  assert.match(got[0].text, /tracker\.evil\.example/);
  assert.ok(notes.join('').length, 'and the structure that could not be followed is announced');
});

test('a well-formed multipart earns no unreadable-structure note', () => {
  const body = ['--BB', 'Content-Type: text/plain', '', 'ordinary', '--BB--'].join('\n');
  const { notes } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.equal(notes.join(''), '', 'the note is earned, not printed over every message');
});

test('a missing closing delimiter keeps the final part', () => {
  const body = ['--BB', 'Content-Type: text/plain', '', 'kept anyway'].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.equal(got.length, 1);
  assert.match(got[0].text, /kept anyway/);
});

test('a child that reuses its parent boundary cannot recurse', () => {
  const body = [
    '--BB',
    'Content-Type: multipart/mixed; boundary=BB',
    '',
    'swallowed by the parent split',
    '--BB--',
  ].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.equal(got.length, 1, 'one part — the child does not recurse into the parent split');
  assert.match(got[0].text, /swallowed by the parent split/, 'and its content is not thrown away');
});

test('a boundary full of regex metacharacters is matched as a string', () => {
  const boundary = '=_(*+?)[a]{2}$^|';
  const body = [
    `--${boundary}`,
    'Content-Type: text/plain',
    '',
    'made it through',
    `--${boundary}--`,
  ].join('\n');
  const { parts: got } = parts([`Content-Type: multipart/mixed; boundary="${boundary}"`], body);
  assert.equal(got.length, 1);
  assert.match(got[0].text, /made it through/);
});

test('base64 that is not base64 is kept as the text it visibly is', () => {
  const body = [
    '--BB',
    'Content-Type: text/plain',
    'Content-Transfer-Encoding: base64',
    '',
    'this was never base64 !!!',
    '--BB--',
  ].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.match(got[0].text, /never base64/);
});

test('an already-decoded "quoted-printable" part is not mangled', () => {
  // A client that decoded before copying leaves real umlauts behind; casting
  // those through charCodeAt & 0xff would destroy them.
  const body = [
    '--BB',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    'schöne Grüße, already decoded',
    '--BB--',
  ].join('\n');
  const { parts: got } = parts(['Content-Type: multipart/mixed; boundary=BB'], body);
  assert.match(got[0].text, /schöne Grüße/);
});

test('an empty body yields no parts and no notes', () => {
  const { parts: got, notes } = parts([], '   \n  \n');
  assert.deepEqual(got, []);
  assert.deepEqual(notes, []);
});

test('an undeclared body that is visibly markup is read as HTML', () => {
  // Found by running the real binary over a body-only paste: with no header
  // to declare a type, the HTML was read as plain text, the hrefs vanished
  // inside their angle brackets, and the link card tallied the decoy text a
  // reader sees instead of the destination underneath it.
  const { parts: got } = parseParts([], '<html><body><a href="http://203.0.113.7/x">dhl.de</a></body></html>');
  assert.equal(got[0].contentType, 'text/html');
});

test('an undeclared body of plain prose stays plain text', () => {
  const { parts: got } = parseParts([], 'no markup here, just words and https://a.example/x');
  assert.equal(got[0].contentType, 'text/plain');
});

test('a declared text/plain over markup is read as markup all the same', () => {
  // The rule above held only where nothing was declared, and the declaration
  // is written by the party that profits from the misreading. One
  // `Content-Type: text/plain` line put an HTML body back on the plain path,
  // where the href vanished inside its tag and the anchor text survived — the
  // real binary then printed paypal.com as the destination of a link going to
  // tracker.evil.example, and never named that host at all.
  const body = '<html><body><a href="https://tracker.evil.example/c">https://www.paypal.com/signin</a></body></html>';
  const { parts: got } = parseParts(parseHeaders('Content-Type: text/plain; charset=utf-8'), body);
  assert.equal(got[0].contentType, 'text/html');
  assert.equal(got[0].charset, 'utf-8', 'only the reading changes; the declared parameters are kept');
});

test('a part that says it is not text is taken at its word', () => {
  // The rule reaches text/* and undeclared bodies only. A PDF or an image is
  // read for its first bytes, not its text, and a hex string inside one is not
  // a <p> tag — second-guessing those would decode attachments as prose.
  const body = '%PDF-1.4 <a href="https://x.example/">catalogue</a>';
  const { parts: got } = parseParts(parseHeaders('Content-Type: application/pdf'), body);
  assert.equal(got[0].contentType, 'application/pdf');
});

// ---------------------------------------------------------------- the tally

test('a tally with nothing to count says so, rather than opening with a blank', () => {
  // Built by joining the non-zero counts, it produced a bare " read." with no
  // subject whenever both were zero — reachable on the command line with
  // --headers-only over a body-only paste, and on the page when parseParts
  // degrades to no parts. The one line whose job is a complete account of the
  // input could not say the input had not been read.
  assert.equal(readTally(0, 0), 'Nothing was read.');
  assert.equal(readTally(1, 0), '1 header field read.');
  assert.equal(readTally(4, 1), '4 header fields and 1 body part read.');
  assert.equal(readTally(4, 2), '4 header fields and 2 body parts read.');
});

// -------------------------------------------------------------------- timing

test('a 4 MB body parses in about a second', () => {
  // Wall-clock, like the hostile suite: a shape test cannot catch quadratic
  // behaviour. Boundary-dense on purpose — many parts, long lines.
  const chunk = ['--BB', 'Content-Type: text/plain', '', 'z'.repeat(65536)].join('\n');
  let body = '';
  while (body.length < MAX_BODY_BYTES) body += `${chunk}\n`;
  const started = Date.now();
  parseParts(parseHeaders(`${HEAD}\nContent-Type: multipart/mixed; boundary=BB`), body);
  const ms = Date.now() - started;
  assert.ok(ms < 1500, `took ${ms}ms`);
});
