import assert from 'node:assert/strict';
import { test } from 'node:test';

import { decodeCandidates, decodeEncodedWords, decodeSegments, findAddresses, readability } from '../js/decode.js';
import { clippedNote, get, getAll, MAX_HEADER_BYTES, parseHeaders, readHeaders, skippedNote } from '../js/unfold.js';
import {
  BULK_HEADER, CAMPAIGN_SEGMENT, MAILER_SEGMENT, RECIPIENT, UNSUB_TOKEN,
} from './fixtures.js';

/** The senders' own transform is reversal; the tests build their input the same way. */
const reverse = (text) => [...text].reverse().join('');

test('folded continuation lines are joined into one value', () => {
  const headers = parseHeaders(BULK_HEADER);
  const extra = get(headers, 'X-Mailer-Info-Extra');
  assert.ok(extra.includes(MAILER_SEGMENT), 'first line kept');
  assert.ok(extra.includes(CAMPAIGN_SEGMENT), 'continuation line joined in');
  assert.equal(getAll(headers, 'X-Mailer-Info-Extra').length, 1);
});

test('a uniformly indented paste still parses as separate fields', () => {
  const indented = BULK_HEADER.split('\n').map((l) => (l ? `    ${l}` : l)).join('\n');
  const headers = parseHeaders(indented);
  assert.equal(get(headers, 'Subject'), 'Herzlich willkommen!');
  assert.ok(get(headers, 'To').includes(RECIPIENT));
});

test('repeated fields are all preserved, in order', () => {
  const headers = parseHeaders(BULK_HEADER);
  assert.equal(getAll(headers, 'Received').length, 3);
  assert.equal(getAll(headers, 'Authentication-Results').length, 3);
});

test('a line that lost its field name is kept rather than dropped', () => {
  const headers = parseHeaders(BULK_HEADER);
  const orphan = headers.find((h) => h.synthetic);
  assert.ok(orphan, 'orphan line captured');
  assert.match(orphan.value, /^<mid-/);
});

test('the body after the blank line is not parsed as headers', () => {
  const headers = parseHeaders('To: a@example.org\n\nSubject: not a header, this is the body\n');
  assert.equal(headers.length, 1);
  assert.equal(headers[0].name, 'To');
});

test('reversed base64 with reversed content decodes back to the address', () => {
  const [best] = decodeCandidates(MAILER_SEGMENT);
  assert.ok(best, 'produced a candidate');
  assert.equal(best.text, RECIPIENT);
  assert.match(best.method, /reversed/);
});

test('the unsubscribe token yields the recipient and the campaign', () => {
  const [best] = decodeCandidates(UNSUB_TOKEN);
  assert.ok(best.text.includes(RECIPIENT));
  assert.ok(best.text.includes('newsletter00news20260817'));
});

test('a fold inside a token does not hide what it carries', () => {
  // Unfolding removes the line break, not the space that came with it, and a
  // mailer folds at a fixed width rather than at its own separators — so the
  // fold lands mid-token on any value long enough. Splitting on whitespace then
  // handed the decoder two halves of a base64 token: the address in it went
  // unreported, and the noise the halves decoded to was printed in its place.
  //
  // Shaped after a real Klaviyo X-Mailer-Info, with this suite's invented
  // address and the sender's own transform: the plaintext reversed, base64'd,
  // and the whole string reversed again.
  const token = reverse(Buffer.from(reverse(RECIPIENT)).toString('base64'));
  const cut = Math.floor(token.length / 2);
  const folded = parseHeaders(`X-Mailer-Info: 10.${token.slice(0, cut)}\n ${token.slice(cut)}\n`);

  const found = decodeSegments(get(folded, 'X-Mailer-Info')).map((c) => c.text);
  assert.ok(found.includes(RECIPIENT), `the fold hid the address: ${JSON.stringify(found)}`);
});

test('whitespace that separates two tokens still reads as a separator', () => {
  // The other half of the same question. Nothing in the value says whether a
  // space is a fold or a separator, so the answer has to come from what the two
  // readings decode to: a separator leaves both sides readable on their own,
  // a fold leaves at least one side holding part of a token. Reading this pair
  // as one token yields both addresses run together into a single line.
  const encode = (text) => reverse(Buffer.from(reverse(text)).toString('base64'));
  const pair = `${encode(RECIPIENT)} ${encode('newsletter@example.org')}`;

  const found = decodeSegments(pair).map((c) => c.text);
  assert.deepEqual(found.sort(), [RECIPIENT, 'newsletter@example.org'].sort());
});

test('bytes that are not text do not become text by being printed', () => {
  // What a reader was shown: replacement characters and control bytes, in rows
  // captioned as campaign metadata, under a headline calling their newsletter a
  // deliberate attempt to control their terminal.
  //
  // U+FFFD is what TextDecoder emits where the bytes were not UTF-8 — the
  // decoder's verdict on its own output — and counting it as an ordinary
  // printable character was enough to carry noise over the line. Three invalid
  // bytes and then a word is the shape a half-token has: mostly text, and not
  // text. Counted as printable, this scored 0.55 against a threshold of 0.5.
  const noise = Buffer.concat([
    Buffer.from([0xb4, 0x8f, 0x9c]), Buffer.from('campaign2026x'),
  ]).toString('base64');
  const [best] = decodeCandidates(noise);

  assert.ok(!best || !best.text.includes('\uFFFD'), `mojibake scored as readable: ${JSON.stringify(best)}`);
});

test('high-entropy blobs are not reported as decoded text', () => {
  // Shaped like the opaque tracking blobs real headers carry.
  const noise = Buffer.from(
    Uint8Array.from({ length: 96 }, (_, i) => (i * 37 + 11) % 256),
  ).toString('base64');
  const meaningful = decodeCandidates(noise).filter((c) => c.score >= 0.5);
  assert.equal(meaningful.length, 0, 'binary noise stays unreported');
});

test('readability separates prose from bytes', () => {
  assert.ok(readability('contact@example.org') > 0.8);
  assert.ok(readability('newsletter campaign') > 0.5);
  assert.equal(readability(''), 0);
});

test('addresses are extracted and normalised', () => {
  assert.deepEqual(findAddresses('To: Maja <MAJA@Example.ORG>, b@x.test'), [
    'maja@example.org',
    'b@x.test',
  ]);
});

test('base64 input of impossible length is rejected, not thrown on', () => {
  assert.doesNotThrow(() => decodeCandidates('QUJDRE'.slice(0, 5)));
});

// ------------------------------------------------------- what was not read

test('a line of whitespace ends the header, and the report says so', () => {
  // Several clients emit obs-FWS — a line holding one space or tab — in the
  // middle of a header. This parser reads it as the end of the block, which is
  // defensible; what was not defensible was doing it silently. A ten-field
  // header analysed as six, reported "6 header fields read" in the same tone a
  // complete one gets, and the four it dropped were the authentication results,
  // a Reply-To on a lookalike domain and an unsubscribe link pointing at a
  // login page. Nothing in the output distinguished that from a short message.
  const { headers, skipped } = readHeaders([
    'From: PayPal <service@paypal.example>',
    'To: reader@example.org',
    'Message-ID: <a@b>',
    ' ',
    'Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail',
    'Reply-To: service@paypa1-secure.example',
  ].join('\n'));

  assert.equal(headers.length, 3, 'the parse still stops where it stopped');
  assert.equal(skipped.lines, 2, 'and counts what it left');
  assert.match(skipped.reason, /whitespace/);
  assert.match(skippedNote(skipped), /2 further lines were treated as message body/);
});

test('a complete header accounts for everything and says nothing', () => {
  // The note has to be absent when there is nothing to report, or it becomes
  // noise on every message and stops being read on the one that matters.
  const { headers, skipped } = readHeaders([
    'From: a@b.example',
    'To: c@d.example',
    'Message-ID: <a@b>',
  ].join('\n'));

  assert.equal(headers.length, 3);
  assert.equal(skipped.lines, 0);
  assert.equal(skippedNote(skipped), '');
});

test('input cut at the ceiling says so, and an uncut input says nothing', () => {
  // The page said "Only the first 1024 KB was read" while the command clipped
  // in silence and closed with "N header fields read. Nothing left this
  // machine." — a complete-sounding tally of an input it had not completely
  // read. A sender who opens with a megabyte of padding chooses what falls
  // past the cut, so the cut has to be announced. One wording, owned here.
  assert.match(clippedNote(MAX_HEADER_BYTES + 1), /Only the first 1024 KB were read/);
  assert.match(clippedNote(MAX_HEADER_BYTES + 1), /not analysed/);
  assert.equal(clippedNote(MAX_HEADER_BYTES), '', 'exactly at the ceiling nothing was lost');
  assert.equal(clippedNote(120), '');
});

test('an ordinary message body is not reported as something lost', () => {
  // The body is not "not read" in the sense that matters — it is the part this
  // tool deliberately never touches. What distinguishes it is the blank line,
  // which is the boundary RFC 5322 actually defines.
  const { skipped } = readHeaders('From: a@b.example\nMessage-ID: <a@b>\n\nHello, this is the message.\n');

  assert.equal(skipped.reason, 'a blank line');
  assert.match(skippedNote(skipped), /after a blank line/);
});

test('parseHeaders still answers with just the fields', () => {
  // Six test files and both renderers called it; changing its return type
  // would have been a change to every one of them for no gain.
  const headers = parseHeaders('From: a@b.example\nTo: c@d.example\n');
  assert.ok(Array.isArray(headers));
  assert.equal(headers.length, 2);
});

// ------------------------------------------- an encoding, or a coincidence

test('an ordinary Gmail message id is not a hidden address', () => {
  // `=8b` is a valid quoted-printable escape and a Gmail message id contains
  // one often enough to matter. Decoding it yields a lone UTF-8 continuation
  // byte — no sequence begins with 0x8B — and the characters left over read as
  // an address, so the tool announced a recipient that does not exist, on
  // ordinary personal mail, in its strongest wording.
  const candidates = decodeCandidates('CAE=8bd3f9a0c1e2d4b5a6c7e8f9a0b1c2d3@mail.gmail.com');
  assert.deepEqual(candidates, [], 'bytes that are not text were not that encoding');
});

test('a printable-ASCII =XX in an opaque id is not a hidden recipient', () => {
  // The =8b fix rejected one byte — an invalid-UTF-8 one — and left the whole
  // printable-ASCII range open. =41 -> 'A', =2E -> '.', =5F -> '_', =2B -> '+',
  // =2D -> '-' are valid UTF-8 and land in the address local-part class, so a
  // Gmail-style Message-ID <CAE=41…@mail.gmail.com> decoded to a *different*
  // local part and was announced as a recipient "recovered by decoding", the
  // card's strongest wording, on ordinary mail. Two of 25 real messages hit it
  // through DKIM-Signature, whose base64 is full of `=` padding followed by two
  // hex digits. Quoted-printable never escapes printable ASCII (RFC 2045 §6.7),
  // so a lone such escape is not that encoding — it is base64, or a literal `=`.
  for (const esc of ['41', '2E', '5f', '2b', '2d', '30', '25', '7e']) {
    const id = `<CAE=${esc}d3f9a0c1e2d4b5a6c7e8@mail.gmail.com>`;
    assert.deepEqual(
      decodeCandidates(id).filter((c) => c.score >= 0.5), [],
      `=${esc} adjacent to @mail.gmail.com is a coincidence, not quoted-printable`,
    );
  }

  // The positive control, and the boundary the fix rides on: an escape carrying
  // a byte quoted-printable exists to carry (0x80..0xFF) still decodes, because
  // that is the only thing a header ever legitimately quoted-printable-encodes.
  const [genuine] = decodeCandidates('Gr=C3=BC=C3=9Fe von M=C3=BCller');
  assert.equal(genuine.text, 'Grüße von Müller');
  assert.equal(genuine.method, 'quoted-printable');
});

test('genuine quoted-printable decodes to the text it encodes', () => {
  // The same strictness that refuses the coincidence above earns this: the
  // bytes are reassembled as UTF-8 instead of being handed over one character
  // each, which is why `Gr=C3=BC=C3=9Fe` used to render as `GrÃ¼Ã…e`.
  const [best] = decodeCandidates('Gr=C3=BC=C3=9Fe von M=C3=BCller');
  assert.equal(best.text, 'Grüße von Müller');
  assert.equal(best.method, 'quoted-printable');
});

test('a percent-encoded address is an encoded copy like any other', () => {
  // The form every click tracker writes, and the one encoding the chain did not
  // know: SendGrid, Mailchimp and HubSpot all put `?u=name%40domain` in the
  // destination.
  const [best] = decodeCandidates('max.mustermann%40example-mail.de');
  assert.equal(best.text, 'max.mustermann@example-mail.de');
  assert.equal(best.method, 'percent-encoded');

  const [twice] = decodeCandidates('max.mustermann%2540example-mail.de');
  assert.equal(twice.text, 'max.mustermann@example-mail.de', 'double encoding is ordinary in a URL');
});

test('a malformed percent sequence decodes to nothing', () => {
  assert.deepEqual(decodeCandidates('discount%ZZoffer%2'), []);
});

test('adjacent encoded-words join without the whitespace a client removes', () => {
  // RFC 2047 §6.2: whitespace between two adjacent encoded-words exists only to
  // let a long run be split across words (and folded lines), and is removed on
  // display. Keeping it rendered `café` as `caf é` on ordinary mail, and let a
  // sender split a token across two words to slip past a check that reads the
  // end of the string: a dangerous filename `report.ex` + `e` read as
  // `report.ex e` so the `.exe` check saw nothing while a client saves and runs
  // `report.exe`; a hidden address `ali` + `ce=40x.org` decoded to `ali ce@x.org`,
  // the wrong recipient found and the real one missed.
  const enc = (s) => Buffer.from(s, 'utf8').toString('base64');
  assert.equal(decodeEncodedWords(`=?utf-8?B?${enc('caf')}?= =?utf-8?B?${enc('é')}?=`), 'café');
  assert.equal(decodeEncodedWords('=?utf-8?Q?M=C3=BC?= =?utf-8?Q?ller?='), 'Müller');
  assert.equal(decodeEncodedWords(`=?utf-8?B?${enc('report.ex')}?=\t=?utf-8?B?${enc('e')}?=`), 'report.exe', 'a tab counts too');
  assert.deepEqual(
    findAddresses(decodeEncodedWords('=?utf-8?Q?ali?= =?utf-8?Q?ce=40example.org?=')),
    ['alice@example.org'],
  );

  // The boundary: whitespace between an encoded-word and ordinary text is kept —
  // only the whitespace between two encoded-words is removed. A blanket collapse
  // would glue apart words a client keeps apart.
  assert.equal(decodeEncodedWords(`=?utf-8?B?${enc('Hallo')}?= Welt`), 'Hallo Welt');
  assert.equal(decodeEncodedWords(`Von =?utf-8?B?${enc('Müller')}?=`), 'Von Müller');
});

test('an encoded-word with an RFC 2231 language tag is still decoded', () => {
  // RFC 2231 §5 decorates the charset with a language tag — `=?utf-8*en?B?…?=` —
  // and a conformant client drops the `*en` and decodes as utf-8.
  // `TextDecoder('utf-8*en')` throws, so the whole word was returned raw: a
  // subject rendered as its own gibberish, and a hidden address or filename
  // never decoded, so the disclosure and attachment checks read the raw word
  // and saw nothing. Same class as the attachment test in body.test.js, at the
  // decode layer that feeds every consumer.
  const enc = (s) => Buffer.from(s, 'utf8').toString('base64');
  assert.equal(decodeEncodedWords(`=?utf-8*en?B?${enc('café')}?=`), 'café', 'fidelity: the tag is dropped');
  assert.equal(decodeEncodedWords(`=?UTF-8*de?Q?Gr=C3=BC=C3=9Fe?=`), 'Grüße', 'case and Q-encoding too');
  assert.deepEqual(
    findAddresses(decodeEncodedWords(`=?utf-8*en?Q?ali?= =?utf-8*en?Q?ce=40example.org?=`)),
    ['alice@example.org'],
    'a hidden address split across two tagged words still joins',
  );

  // The boundary: a genuinely unknown charset has no tag to strip and nothing
  // safe to decode to, so it is left raw rather than force-decoded into a wrong
  // reading. Stripping only ever recovers a charset that exists.
  assert.equal(
    decodeEncodedWords('=?x-not-a-charset?B?aGVsbG8=?='),
    '=?x-not-a-charset?B?aGVsbG8=?=',
    'an unknown charset is left as written',
  );
});
