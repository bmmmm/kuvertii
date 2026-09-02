// Properties every report must have, whatever the message said.
//
// The other test files ask whether a particular header produces a particular
// sentence. This one asks a different question: is the report internally
// consistent — does the headline agree with the rows underneath it. That is a
// property of the data, checkable without reading any of the English, and it is
// the check that was missing when a card announced "Every check passed" above a
// red SPF row.
//
// Driven by test/verdicts.js rather than by fixtures, because a fixture pair
// cannot express the combinations where a summary and its rows come apart.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { analyseBody } from '../js/body.js';
import { textFromMessageBytes } from '../js/decode.js';
import { ALL_CLEAR_TITLE, analyse, PASSED_BUT_JUNK_TITLE } from '../js/findings.js';
import { parseParts, splitMessage } from '../js/mime.js';
import { createRenderer } from '../js/terminal.js';
import { parseHeaders } from '../js/unfold.js';
import { authCombinations, compauthCombinations, DECISIVE } from './verdicts.js';

test('a card carrying a failure is never toned as though it were not', () => {
  // `bad` is the level reserved for "this is wrong and you should act on it".
  // A card containing one and toned `info` reads, at a glance and in colour, as
  // routine — and the glance is what most readers give it.
  const offenders = [];
  const everyMessage = [...authCombinations(), ...compauthCombinations()];

  for (const { verdicts, compauth, header } of everyMessage) {
    for (const finding of analyse(parseHeaders(header))) {
      const bad = finding.items.filter((i) => i.level === 'bad');
      if (bad.length && finding.tone !== 'alert') {
        const which = compauth ? `compauth=${compauth}` : JSON.stringify(verdicts);
        offenders.push(`${which} → ${finding.id} toned ${finding.tone} with ${bad.length} bad row(s)`);
      }
    }
  }

  assert.deepEqual(offenders.slice(0, 5), [], `${offenders.length} card(s) understate a failure`);
});

test('"every check passed" is never printed over a check that did not', () => {
  // The title is compared against the constant the code itself uses, so that
  // rewording it cannot quietly disarm this test — the failure mode a test
  // matching on its own copy of a sentence always has.
  const offenders = [];

  for (const { verdicts, header } of authCombinations()) {
    // Not just `fail`. The first version of this test asked only about the word
    // that had been reported, so the first version of the fix only handled that
    // word — and softfail, neutral, temperror, permerror, DKIM policy and DMARC
    // none all kept the all-clear headline. 168 combinations, invisible to a
    // test written against one example. A pass is a pass; everything else is
    // something a reader is owed.
    const notPassed = DECISIVE.filter((m) => verdicts[m] && verdicts[m] !== 'pass');
    if (!notPassed.length) continue;

    // Both spellings of the headline make the claim, so both are refused —
    // and the junk-filed spelling is only reachable under a filter verdict,
    // so every combination is also run with one.
    for (const message of [header, `X-Spam-Flag: yes\n${header}`]) {
      const auth = analyse(parseHeaders(message)).find((f) => f.id === 'auth');
      if (auth?.title === ALL_CLEAR_TITLE || auth?.title === PASSED_BUT_JUNK_TITLE) {
        offenders.push(`${JSON.stringify(verdicts)} — ${notPassed.map((m) => `${m}=${verdicts[m]}`).join(', ')}`);
      }
    }
  }

  assert.deepEqual(offenders.slice(0, 5), [], `${offenders.length} failing message(s) titled as clean`);
});

test('a composite-authentication failure also disqualifies "every check passed"', () => {
  // Microsoft's `compauth=fail` means someone outside wrote as though they were
  // a colleague. It rides in the same header, it is rendered as a red row, and
  // it fed nothing that decided the headline — so SPF, DKIM and DMARC all
  // passing was enough to title the card clean over it.
  for (const { compauth, header } of compauthCombinations()) {
    const auth = analyse(parseHeaders(header)).find((f) => f.id === 'auth');
    if (compauth === 'fail') {
      assert.notEqual(auth.title, ALL_CLEAR_TITLE, 'compauth=fail was titled as a clean pass');
      assert.notEqual(auth.title, PASSED_BUT_JUNK_TITLE, 'nor as a clean pass that was filed as junk');
      assert.equal(auth.tone, 'alert');
    }
  }
});

test('no combination of verdicts makes the analysis throw', () => {
  // The fault boundary exists so a producer that throws costs one section. It
  // must never be load-bearing for input the tool claims to understand, and
  // this is the widest set of such input there is.
  for (const { verdicts, header } of authCombinations()) {
    const faults = analyse(parseHeaders(header)).filter((f) => String(f.id).startsWith('fault:'));
    assert.deepEqual(faults, [], `a producer threw on ${JSON.stringify(verdicts)}`);
  }
});

// Fields whose values this tool decodes rather than merely prints. Everything
// a decoder can invent has to come out of one of these.
const DECODED_FIELDS = [
  'X-Mailer-Info', 'X-Mailer-Info-Extra', 'List-Unsubscribe', 'Feedback-Id',
  'X-Campaign-Id', 'Return-Path', 'X-SG-EID',
];

/** An opaque blob of the kind every bulk sender stamps — bytes, deterministically. */
const blob = (seed, length) => Buffer.from(
  Uint8Array.from({ length }, (_, i) => (i * seed + 11) % 256),
).toString('base64');

test('a decode the tool could not read is never put on screen', () => {
  // U+FFFD is the one character on a report that can only have come from this
  // tool: TextDecoder emits it where the bytes were not UTF-8, which is the
  // decoder saying it failed. So if the header carries none, no rendered line
  // may carry one either — a property of the output, checkable without reading
  // a word of it, and true of every message rather than of a chosen fixture.
  //
  // What it would have caught: a Klaviyo X-Mailer-Info folded mid-token. Half a
  // base64 token decodes to noise; the noise counted its replacement characters
  // as printable, scored 0.52 as prose, and was printed to the reader as
  // campaign metadata. Then the stray control bytes that come with random data
  // were read as intent, and an ordinary newsletter was headlined as a
  // deliberate attempt to control the reader's terminal.
  const offenders = [];

  for (const field of DECODED_FIELDS) {
    for (const seed of [7, 13, 37, 91, 137]) {
      for (const length of [24, 48, 96, 192]) {
        const token = blob(seed, length);
        // Folded and whole: the fold is what cuts a token in half, and half a
        // token is what decodes to bytes.
        for (const value of [token, `${token.slice(0, 40)}\n ${token.slice(40)}`]) {
          const header = `From: Sender <s@sender.example>\nTo: you@example.org\n${field}: ${value}\n`;
          const rendered = createRenderer({ colour: false, width: 80 }).render(analyse(parseHeaders(header)));
          if (rendered.includes('\uFFFD')) {
            offenders.push(`${field} seed=${seed} len=${length}${value.includes('\n') ? ' folded' : ''}`);
          }
        }
      }
    }
  }

  assert.deepEqual(offenders.slice(0, 5), [], `${offenders.length} render(s) printed a failed decode`);
});

// ------------------------------------------------ charsets only mail declares

/**
 * Deterministic double-byte characters, as bytes in a legacy 8-bit charset.
 *
 * The lead and trail ranges are ones EUC-KR and GBK both fill with ordinary
 * Hangul and Hanzi, so every pair generated here is a character a reader could
 * receive rather than a hole in the table.
 */
function wideRun(count, offset) {
  const bytes = [];
  for (let i = 0; i < count; i++) {
    bytes.push(0xb0 + ((i + offset) % 4), 0xa1 + ((i * 3 + offset) % 16));
  }
  return Uint8Array.from(bytes);
}

const ascii = (text) => Uint8Array.from(text, (c) => c.charCodeAt(0));
const join = (...runs) => Uint8Array.from(runs.flatMap((run) => [...run]));
const b64 = (bytes) => Buffer.from(bytes).toString('base64');

const ESC_DESIGNATOR = join([0x1b], ascii('$)C')); // ESC $ ) C — RFC 1557 §4
const SO = 0x0e;
const SI = 0x0f;

/**
 * The three 7-bit charsets, each paired with the 8-bit one it is a spelling of.
 *
 * Both spellings take the same segments — plain ASCII strings, and the
 * generated double-byte run — and return the bytes of that spelling. Nothing
 * here calls the code under test: the shifts are written out from RFC 1557 §4
 * and RFC 1843 §2 and the runs from RFC 2152, so the twin states independently
 * what the message says rather than asking the same decoder twice.
 */
const SPELLINGS = [
  {
    seven: 'iso-2022-kr',
    twin: 'euc-kr',
    eight: (segments) => join(...segments.map((s) => (typeof s === 'string' ? ascii(s) : s))),
    shifted: (segments) => join(ESC_DESIGNATOR, ...segments.map((s) => (typeof s === 'string'
      ? ascii(s)
      : join([SO], Uint8Array.from(s, (b) => b & 0x7f), [SI])))),
  },
  {
    seven: 'hz-gb-2312',
    twin: 'gbk',
    eight: (segments) => join(...segments.map((s) => (typeof s === 'string' ? ascii(s) : s))),
    shifted: (segments) => join(...segments.map((s) => (typeof s === 'string'
      ? ascii(s)
      : join(ascii('~{'), Uint8Array.from(s, (b) => b & 0x7f), ascii('~}'))))),
  },
  {
    seven: 'utf-7',
    twin: 'utf-8',
    eight: (segments) => join(...segments.map((s) => (typeof s === 'string'
      ? ascii(s)
      : new TextEncoder().encode(new TextDecoder('euc-kr').decode(s))))),
    shifted: (segments) => join(...segments.map((s) => {
      if (typeof s === 'string') return ascii(s);
      const text = new TextDecoder('euc-kr').decode(s);
      const units = [];
      for (let i = 0; i < text.length; i++) {
        units.push(text.charCodeAt(i) >> 8, text.charCodeAt(i) & 0xff);
      }
      return ascii(`+${b64(Uint8Array.from(units)).replace(/=+$/, '')}-`);
    })),
  },
];

/** Everything a reader is shown, plus the text each part was read as. */
function reportOf(source) {
  const { headerText, bodyText, bodyOnly } = splitMessage(source);
  const headers = parseHeaders(headerText);
  const { parts } = parseParts(headers, bodyText);
  const findings = [...analyse(headers), ...analyseBody(parts, { headers, bodyOnly })];
  return {
    screen: createRenderer({ colour: false, width: 78 }).render(findings),
    // Trailing line breaks are the one thing the twins may legitimately differ
    // in: a base64 part decodes to exactly its payload, while a part carried
    // without a transfer encoding keeps the break that ended its last line.
    // Nothing else is normalised — the comparison is otherwise character for
    // character, in both what was read and what is shown.
    text: JSON.stringify(parts.map((part) => String(part.text).replace(/\n+$/, ''))),
  };
}

const LEAD = ['From: Sender <s@sender.example>', 'To: you@example.org'];

/** The places a declared charset decides what the tool is looking at. */
const PLACEMENTS = [
  {
    what: 'subject',
    build: (label, word) => [
      ...LEAD, `Subject: ${word(label)}`, 'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=us-ascii', '', 'Hello.', '',
    ].join('\n'),
  },
  {
    what: 'attachment filename',
    build: (label, word) => [
      ...LEAD, 'Subject: Invoice', 'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary=B', '',
      '--B', 'Content-Type: text/plain', '', 'See attached.',
      '--B', 'Content-Type: application/octet-stream',
      `Content-Disposition: attachment; filename="${word(label, '.exe')}"`,
      'Content-Transfer-Encoding: base64', '', b64(ascii('AAAA')), '--B--', '',
    ].join('\n'),
  },
  {
    what: 'body, base64',
    build: (label, word, body) => [
      ...LEAD, 'Subject: Notice', 'MIME-Version: 1.0',
      `Content-Type: text/html; charset=${label}`, 'Content-Transfer-Encoding: base64',
      '', b64(body(label)), '',
    ].join('\n'),
  },
  {
    what: 'body, no transfer encoding',
    // The 7-bit spelling needs none by construction; its 8-bit twin cannot do
    // without one — which is the point. The transfer encoding must not decide
    // whether the charset is honoured, and this is the path that reached no
    // charset at all, the one `charset=utf-7` naturally arrives on.
    build: (label, word, body, sevenBit) => [
      ...LEAD, 'Subject: Notice', 'MIME-Version: 1.0',
      `Content-Type: text/html; charset=${label}`,
      `Content-Transfer-Encoding: ${sevenBit ? '7bit' : 'base64'}`, '',
      sevenBit ? String.fromCharCode(...body(label)) : b64(body(label)), '',
    ].join('\n'),
  },
];

test('a charset only mail uses reads as the message its 8-bit twin does', () => {
  // `TextDecoder` implements the Encoding Standard, which is written for
  // browsers: it leaves UTF-7 out and deliberately maps ISO-2022-KR and HZ onto
  // a refusal, because re-reading a page under a second encoding is how a
  // script gets past a filter that only looked at the first reading. A mail
  // client honours all three, so this tool inherited a blindness sitting
  // exactly where a sender would aim: a phishing anchor written `+ADw-a href…`
  // drew no link card whatever, and an attachment named in an ISO-2022-KR
  // encoded-word left the executable check reading a string ending in `?=`.
  //
  // Stated as a twin rather than as expected strings: the same characters, sent
  // once in the 8-bit charset every decoder knows and once in its 7-bit
  // spelling, are the same message and owe the reader the same report.
  const offenders = [];

  for (const spelling of SPELLINGS) {
    // The premise the rest of this rests on, stated rather than assumed: these
    // are the labels the platform refuses and their twins are the ones it
    // takes. If a runtime ever grows one of them, this line says so, and the
    // table in js/decode.js should give the platform its label back rather than
    // keep shadowing a decoder that now exists.
    assert.throws(() => new TextDecoder(spelling.seven), RangeError, `${spelling.seven} is refused`);
    assert.doesNotThrow(() => new TextDecoder(spelling.twin), `${spelling.twin} is known`);

    for (const offset of [0, 1, 5, 9]) {
      const wide = wideRun(6 + (offset % 3), offset);
      const spell = (label, segments) => (label === spelling.seven
        ? spelling.shifted(segments) : spelling.eight(segments));
      const word = (label, extra) => `=?${label}?B?${b64(spell(label, extra ? [wide, extra] : [wide]))}?=`;
      const body = (label) => spell(label, [
        '<p>', wide, '</p><a href="https://secure-paypa1.example/login">', wide, '</a>',
      ]);

      for (const placement of PLACEMENTS) {
        const mine = reportOf(placement.build(spelling.seven, word, body, true));
        const twin = reportOf(placement.build(spelling.twin, word, body, false));
        if (mine.screen !== twin.screen || mine.text !== twin.text) {
          offenders.push(`${spelling.seven} vs ${spelling.twin} in ${placement.what} (offset ${offset})`);
        }
      }
    }
  }

  assert.deepEqual(offenders.slice(0, 5), [], `${offenders.length} message(s) read unlike their twin`);
});

test('a message file in any 8-bit charset never puts U+FFFD on screen', () => {
  // The file and pipe paths hand bytes to textFromMessageBytes; a paste never
  // gets here. Every byte value, once as an 8bit body under a latin-1 label and
  // once as a raw header value: the decoder may pick the wrong letters for a
  // charset it was not told about, but never the one character that means it
  // failed — U+FFFD is the tool's own signature, not the sender's.
  const every = Uint8Array.from({ length: 256 }, (_, i) => i);
  const head = new TextEncoder().encode(
    'From: a@example.org\nTo: b@example.net\nSubject: x\nX-Note: ',
  );
  const middle = new TextEncoder().encode(
    '\nContent-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: 8bit\n\n',
  );
  // A header value cannot carry the line breaks in `every`, so it gets the
  // high half only; the body gets all 256.
  const bytes = Uint8Array.from([...head, ...every.subarray(0xa0), ...middle, ...every]);

  const text = textFromMessageBytes(bytes);
  assert.ok(!text.includes('�'), 'the decode itself invented nothing');

  const { headerText, bodyText, bodyOnly } = splitMessage(text);
  const headers = parseHeaders(headerText);
  const { parts } = parseParts(headers, bodyText);
  const findings = [...analyse(headers), ...analyseBody(parts, { headers, bodyOnly })];
  const rendered = JSON.stringify(findings);
  assert.ok(!rendered.includes('�'), 'nothing rendered carries U+FFFD');
});

test('a UTF-8 message file decodes exactly, and a windows-1252 one keeps its euro', () => {
  const utf8 = new TextEncoder().encode('Subject: Grüße — 5 €\n');
  assert.equal(textFromMessageBytes(utf8), 'Subject: Grüße — 5 €\n');
  // 0x80 is € in windows-1252 and a control character in ISO-8859-1: the
  // superset is the right fallback because a Windows client wrote it.
  const cp1252 = Uint8Array.from([0x35, 0x20, 0x80, 0x0a]);
  assert.equal(textFromMessageBytes(cp1252), '5 €\n');
});
