// Headers written to attack the reader rather than to be read by them.
//
// The rest of the suite feeds this project well-formed mail. This file feeds it
// mail whose sender is trying to control the program that opens it, which is
// the only input the tool is ever guaranteed to meet.
//
// The distinction that matters: the existing escape assertions in
// cli.test.js and terminal.test.js run over benign fixtures, so they have never
// once seen a hostile byte and cannot fail if the filtering is removed.
//
// These can. Stubbing `neutralise` to the identity function turns every test
// under "the rule" red, which is the check that this file is a gate and not
// decoration. tools/mutations.js now performs that stub on every CI run rather
// than leaving it as a sentence somebody is trusted to have verified. The finding tests stay green under that stub by design: they
// cover `scanControls`, which reports what was found and does not depend on
// what the renderer subsequently does about it.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { hasControls, neutralise, scanControls } from '../js/control.js';
import { analyse } from '../js/findings.js';
import { createRenderer } from '../js/terminal.js';
import { MAX_HEADER_BYTES, parseHeaders } from '../js/unfold.js';

const ESC = '\x1b';
const BEL = '\x07';

// Anything a terminal acts on, by Unicode category rather than by a list.
//
// These used to be two hand-written ranges — the same two js/control.js used,
// which meant the test could only catch what the code had already thought of.
// The C1 block passed both. A test that shares the code's blind spot is not a
// second opinion, so this asks Unicode instead: Cc covers C0, DEL and C1, Cf
// the format and bidi characters including any Unicode adds later, Co and Cs
// private use and lone surrogates, Zl and Zp the separators.
//
// Tab and newline are excluded deliberately: both are legitimate in rendered
// output, and neither steers anything.
const CONTROL_BYTE = /(?![\t\n])[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}]/u;
const UNICODE_CONTROL = CONTROL_BYTE;

const HEAD = [
  'From: Support <support@sender.example>',
  'To: you@example.org',
  'Date: Mon, 1 Jan 2026 00:00:00 +0000',
  'Message-ID: <abc@sender.example>',
  'Received: from a.example by b.example; Mon, 1 Jan 2026 00:00:00 +0000',
].join('\n');

const header = (...lines) => `${HEAD}\n${lines.join('\n')}\n`;

/**
 * Render through both the colour and the plain renderer.
 *
 * Both, because the isTTY check governs only this tool's own ANSI. With colour
 * off, the sender's escapes would be the only ones left in the stream — which
 * is the case a redirected report or a `--no-colour` run actually produces.
 */
const renderAll = (text) => {
  const findings = analyse(parseHeaders(text));
  return [
    createRenderer({ colour: false, width: 80 }).render(findings),
    createRenderer({ colour: true, width: 80 }).render(findings),
  ];
};

/** Strip this tool's own colour codes, leaving only what the header contributed. */
const senderBytes = (out) => out.replace(/\x1b\[[0-9;]*m/g, '');

// ------------------------------------------------------------------ the rule

test('no control byte from a header ever reaches the screen', () => {
  // One marker per field, spread across the values findings.js echoes verbatim.
  const out = renderAll(header(
    `X-Mailer: Mailer${ESC}[31mM1${ESC}[0m 1.0`,
    `List-ID: seg${ESC}[2KM2 <l.sender.example>`,
    `List-Owner: <mailto:owner${ESC}[1mM3@sender.example>`,
    `Feedback-ID: fb${ESC}[7mM4:1:2:3`,
    `DKIM-Signature: v=1; a=rsa-sha256; d=sig${ESC}[4mM5.example; s=k1; b=AAAA`,
    `X-Spam-Status: Yes${ESC}[5mM6, score=9`,
    `X-Campaign-ID: camp${ESC}[9mM7`,
  ));

  for (const rendered of out) {
    assert.doesNotMatch(senderBytes(rendered), CONTROL_BYTE);
  }
});

test('the ban holds for the escapes that do more than colour', () => {
  const out = renderAll(header(
    // Writes the reader's clipboard on kitty, wezterm, ghostty, tmux, xterm.
    `List-ID: ${ESC}]52;c;cm0gLXJmIH4=${BEL}seg <l.sender.example>`,
    // Survives defang() entirely: the scheme is one defang does not rewrite.
    `X-Mailer: ${ESC}]8;;file:///etc/passwd${ESC}\\Mailer 1.0${ESC}]8;;${ESC}\\`,
  ));

  for (const rendered of out) {
    const bytes = senderBytes(rendered);
    assert.doesNotMatch(bytes, CONTROL_BYTE);
    // Present, but inert — the point is that it is reported, not deleted.
    assert.match(bytes, /<1b>\]52;/, 'the clipboard write is still shown');
    assert.match(bytes, /<1b>\]8;;file:/, 'the hyperlink is still shown');
  }
});

test('a verdict cannot be repainted, hidden or scrolled away', () => {
  // ESC[8m with no reset conceals everything after it; ESC[2J ESC[H clears the
  // screen and homes the cursor, which is enough to replace the whole report.
  const out = renderAll(header(
    'Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail',
    `X-Mailer: ${ESC}[8mhidden${ESC}[2J${ESC}[H${ESC}[32m  ok ALL CHECKS PASSED`,
  ));

  for (const rendered of out) {
    assert.doesNotMatch(senderBytes(rendered), CONTROL_BYTE);
    // The real verdict is still there to be read.
    assert.match(rendered, /did not check out|dmarc/i);
  }
});

test('base64 this tool decodes cannot manufacture an escape', () => {
  // Nothing in the raw header looks dangerous: the value is pure base64. The
  // decoder is what turns it into a screen-clearing sequence.
  const payload = Buffer.from(`${ESC}[2J${ESC}[H  ok ALL CHECKS PASSED`).toString('base64');
  const out = renderAll(header(`X-Mailer-Info: ${payload}`));

  for (const rendered of out) {
    assert.doesNotMatch(senderBytes(rendered), CONTROL_BYTE);
  }
});

test('bidi and zero-width controls never reach a value', () => {
  // U+202E reverses what follows, so a hostname whose bytes read `evil` can be
  // displayed as something else entirely — on a tool whose whole job is to say
  // where a link really goes.
  const out = renderAll(header(
    'List-Unsubscribe: <https://evil\u202Eelpmaxe.example/unsub>',
    'X-Mailer: Out\u200Blook \u2066spoofed\u2069',
  ));

  for (const rendered of out) {
    // senderBytes first: with colour on, the stream also carries this tools own
    // ANSI, and the question here is only what the header contributed. The old
    // hand-written range happened not to include ESC, so this passed without
    // stripping — an accident, not a decision.
    assert.doesNotMatch(senderBytes(rendered), UNICODE_CONTROL);
  }
});

test('a header of ordinary text is left exactly as it was', () => {
  // The filter must not become a mangler: no legitimate value may change.
  const out = renderAll(header(
    'X-Mailer: Apple Mail (2.3774.600.62)',
    'List-ID: Weekly news <news.sender.example>',
  ));

  for (const rendered of out) {
    assert.doesNotMatch(rendered, /<[0-9a-f]{2}>|<U\+/, 'nothing was neutralised');
    assert.match(rendered, /Apple Mail \(2\.3774\.600\.62\)/);
  }
});

// --------------------------------------------------------------- the finding

test('a header that carries escapes is reported, not silently cleaned', () => {
  const findings = analyse(parseHeaders(header(
    `List-ID: ${ESC}]52;c;cm0gLXJmIH4=${BEL}seg <l.sender.example>`,
  )));

  // First, because it qualifies every finding under it.
  assert.equal(findings[0].tone, 'alert');
  assert.match(findings[0].title, /instructions/i);

  const values = findings[0].items.map((item) => `${item.label} ${item.value}`).join(' ');
  assert.match(values, /List-ID/);
  assert.match(values, /writes to your clipboard/);
});

test('an escape that only the decoder produces is reported too', () => {
  const payload = Buffer.from(`${ESC}]52;c;cm0gLXJmIH4=${BEL}`).toString('base64');
  const findings = analyse(parseHeaders(header(`X-Mailer-Info: ${payload}`)));

  assert.match(findings[0].title, /instructions/i);
  const values = findings[0].items.map((item) => `${item.label} ${item.value}`).join(' ');
  assert.match(values, /encoded value/i);
  assert.match(values, /writes to your clipboard/);
});

test('an ordinary header produces no such finding at all', () => {
  const findings = analyse(parseHeaders(header('X-Mailer: Apple Mail (2.3774.600.62)')));
  assert.doesNotMatch(findings[0].title, /instructions/i);
});

// ---------------------------------------------------------------- the module

test('neutralise names the byte it replaced', () => {
  assert.equal(neutralise(`a${ESC}b`), 'a<1b>b');
  assert.equal(neutralise('a\x00b'), 'a<00>b');
  assert.equal(neutralise('a\rb'), 'a<0d>b');
  assert.equal(neutralise('a\u202Eb'), 'a<U+202E>b');
});

test('neutralise leaves tab and newline alone', () => {
  // A decoded multi-line payload is printed line by line; folding it into one
  // line would invent breaks that were never there.
  assert.equal(neutralise('a\tb\nc'), 'a\tb\nc');
});

test('scanControls describes consequences, not byte counts', () => {
  assert.deepEqual(scanControls(`${ESC}]52;c;AAAA`), ['writes to your clipboard']);
  assert.deepEqual(scanControls(`${ESC}[2J`), ['erases part of the screen']);
  assert.deepEqual(scanControls('\u202Ea'), ['reverses the direction the text is read in']);
  assert.deepEqual(scanControls('ordinary text'), []);
});

test('scanControls does not pad a real sequence with a phantom one', () => {
  // The string terminator closing an OSC is part of the sequence already named.
  assert.deepEqual(scanControls(`${ESC}]8;;http://a.example${ESC}\\x${ESC}]8;;${ESC}\\`), [
    'turns text into a clickable link',
  ]);
});

// ------------------------------------------------------- cost of a hostile paste

// Wall-clock, deliberately. A shape assertion cannot fail on a regex that
// backtracks, which is the only failure these guard against. The numbers are
// ~20x the measured cost on the machine this was written on, so they catch a
// return to quadratic behaviour without going red on a slow runner.

const took = (fn) => {
  const started = Date.now();
  fn();
  return Date.now() - started;
};

test('a 128 KB header field analyses in well under a second', () => {
  // Measured before the quantifiers were bounded: 35 seconds. A message with
  // ten of these is deliverable — Postfix caps one header at 102400 octets and
  // does not cap how many a message carries.
  const ms = took(() => analyse(parseHeaders(`From: a@b.example\nX-Blob: ${'x'.repeat(131072)}\n`)));
  assert.ok(ms < 1000, `took ${ms}ms`);
});

test('40k spaces in a List-ID cost nothing', () => {
  // The old pattern paired a lazy `.*?` with a trailing anchor: 3.3 seconds.
  const ms = took(() => analyse(parseHeaders(`From: a@b.example\nList-ID: a${' '.repeat(40000)}a\n`)));
  assert.ok(ms < 200, `took ${ms}ms`);
});

test('a long run of dotted labels does not stall defang', () => {
  // Reachable through a List-ID whose brackets were omitted: 5.3 seconds.
  const ms = took(() => createRenderer({ colour: false, width: 80 }).render([
    { title: 'T', tone: 'neutral', items: [{ label: 'L', value: 'a.'.repeat(16000) }] },
  ]));
  assert.ok(ms < 300, `took ${ms}ms`);
});

test('the analysis still finds the addresses it always found', () => {
  // The bounds are only correct if they changed nothing that matters. A real
  // Received line, a real VERP bounce address, a real recipient.
  const findings = analyse(parseHeaders([
    'From: news@sender.example',
    'To: maja.beispiel@example.org',
    'Return-Path: <bounce-maja.beispiel=example.org@mail.sender.example>',
    'Received: from mx1.mail.sender.example (mx1.mail.sender.example [198.51.100.7])'
      + ' by mx.example.org; Mon, 1 Jan 2026 00:00:00 +0000',
  ].join('\n')));

  const text = JSON.stringify(findings);
  assert.match(text, /maja\.beispiel@example\.org/);
  assert.match(text, /mx1\.mail\.sender\.example/);
});

test('an oversized paste is clipped, and the CLI says so', () => {
  const ms = took(() => analyse(parseHeaders(
    `From: a@b.example\n${Array.from({ length: 10 }, (_, i) => `X-Blob${i}: ${'x'.repeat(102400)}`).join('\n')}\n`,
  )));
  // Measured at 217 seconds before the bounds; the ceiling is a second guard,
  // not the fix.
  assert.ok(ms < 2000, `took ${ms}ms`);
  assert.equal(MAX_HEADER_BYTES, 1024 * 1024);
});

// ------------------------------------------------------------ invented verdicts

test('a verdict this tool did not compute is never printed', () => {
  // Every lookup table is keyed by a word out of the header. On a plain object
  // `constructor` is not undefined, and used to render as an emphasised red
  // "Flagged as function Object() { [native code] }".
  const out = renderAll(header(
    'Authentication-Results: mx.example; spf=constructor; dkim=__proto__; dmarc=toString',
    'X-Forefront-Antispam-Report: CIP:1.2.3.4;SFTY:constructor;SCL:1',
  ));

  for (const rendered of out) {
    assert.doesNotMatch(rendered, /native code|\[object Object\]/);
  }
});

test('an unknown verdict says it is unknown', () => {
  const out = renderAll(header('Authentication-Results: mx.example; spf=constructor'));
  assert.match(out[0], /does not know/);
});

test('a homoglyph dot is bracketed like a real one', () => {
  // UTS-46 maps each of these to `.` while resolving, so they reach the same
  // host — and reached the screen unbracketed.
  const out = createRenderer({ colour: false, width: 80 }).render([{
    title: 'T',
    tone: 'neutral',
    items: [{ label: 'L', value: 'evil。com evil．com evil｡com' }],
  }]);
  assert.doesNotMatch(out, /evil[。．｡]com/);
  assert.equal(out.match(/evil\[\.\]com/g)?.length, 3);
});

// ------------------------------------------------------- the eight-bit forms

test('the 8-bit escape introducers are neutralised like their ESC forms', () => {
  // U+0080-U+009F is the C1 block: the same OSC, CSI, DCS and APC introducers
  // as the two-character ESC spellings, in one codepoint. xterm honours them in
  // UTF-8 mode by default. Both hand-written ranges this file and js/control.js
  // used to share missed the whole block, so these bytes reached the screen and
  // the report said nothing had been found — the two failures that make each
  // other hard to notice.
  const cp = (n) => String.fromCodePoint(n);

  for (const [name, value] of [
    ['OSC 52, clipboard write', `${cp(0x9d)}52;c;ZXZpbA==`],
    ['CSI erase', `${cp(0x9b)}2J`],
    ['CSI hide', `${cp(0x9b)}8m`],
    ['DCS payload', `${cp(0x90)}payload`],
  ]) {
    assert.doesNotMatch(neutralise(value), CONTROL_BYTE, name);
    assert.match(neutralise(value), /<U\+00[89][0-9A-F]>/, `${name} is named as a codepoint`);
  }
});

test('an 8-bit sequence is reported, in the same words as its ESC form', () => {
  // Neutralising without reporting is the half-fix: the reader sees <U+009D> in
  // the output and no finding explaining what it was for.
  const cp = (n) => String.fromCodePoint(n);

  assert.deepEqual(scanControls(`x${cp(0x9d)}52;c;ZXZpbA==`), ['writes to your clipboard']);
  assert.deepEqual(scanControls(`x${ESC}]52;c;ZXZpbA==`), ['writes to your clipboard']);
  assert.deepEqual(scanControls(`x${cp(0x9b)}2J`), ['erases part of the screen']);
});

test('the characters the old ranges forgot are all caught now', () => {
  const cp = (n) => String.fromCodePoint(n);

  for (const [name, code] of [
    ['line separator', 0x2028],
    ['paragraph separator', 0x2029],
    ['private use', 0xe000],
    ['Mongolian vowel separator', 0x180e],
  ]) {
    const value = `a${cp(code)}b`;
    assert.doesNotMatch(neutralise(value), CONTROL_BYTE, name);
    assert.ok(scanControls(value).length, `${name} is reported, not only defused`);
  }
});

test('what a reader legitimately sees is left exactly as it was', () => {
  // The category set is wide, and the cost of getting it wrong is a tool that
  // mangles the mail it exists to open. None of these are in any of the six
  // categories, and all of them are things this project actually renders.
  for (const value of [
    'Antwort an: Müller & Söhne — Größe 12',
    'À: jean@exemple.fr, Réponse à',
    '✓ ✗ ! ○ · ▸',
    'münchen.example / xn--mnchen-3ya.example',
    '請求書 · 発送 📦',
    'hxxps://evil[.]example/login',
    'a\tb\nc',
  ]) {
    assert.equal(neutralise(value), value);
    assert.equal(hasControls(value), false, value);
  }
});
