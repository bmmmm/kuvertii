// The terminal renderer, and the rule it exists to enforce.

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

import { analyse } from '../js/findings.js';
import { createRenderer, defang } from '../js/terminal.js';
import { parseHeaders } from '../js/unfold.js';
import { BULK_HEADER, MICROSOFT_HEADER } from './fixtures.js';

const plain = createRenderer({ colour: false, width: 80 });
const renderAll = (header) => plain.render(analyse(parseHeaders(header)));

test('a URL is broken so that no terminal can linkify it', () => {
  const out = defang('see https://track.example.com/click?id=7 for details');
  assert.match(out, /hxxps:/, 'scheme broken');
  assert.doesNotMatch(out, /https:\/\//);
  assert.match(out, /track\[\.\]example\[\.\]com/, 'dots bracketed');
});

test('every scheme gets its conventional spelling', () => {
  assert.match(defang('http://a.example'), /^hxxp:/);
  assert.match(defang('https://a.example'), /^hxxps:/);
  assert.match(defang('ftp://a.example'), /^fxp:/);
});

test('a bare hostname is bracketed too', () => {
  // A blocklist verdict names a domain with no scheme, and terminals link
  // those just as readily.
  assert.match(defang('login.paypa1-secure.example is listed'), /login\[\.\]paypa1-secure\[\.\]example/);
});

test('an email address stays readable', () => {
  // Its dots carry the meaning of the whole tool, and a mailto is harmless.
  const out = defang('maja.beispiel@example.org was the recipient');
  assert.match(out, /maja\.beispiel@example\.org/);
  assert.doesNotMatch(out, /\[\.\]/);
});

test('a base64 payload is not mistaken for a hostname', () => {
  // Inside a tracking blob, `u001.SdBcvi` reads as label-dot-TLD without being
  // a host. Bracketing it corrupts a value the reader may want to copy.
  const blob = 'u001.SdBcvi+Evd/bQef8eZF3BqAFEhjr7L5hwr+/dKejwhJSIGom3KureJpcrVe2sYRm';
  assert.equal(defang(blob), blob, 'left byte-for-byte intact');
});

test('a real hostname beside a payload is still defanged', () => {
  const out = defang(`sent via track.example.com id=${'A'.repeat(50)}+x/y`);
  assert.match(out, /track\[\.\]example\[\.\]com/, 'the short token is a host');
});

test('prose is left alone', () => {
  const sentence = 'Encoding is not encryption. It only assumes nobody looks.';
  assert.equal(defang(sentence), sentence);
});

test('no clickable link survives into rendered output', () => {
  // The rule this whole module exists for. A terminal turns a printed URL into
  // a click target on its own, so the output must contain no live one anywhere
  // — not in a value, not in a chip, not in a note.
  for (const header of [BULK_HEADER, MICROSOFT_HEADER]) {
    const out = renderAll(header);
    assert.doesNotMatch(out, /https?:\/\//, 'no live URL');
    assert.doesNotMatch(out, /\bftps?:\/\//, 'no live ftp URL');
    assert.doesNotMatch(out, /\x1b]8;;/, 'no OSC 8 hyperlink escape');
  }
});

test('a hostname in a label is defanged like any other', () => {
  // Blocklist verdicts put the offending domain in the label, which is the one
  // place a live link would be most harmful — the reader has just been told
  // the domain is hostile.
  const rendered = plain.renderFinding({
    id: 'x',
    title: 'Where the unsubscribe link really goes',
    tone: 'alert',
    items: [{
      label: 'login.paypa1-secure.example is on a phishing blocklist',
      value: 'Treat this link as hostile.',
      level: 'bad',
    }],
  });
  assert.match(rendered, /login\[\.\]paypa1-secure\[\.\]example/);
  assert.doesNotMatch(rendered, /login\.paypa1-secure\.example/);
});

test('a hostname in a title or lede is defanged too', () => {
  const rendered = plain.renderFinding({
    id: 'x',
    title: 'evil.example sent this',
    tone: 'alert',
    lede: 'The message came from evil.example.',
    items: [],
  });
  assert.doesNotMatch(rendered, /evil\.example/);
  assert.match(rendered, /evil\[\.\]example/);
});

test('the unsubscribe destination is reported, but defanged', () => {
  const out = renderAll(BULK_HEADER);
  assert.match(out, /unsub/i, 'the destination is still shown');
  assert.match(out, /\[\.\]/, 'and it is bracketed');
});

test('a verdict is marked, not only coloured', () => {
  // Colour is lost down a pipe, under NO_COLOR, on a monochrome terminal, and
  // for anyone who cannot tell red from green. The mark has to carry it.
  const rendered = plain.renderFinding({
    id: 'x',
    title: 'Checks',
    tone: 'info',
    items: [
      { label: 'SPF = pass', value: 'authorised', level: 'good' },
      { label: 'SPF = fail', value: 'not authorised', level: 'bad' },
      { label: 'Filtering skipped', value: 'a rule matched', level: 'caution' },
      { label: 'DKIM = none', value: 'nothing to check', level: 'absent' },
      { label: 'Signed by domain', value: 'example.org' },
    ],
  });
  assert.match(rendered, /✓ SPF = pass/);
  assert.match(rendered, /✗ SPF = fail/);
  assert.match(rendered, /! Filtering skipped/);
  assert.match(rendered, /○ DKIM = none/, 'an absence is marked, but not as a failure');
  assert.match(rendered, /· Signed by domain/, 'a plain row keeps the plain marker');
  assert.doesNotMatch(rendered, /\x1b\[/, 'and none of this needed colour');
});

test('the marks the page uses match the ones the terminal prints', async () => {
  // Two renderers, one vocabulary — a reader moving between them should not
  // have to learn a second set of symbols.
  const css = await readFile(new URL('../css/style.css', import.meta.url), 'utf8');
  assert.match(css, /\.item--good \.item__label::before \{ content: "✓"/);
  assert.match(css, /\.item--bad \.item__label::before \{ content: "✗"/);
  assert.match(css, /\.item--caution \.item__label::before \{ content: "!"/);
  assert.match(css, /\.item--fault \.item__label::before \{ content: "‡"/);
  assert.match(css, /\.item--absent \.item__label::before \{ content: "○"/);
});

test('colour is omitted entirely when switched off', () => {
  assert.doesNotMatch(renderAll(MICROSOFT_HEADER), /\x1b\[/);
});

test('colour is emitted when switched on', () => {
  const coloured = createRenderer({ colour: true, width: 80 });
  assert.match(coloured.render(analyse(parseHeaders(MICROSOFT_HEADER))), /\x1b\[/);
});

test('wrapping respects the given width', () => {
  const narrow = createRenderer({ colour: false, width: 40 });
  const lines = narrow.render(analyse(parseHeaders(MICROSOFT_HEADER))).split('\n');
  // Mono rows are printed verbatim by design; prose must fit.
  const prose = lines.filter((line) => /^ {0,4}[A-Z]/.test(line) && !line.includes('  ·'));
  for (const line of prose) {
    assert.ok(line.length <= 60, `line too long (${line.length}): ${line}`);
  }
});


test('a scheme is broken wherever it appears, not only at a word boundary', () => {
  // The bypass this closes: `\b` needs a non-word character on one side, and an
  // underscore is a word character, so `_https://evil.example/…` matched
  // nothing and was never split out for defanging. It then reached the hostname
  // pass inside a token long enough to read as an encoded payload, which spared
  // the host as well — scheme, host and path printed byte-for-byte.
  //
  // Terminals do not require a word boundary before linkifying. Neither do we.
  for (const value of [
    '_https://evil.example/login?u=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
    'x1https://evil.example/a',
    'read=https://evil.example/a',
    'https://evil.example/a',
  ]) {
    const out = defang(value);
    assert.doesNotMatch(out, /https:\/\//, value);
    assert.match(out, /hxxps:/, value);
    assert.doesNotMatch(out, /evil\.example/, `the host is bracketed too: ${value}`);
  }
});

test('a long payload token is still left alone, unless it carries a scheme', () => {
  // The exemption exists for a reason and keeps it: a tracking blob contains
  // stretches that read as label-dot-TLD, and bracketing them corrupts a value
  // the reader may want to copy verbatim.
  const blob = 'upn=aHR0cHM6Ly9zaG9wLmV4YW1wbGUu.SdBcvi+abc/def=';
  assert.equal(defang(blob), blob, 'a genuine payload is untouched');

  const withScheme = `${blob}https://evil.example/x`;
  assert.doesNotMatch(defang(withScheme), /https:\/\//, 'a scheme inside one is not exempt');
});
