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

test('the unsubscribe destination is reported, but defanged', () => {
  const out = renderAll(BULK_HEADER);
  assert.match(out, /unsub/i, 'the destination is still shown');
  assert.match(out, /\[\.\]/, 'and it is bracketed');
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

test('the CLI reaches for nothing that could open a link', async () => {
  // The header analysis resolves redirects by decoding, never by fetching.
  // In a browser the CSP enforces that; here it has to be a test, and the
  // temptation is real, since a HEAD request would resolve a destination more
  // reliably than decoding does.
  const sources = await Promise.all(
    ['bin/kuvertii.js', 'js/terminal.js', 'js/clipboard.js', 'js/findings.js', 'js/links.js']
      .map((path) => readFile(new URL(`../${path}`, import.meta.url), 'utf8')),
  );
  for (const source of sources) {
    assert.doesNotMatch(source, /\bfetch\s*\(/, 'no fetch');
    assert.doesNotMatch(source, /node:(https?|net|dns)\b/, 'no network module');
    assert.doesNotMatch(source, /\brequire\(['"](https?|net|dns)['"]\)/, 'no network require');
    assert.doesNotMatch(source, /\bopen\b.*\bbrowser\b/i, 'nothing that opens a browser');
  }
});
