// Smoke test for the UI layer against a minimal DOM stub.
//
// The unit tests prove the analysis is right; this proves the page actually
// runs it — that app.js finds its elements, renders without throwing, and puts
// the recipient on screen. Without it, a typo in a selector would only ever
// surface in a browser.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { BULK_HEADER, RECIPIENT } from './fixtures.js';

function stubNode(tag = 'div') {
  const node = {
    tag,
    className: '',
    textContent: '',
    hidden: false,
    // `<details>` state, and the two things a jump does to a card. Recorded
    // rather than ignored: "the report is brought into view" is a promise now,
    // and a spy that swallows the call cannot tell whether it was kept.
    open: false,
    scrolledIntoView: [],
    clicks: 0,
    children: [],
    classList: {
      add(...c) { node.className += ` ${c.join(' ')}`; },
      remove(...c) {
        node.className = node.className.split(/\s+/)
          .filter((name) => name && !c.includes(name))
          .join(' ');
      },
      contains(name) { return node.className.split(/\s+/).includes(name); },
    },
    append(...kids) { node.children.push(...kids); },
    replaceChildren(...kids) { node.children = kids; },
    addEventListener(type, handler) { (node.handlers[type] ??= []).push(handler); },
    focus() { globalThis.document.activeElement = node; },
    click() { node.clicks += 1; },
    scrollIntoView(options) { node.scrolledIntoView.push(options); },
    handlers: {},
  };
  return node;
}

/** Fire every handler registered for `type`, with an event the page can use. */
function fire(node, type, event = {}) {
  const fake = { defaultPrevented: false, preventDefault() { fake.defaultPrevented = true; }, ...event };
  for (const handler of node.handlers[type] ?? []) handler(fake);
  return fake;
}

/** Let a `setTimeout(…, 0)` and any pending microtask run. */
const settle = () => new Promise((resolve) => { setTimeout(resolve, 0); });

/**
 * A File as this page uses it: a size to check and bytes to await — UTF-8 from
 * `text` unless `bytes` are given. No text() on purpose: the browser's own
 * UTF-8 decode is exactly what the page must not use on a message file.
 */
function stubFile(text, size, bytes = new TextEncoder().encode(text)) {
  return {
    size: size ?? bytes.byteLength,
    async arrayBuffer() { return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength); },
  };
}

/** The findings' cards, without the overview that leads them. */
const cardsOf = (results) => results.children.slice(1);
const toneOf = (card) => card.className.split(/\s+/).find((c) => c.startsWith('card--'))?.slice(6);

/** Flatten the rendered tree into text, the way a reader would see it. */
function renderedText(node) {
  return [node.textContent, ...node.children.map(renderedText)].filter(Boolean).join('\n');
}

/** Every node in the tree whose class list contains `name`. */
function byClass(node, name) {
  const here = node.className?.split(/\s+/).includes(name) ? [node] : [];
  return [...here, ...node.children.flatMap((child) => byClass(child, name))];
}

async function loadApp({ wide = true } = {}) {
  const nodes = {
    '#header-input': stubNode('textarea'),
    '#input-area': stubNode('section'),
    '#file-input': stubNode('input'),
    '#results': stubNode(),
    '#empty-state': stubNode(),
    '#status': stubNode(),
    '#analyse': stubNode('button'),
    '#clear': stubNode('button'),
    '#open-file': stubNode('button'),
  };
  nodes['#header-input'].value = '';
  nodes['#file-input'].value = '';
  nodes['#file-input'].files = [];

  globalThis.document = {
    querySelector: (selector) => nodes[selector] ?? null,
    createElement: (tag) => stubNode(tag),
    activeElement: null,
  };
  // `wide` is the whole difference between a desktop report and a phone one:
  // every non-alert card reads it once, at render time.
  globalThis.window = {
    addEventListener() {},
    matchMedia: (media) => ({ media, matches: wide }),
  };
  // The blocklist is fetched lazily; the stub keeps the smoke test offline.
  globalThis.fetch = async () => { throw new Error('offline in tests'); };

  // Fresh module instance per test — app.js wires listeners on import.
  await import(`../js/app.js?t=${nodes ? Math.round(performance.now() * 1000) : 0}`);
  return nodes;
}

test('the page wires up and renders findings for a pasted header', async () => {
  const nodes = await loadApp();

  nodes['#header-input'].value = BULK_HEADER;
  for (const handler of nodes['#analyse'].handlers.click) handler();

  const output = renderedText(nodes['#results']);
  assert.match(output, new RegExp(RECIPIENT.replace('.', '\\.')), 'recipient shown');
  assert.match(output, /addressed to/i, 'the headline finding is rendered');
  assert.equal(nodes['#empty-state'].hidden, true, 'empty state hidden once there is output');
  assert.match(nodes['#status'].textContent, /Nothing left this page/);
});

test('structural facts render as chips rather than prose', async () => {
  const nodes = await loadApp();
  nodes['#header-input'].value = BULK_HEADER;
  for (const handler of nodes['#analyse'].handlers.click) handler();

  const chips = byClass(nodes['#results'], 'chip').map((c) => c.textContent);
  assert.ok(chips.length > 0, 'chips are rendered');
  assert.ok(
    chips.some((c) => /X-Mailer-Info/.test(c)),
    'the places an address was hidden become individual chips',
  );
});

test('a note shared by several rows is shown once per card', async () => {
  const nodes = await loadApp();
  // ARC and BIMI both carry the same "informational" caveat; a reader needs
  // to be told once, not once per row.
  nodes['#header-input'].value =
    'Authentication-Results: mx.example.net; arc=none; bimi=skipped\n';
  for (const handler of nodes['#analyse'].handlers.click) handler();

  const notes = byClass(nodes['#results'], 'item__note').map((n) => n.textContent);
  assert.equal(new Set(notes).size, notes.length, 'no note is repeated within a card');

  // Both rows still appear — deduplication touches the prose, never the data.
  const output = renderedText(nodes['#results']);
  assert.match(output, /ARC = none/);
  assert.match(output, /BIMI = skipped/);
});

test('clear wipes the input and the rendered output', async () => {
  const nodes = await loadApp();

  nodes['#header-input'].value = BULK_HEADER;
  for (const handler of nodes['#analyse'].handlers.click) handler();
  assert.ok(nodes['#results'].children.length > 0, 'precondition: something rendered');

  for (const handler of nodes['#clear'].handlers.click) handler();
  assert.equal(nodes['#header-input'].value, '');
  assert.equal(nodes['#results'].children.length, 0);
  assert.equal(nodes['#empty-state'].hidden, false);
});

test('empty input renders nothing and does not throw', async () => {
  const nodes = await loadApp();
  nodes['#header-input'].value = '   ';
  for (const handler of nodes['#analyse'].handlers.click) handler();
  assert.equal(nodes['#results'].children.length, 0);
});

test('a decoded payload cannot forge a row in either renderer', async () => {
  // A base64 field decoding to "\n  ✓ SPF = pass\n    The message is authentic."
  // rendered as two further lines in this tool's own idiom, carrying this
  // tool's own mark, asserting something it never computed. `neutralise` spares
  // newlines on purpose — a multi-line payload reads better as lines — so the
  // renderers have to make clear whose lines they are.
  //
  // Asserted against both renderers from one analysis, because a guarantee that
  // exists in one and not the other is the shape of half this project's bugs.
  const forged = Buffer.from('x\n  ✓ SPF = pass\n    The message is authentic.').toString('base64');
  const header = [
    'From: a@evil.example',
    'To: reader@example.org',
    'Subject: t',
    'Date: Mon, 17 Aug 2026 18:13:58 +0200',
    'Message-ID: <x@y>',
    `X-Mailer-Info: ${forged}`,
  ].join('\n');

  const { analyse } = await import('../js/findings.js');
  const { createRenderer } = await import('../js/terminal.js');
  const { parseHeaders } = await import('../js/unfold.js');
  const findings = analyse(parseHeaders(header));

  // The terminal marks every line of a multi-line payload with a gutter.
  const rendered = createRenderer({ colour: false, width: 80 }).render(findings);
  const forgedLine = rendered.split('\n').find((l) => l.includes('✓ SPF = pass'));
  assert.ok(forgedLine, 'the payload is still shown — nothing is hidden from the reader');
  assert.match(forgedLine, /│/, 'and it is quoted, not presented as one of our own rows');

  // The page marks the same block with a class the stylesheet quotes.
  const nodes = await loadApp();
  nodes['#header-input'].value = header;
  for (const handler of nodes['#analyse'].handlers.click) handler();
  const quoted = byClass(nodes['#results'], 'item__value--quoted');
  assert.ok(quoted.length > 0, 'the page quotes it too');
  assert.ok(
    quoted.some((n) => n.textContent.includes('✓ SPF = pass')),
    'and it is the block carrying the forgery',
  );
});

test('no hostile byte from a header reaches the page', async () => {
  // Every escape-stripping test in this suite drove the terminal renderer. The
  // page has its own call to `neutralise`, at a single site, and that site could
  // be deleted with all 224 other tests still green — so the browser half of
  // the project's headline safety claim was ungated on the page it is written
  // about. This is the same question test/hostile.test.js asks of the terminal,
  // asked of the DOM instead.
  const cp = (n) => String.fromCodePoint(n);
  const HOSTILE = /(?![\t\n])[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}]/u;

  const header = [
    'From: Support <support@sender.example>',
    'To: reader@example.org',
    'Date: Mon, 1 Jan 2026 00:00:00 +0000',
    'Message-ID: <abc@sender.example>',
    `List-ID: ${cp(0x1b)}]52;c;cm0gLXJmIH4=${cp(0x07)}seg <l.sender.example>`,
    `X-Mailer: Out${cp(0x200b)}look ${cp(0x2066)}spoofed${cp(0x2069)}`,
    `X-Campaign: paypal-${cp(0x202e)}moc.live`,
    `X-Note: erase${cp(0x9b)}2J and hide${cp(0x9b)}8m`,
  ].join('\n');

  const nodes = await loadApp();
  nodes['#header-input'].value = header;
  for (const handler of nodes['#analyse'].handlers.click) handler();

  const shown = renderedText(nodes['#results']);
  assert.ok(shown.length > 0, 'something was rendered at all');
  assert.doesNotMatch(shown, HOSTILE, 'a control or format character reached the page');
  assert.match(shown, /instructions, not just text/, 'and the attempt is reported, not silently cleaned');
});

test('no live URL reaches the page either', async () => {
  // The terminal defangs because terminals linkify plain text. A browser does
  // not linkify textContent, so the page has never needed defanging — but it
  // must still never construct a link, and the value it shows must be the one
  // the analysis decoded rather than a clickable version of it.
  const nodes = await loadApp();
  nodes['#header-input'].value = [
    'From: Shop <news@shop.example>',
    'To: reader@example.org',
    'Date: Mon, 1 Jan 2026 00:00:00 +0000',
    'Message-ID: <abc@shop.example>',
    'List-Unsubscribe: <https://u1.ct.sendgrid.net/ls/click?upn=abcdef>',
  ].join('\n');
  for (const handler of nodes['#analyse'].handlers.click) handler();

  const anchors = [];
  const walk = (node) => {
    if (node.tag === 'a') anchors.push(node);
    node.children.forEach(walk);
  };
  walk(nodes['#results']);

  assert.deepEqual(anchors, [], 'the page built an anchor out of header text');
});

// ---------------------------------------------------------------- reading it
//
// Everything below is about the page as a phone reader meets it: a paste that
// reads itself, a report that says what is in it before the scrolling starts,
// and a file that never goes anywhere near a network.

test('a paste reads the message without a second click', async () => {
  const nodes = await loadApp();

  // The value lands after the paste event, which is why the page defers: read
  // synchronously, this would have analysed the empty field.
  fire(nodes['#header-input'], 'paste');
  nodes['#header-input'].value = BULK_HEADER;
  await settle();

  assert.ok(nodes['#results'].children.length > 0, 'the paste alone produced a report');
  assert.match(nodes['#status'].textContent, /Nothing left this page/);
});

test('a paste of nothing produces nothing rather than an error', async () => {
  const nodes = await loadApp();
  fire(nodes['#header-input'], 'paste');
  await settle();
  assert.equal(nodes['#results'].children.length, 0);
});

test("the overview names every card once, in the card's own tone", async () => {
  const nodes = await loadApp();
  nodes['#header-input'].value = BULK_HEADER;
  for (const handler of nodes['#analyse'].handlers.click) handler();

  const [overview] = nodes['#results'].children;
  assert.ok(overview.classList.contains('overview'), 'the overview leads the results');
  assert.equal(overview.tag, 'nav');
  assert.equal(overview.ariaLabel, 'Report overview');

  const cards = cardsOf(nodes['#results']);
  const jumps = byClass(overview, 'overview__jump');
  assert.ok(cards.length > 1, 'sanity: this header produces several cards');
  assert.equal(jumps.length, cards.length, 'one jump per card, no more and no fewer');

  cards.forEach((card, i) => {
    const title = byClass(card, 'card__title')[0].textContent;
    assert.equal(jumps[i].textContent, title, 'a jump is labelled with the card it points at');
    assert.ok(
      jumps[i].classList.contains(`overview__jump--${toneOf(card)}`),
      `jump ${i} carries the tone of its card`,
    );
  });

  const tally = byClass(overview, 'overview__tally')[0].textContent;
  const counted = [...tally.matchAll(/(\d+)\s/g)].reduce((sum, [, n]) => sum + Number(n), 0);
  assert.equal(counted, cards.length, `the tally counts every card: ${tally}`);
});

test('a jump opens a collapsed card, scrolls to it and puts focus in it', async () => {
  const nodes = await loadApp({ wide: false });
  nodes['#header-input'].value = BULK_HEADER;
  for (const handler of nodes['#analyse'].handlers.click) handler();

  const [overview] = nodes['#results'].children;
  const cards = cardsOf(nodes['#results']);
  const jumps = byClass(overview, 'overview__jump');

  const index = cards.findIndex((card) => card.tag === 'details');
  assert.ok(index >= 0, 'sanity: a narrow screen collapses at least one card');
  const card = cards[index];
  assert.equal(card.open, false, 'precondition: it starts closed');

  fire(jumps[index], 'click');

  assert.equal(card.open, true, 'the jump opened it — a closed card cannot be read');
  assert.deepEqual(card.scrolledIntoView, [{ block: 'start' }]);
  assert.equal(globalThis.document.activeElement, card, 'and focus followed the scroll');
  assert.equal(card.tabIndex, -1, 'reachable by focus, not by tabbing');
});

test('a finished report is brought into view rather than left below the fold', async () => {
  const nodes = await loadApp({ wide: false });
  nodes['#header-input'].value = BULK_HEADER;
  for (const handler of nodes['#analyse'].handlers.click) handler();

  const [overview] = nodes['#results'].children;
  assert.deepEqual(overview.scrolledIntoView, [{ block: 'start' }], 'the report scrolled itself into view');
  assert.equal(globalThis.document.activeElement, overview, 'and focus is on it, not on the body');
  assert.equal(overview.tabIndex, -1);
});

test('notes fold on a narrow screen and stand open on a wide one', async () => {
  for (const wide of [true, false]) {
    const nodes = await loadApp({ wide });
    nodes['#header-input'].value = BULK_HEADER;
    for (const handler of nodes['#analyse'].handlers.click) handler();

    const foldable = cardsOf(nodes['#results']).filter((card) => card.tag === 'details');
    assert.ok(foldable.length > 0, 'sanity: some cards are foldable');
    for (const card of foldable) {
      assert.equal(card.open, wide, `a foldable card is ${wide ? 'open' : 'closed'} at this width`);
    }
  }
});

test('an alert card is never one of the foldable ones', async () => {
  // The card a hurried reader came for is the one that must not need a tap.
  const nodes = await loadApp({ wide: false });
  nodes['#header-input'].value = BULK_HEADER;
  for (const handler of nodes['#analyse'].handlers.click) handler();

  const alerts = cardsOf(nodes['#results']).filter((card) => toneOf(card) === 'alert');
  assert.ok(alerts.length > 0, 'sanity: this header raises at least one alert');
  for (const card of alerts) {
    assert.equal(card.tag, 'section', 'an alert stays a plain section');
    assert.equal(byClass(card, 'card__summary').length, 0, 'and has nothing to expand');
  }
});

test('the Open a file button reaches the hidden input rather than a dialog of its own', async () => {
  const nodes = await loadApp();
  fire(nodes['#open-file'], 'click');
  assert.equal(nodes['#file-input'].clicks, 1);
});

test('a chosen file is read and analysed, and its name does not linger', async () => {
  const nodes = await loadApp();
  nodes['#file-input'].files = [stubFile(BULK_HEADER)];

  fire(nodes['#file-input'], 'change', { target: nodes['#file-input'] });
  await settle();

  assert.equal(nodes['#header-input'].value, BULK_HEADER, 'the file landed in the same field a paste uses');
  assert.ok(nodes['#results'].children.length > 0, 'and was read');
  assert.equal(nodes['#file-input'].value, '', 'the input is reset, so the same file can be picked again');
});

test('a file too large to be a message is refused rather than read', async () => {
  const nodes = await loadApp();
  let touched = false;
  nodes['#file-input'].files = [{
    size: 33 * 1024 * 1024,
    async arrayBuffer() { touched = true; return new TextEncoder().encode(BULK_HEADER).buffer; },
  }];

  fire(nodes['#file-input'], 'change', { target: nodes['#file-input'] });
  await settle();

  assert.equal(touched, false, 'the bytes were never read at all');
  assert.equal(nodes['#header-input'].value, '', 'nothing was loaded');
  assert.equal(nodes['#results'].children.length, 0);
  assert.match(nodes['#status'].textContent, /32 MB/, 'and the reader is told why');
});

test('a dropped file takes the same path as a chosen one', async () => {
  const nodes = await loadApp();

  const over = fire(nodes['#input-area'], 'dragover');
  assert.equal(over.defaultPrevented, true, 'or the browser navigates to the file instead');
  assert.ok(nodes['#input-area'].classList.contains('input-area--drop'));

  fire(nodes['#input-area'], 'dragleave');
  assert.equal(nodes['#input-area'].classList.contains('input-area--drop'), false);

  const drop = fire(nodes['#input-area'], 'drop', { dataTransfer: { files: [stubFile(BULK_HEADER)] } });
  await settle();

  assert.equal(drop.defaultPrevented, true);
  assert.equal(nodes['#header-input'].value, BULK_HEADER);
  assert.ok(nodes['#results'].children.length > 0, 'the drop produced a report');
  assert.equal(nodes['#input-area'].classList.contains('input-area--drop'), false);
});

test('the textarea shrinks once it has been read, and opens again to edit', async () => {
  const nodes = await loadApp();
  const area = nodes['#input-area'];
  nodes['#header-input'].value = BULK_HEADER;
  for (const handler of nodes['#analyse'].handlers.click) handler();
  assert.ok(area.classList.contains('input-area--read'), 'a read report collapses the paste');

  fire(nodes['#header-input'], 'focus');
  assert.equal(area.classList.contains('input-area--read'), false, 'clicking in re-opens it');

  for (const handler of nodes['#analyse'].handlers.click) handler();
  assert.ok(area.classList.contains('input-area--read'));
  for (const handler of nodes['#clear'].handlers.click) handler();
  assert.equal(area.classList.contains('input-area--read'), false, 'and clear leaves nothing collapsed');
});

test('a file in a legacy charset is read as the sender wrote it, not as U+FFFD', async () => {
  // `file.text()` decodes as UTF-8 and writes U+FFFD where these bytes are
  // not — before js/mime.js has seen one. The invariant that no invented
  // U+FFFD reaches the screen has to hold from the file picker onwards, so the
  // page decodes the bytes itself (js/decode.js, textFromMessageBytes).
  const nodes = await loadApp();
  const latin1 = Uint8Array.from(`Comments: Best\xe4tigung n\xf6tig\n${BULK_HEADER}`, (c) => c.charCodeAt(0));
  nodes['#file-input'].files = [stubFile('', undefined, latin1)];

  fire(nodes['#file-input'], 'change', { target: nodes['#file-input'] });
  await settle();

  assert.match(nodes['#header-input'].value, /Bestätigung nötig/, 'the umlauts survived the read');
  assert.ok(!nodes['#header-input'].value.includes('�'), 'no replacement character was invented');
  assert.ok(nodes['#results'].children.length > 0, 'and the message was read');
  assert.ok(!renderedText(nodes['#results']).includes('�'), 'nothing on screen carries one either');
});
