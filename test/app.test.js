// Smoke test for the UI layer against a minimal DOM stub.
//
// The unit tests prove the analysis is right; this proves the page actually
// runs it — that app.js finds its elements, renders without throwing, and puts
// the recipient on screen. Without it, a typo in a selector would only ever
// surface in a browser.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { byClass, fire, loadApp, renderedText } from './dom-stub.js';
import { BULK_HEADER, RECIPIENT } from './fixtures.js';

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
  assert.equal(
    globalThis.document.activeElement,
    nodes['#header-input'],
    'the button is a gesture, so the cursor goes back where the next paste lands',
  );
});

test('a restored page discards the message without calling up the keyboard', async () => {
  // Back-navigation out of the bfcache restores form fields, which would
  // resurrect a header the reader believed they had discarded. Discarding it is
  // right; focusing the field is not — on a phone that raises the keyboard over
  // a page nobody tapped.
  const nodes = await loadApp();
  nodes['#header-input'].value = BULK_HEADER;
  fire(nodes['#analyse'], 'click');
  assert.ok(nodes['#results'].children.length > 0, 'precondition: something rendered');

  fire(nodes.window, 'pageshow', { persisted: true });

  assert.equal(nodes['#header-input'].value, '', 'the restored header is gone');
  assert.equal(nodes['#results'].children.length, 0, 'and so is the report about it');
  assert.notEqual(
    globalThis.document.activeElement,
    nodes['#header-input'],
    'no keyboard without a gesture',
  );
});

test('an ordinary load leaves a freshly pasted message alone', async () => {
  // `pageshow` fires on every navigation, restored or not. Without the
  // `persisted` check this wipes the report a reader has just produced —
  // which is worse than the keyboard it was added to stop.
  const nodes = await loadApp();
  nodes['#header-input'].value = BULK_HEADER;
  fire(nodes['#analyse'], 'click');

  fire(nodes.window, 'pageshow', { persisted: false });

  assert.equal(nodes['#header-input'].value, BULK_HEADER, 'the message is still there');
  assert.ok(nodes['#results'].children.length > 0, 'and the report with it');
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

/** A drag as the browser describes one: the cargo is in `types`, not in `files`. */
const fileDrag = (...files) => ({ dataTransfer: { types: ['Files'], files } });

test('a file that will not be read is reported as unread, by either route', async () => {
  // Without the catch this test does not merely fail: the two call sites invoke
  // an async function as a bare statement, so the rejection is unhandled and
  // Node tears down the whole test file around it.
  const unreadable = {
    size: 512,
    async arrayBuffer() { throw Object.assign(new Error('device stalled'), { name: 'NotReadableError' }); },
  };

  for (const hand of ['picker', 'drop']) {
    const nodes = await loadApp();
    if (hand === 'picker') {
      nodes['#file-input'].files = [unreadable];
      fire(nodes['#file-input'], 'change', { target: nodes['#file-input'] });
    } else {
      fire(nodes.window, 'drop', fileDrag(unreadable));
    }
    await settle();

    assert.equal(nodes['#header-input'].value, '', `${hand}: nothing was loaded`);
    assert.equal(nodes['#results'].children.length, 0, `${hand}: and no report claims otherwise`);
    assert.match(nodes['#status'].textContent, /could not be read/, `${hand}: the reader is told`);
    assert.match(nodes['#status'].textContent, /NotReadableError/, `${hand}: and what kind of failure it was`);
    assert.ok(
      !nodes['#status'].textContent.includes('device stalled'),
      `${hand}: the browser's prose stays out — it can quote the file name, which is the subject line`,
    );
  }
});

test('a file dropped anywhere on the page is read, not opened by the browser', async () => {
  // The guards are on `window` because `#results` is a sibling of the input
  // area, not a child: after a report is rendered it is most of the screen, and
  // a drop that misses the textarea used to reach no preventDefault at all —
  // the browser then left the page and rendered the message in the tab.
  const nodes = await loadApp();

  const over = fire(nodes.window, 'dragover', fileDrag());
  assert.equal(over.defaultPrevented, true, 'or the browser navigates to the file instead');

  const drop = fire(nodes.window, 'drop', fileDrag(stubFile(BULK_HEADER)));
  await settle();

  assert.equal(drop.defaultPrevented, true);
  assert.equal(nodes['#header-input'].value, BULK_HEADER, 'the drop took the file picker\'s path');
  assert.ok(nodes['#results'].children.length > 0, 'the drop produced a report');
  assert.equal(nodes['#input-area'].classList.contains('input-area--drop'), false);
});

test('a drag across the page keeps saying where the file will land', async () => {
  const nodes = await loadApp();
  const area = nodes['#input-area'];

  fire(nodes.window, 'dragenter', fileDrag());
  assert.ok(area.classList.contains('input-area--drop'), 'the target is named as soon as a file is over the page');

  // Crossing from one element to the next: the child is entered before the
  // parent is left, so the frame must survive the pair.
  fire(nodes.window, 'dragenter', fileDrag());
  fire(nodes.window, 'dragleave', fileDrag());
  assert.ok(area.classList.contains('input-area--drop'), 'an element boundary is not the drag leaving');

  fire(nodes.window, 'dragleave', fileDrag());
  assert.equal(area.classList.contains('input-area--drop'), false, 'leaving the window takes the frame with it');
});

test('a drag carrying no file is left to the browser', async () => {
  // Dragging selected text inside the textarea is the browser's own edit
  // gesture. A window-wide unconditional preventDefault swallows it — the
  // gate is the cargo, not the target.
  const nodes = await loadApp();
  const textDrag = { dataTransfer: { types: ['text/plain'], files: [] } };

  const over = fire(nodes.window, 'dragover', textDrag);
  const drop = fire(nodes.window, 'drop', textDrag);
  await settle();

  assert.equal(over.defaultPrevented, false, 'the browser still moves the text');
  assert.equal(drop.defaultPrevented, false);
  assert.equal(
    nodes['#input-area'].classList.contains('input-area--drop'),
    false,
    'and nothing pretends a file is coming',
  );
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
