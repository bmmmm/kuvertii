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
    children: [],
    classList: { add(...c) { node.className += ` ${c.join(' ')}`; } },
    append(...kids) { node.children.push(...kids); },
    replaceChildren(...kids) { node.children = kids; },
    addEventListener(type, handler) { (node.handlers[type] ??= []).push(handler); },
    focus() {},
    handlers: {},
  };
  return node;
}

/** Flatten the rendered tree into text, the way a reader would see it. */
function renderedText(node) {
  return [node.textContent, ...node.children.map(renderedText)].filter(Boolean).join('\n');
}

/** Every node in the tree whose class list contains `name`. */
function byClass(node, name) {
  const here = node.className?.split(/\s+/).includes(name) ? [node] : [];
  return [...here, ...node.children.flatMap((child) => byClass(child, name))];
}

async function loadApp() {
  const nodes = {
    '#header-input': stubNode('textarea'),
    '#results': stubNode(),
    '#empty-state': stubNode(),
    '#status': stubNode(),
    '#analyse': stubNode('button'),
    '#clear': stubNode('button'),
  };
  nodes['#header-input'].value = '';

  globalThis.document = {
    querySelector: (selector) => nodes[selector] ?? null,
    createElement: (tag) => stubNode(tag),
  };
  globalThis.window = { addEventListener() {} };
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
