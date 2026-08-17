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
