// The DOM the page is tested against, and the page loaded onto it.
//
// This was defined inside test/app.test.js, where only that file could reach
// it. tools/fuzz-corpus.mjs needs the same thing: the browser front end is not
// the terminal renderer, and an invariant checked only against the terminal is
// checked against one of the two screens a reader can be looking at.
//
// Small on purpose. It models what js/app.js actually touches — no layout, no
// selectors beyond an id lookup, no bubbling — so a test written against it
// says "the page ran and put this on screen", never "the browser agrees".

export function stubNode(tag = 'div') {
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
export function fire(node, type, event = {}) {
  const fake = { defaultPrevented: false, preventDefault() { fake.defaultPrevented = true; }, ...event };
  for (const handler of node.handlers[type] ?? []) handler(fake);
  return fake;
}

/**
 * A File as this page uses it: a size to check and bytes to await — UTF-8 from
 * `text` unless `bytes` are given. No text() on purpose: the browser's own
 * UTF-8 decode is exactly what the page must not use on a message file.
 */
export function stubFile(text, size, bytes = new TextEncoder().encode(text)) {
  return {
    size: size ?? bytes.byteLength,
    async arrayBuffer() { return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength); },
  };
}

/** Flatten the rendered tree into text, the way a reader would see it. */
export function renderedText(node) {
  return [node.textContent, ...node.children.map(renderedText)].filter(Boolean).join('\n');
}

/** Every node in the tree whose class list contains `name`. */
export function byClass(node, name) {
  const here = node.className?.split(/\s+/).includes(name) ? [node] : [];
  return [...here, ...node.children.flatMap((child) => byClass(child, name))];
}

export async function loadApp({ wide = true } = {}) {
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
  // A real node, not `{ addEventListener() {} }`: the page registers handlers on
  // `window` too — the drop guards and `pageshow` — and a stub that throws them
  // away cannot be fired, so those paths had no test at all rather than a
  // failing one. `wide` is the whole difference between a desktop report and a
  // phone one: every non-alert card reads it once, at render time.
  nodes.window = stubNode('window');
  nodes.window.matchMedia = (media) => ({ media, matches: wide });
  globalThis.window = nodes.window;
  // The blocklist is fetched lazily; the stub keeps the smoke test offline.
  globalThis.fetch = async () => { throw new Error('offline in tests'); };

  // Fresh module instance per test — app.js wires listeners on import.
  await import(`../js/app.js?t=${nodes ? Math.round(performance.now() * 1000) : 0}`);
  return nodes;
}
