// Nothing this project ships can reach the network.
//
// This is the claim the README makes first and the one a reader has least
// ability to verify for themselves. In the browser the CSP enforces it, so the
// test is a second line. In the terminal there is no CSP, no sandbox by
// default, and nothing else at all — here the test *is* the enforcement.
//
// It used to be a list of five filenames. The two entry points load fifteen
// modules between them, so ten were checked by nothing: a `fetch()` added to
// js/senders.js — the module whose whole job is identifying senders, and the
// one place a WHOIS or reverse-DNS lookup would feel most natural — shipped
// with a green suite. The list was written when the project had five files and
// was never wrong on the day it was written, which is how lists fail.
//
// So it walks. Whatever is added tomorrow is covered the day it is imported.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { code, everythingShipped, importGraph, read } from './graph.js';

// Every way a browser or Node process can start a request, plus the two ways to
// hand the reader's click to somebody else. Named individually rather than as
// one alternation so a failure says which one was found.
const REACHES_OUT = [
  [/\bfetch\s*\(/, 'fetch()'],
  [/\bXMLHttpRequest\b/, 'XMLHttpRequest'],
  [/\bnew\s+WebSocket\b/, 'WebSocket'],
  [/\bnavigator\s*\.\s*sendBeacon\b/, 'sendBeacon'],
  [/\bnew\s+Image\b/, 'new Image()'],
  [/\bnew\s+EventSource\b/, 'EventSource'],
  [/\bimportScripts\b/, 'importScripts'],
  [/\bnode:(https?|net|dns|dgram|tls)\b/, 'a Node network module'],
  [/\brequire\(['"](https?|net|dns|dgram|tls)['"]\)/, 'a Node network require'],
  [/\bwindow\s*\.\s*open\b/, 'window.open'],
  [/\bnavigator\s*\.\s*clipboard\b/, 'the async clipboard API'],
];

test('nothing the command loads can reach the network', () => {
  // The CLI graph has no CSP underneath it. A leak here would be a leak,
  // full stop — and the tool prints "Nothing left this machine" regardless.
  for (const module of importGraph('bin/kuvertii.js')) {
    const source = code(read(module));
    for (const [pattern, name] of REACHES_OUT) {
      assert.doesNotMatch(source, pattern, `${module} reaches for ${name}`);
    }
  }
});

test('the page reaches only for its own two static assets', () => {
  // js/blocklist.js fetches the filter, which is the one request the page is
  // allowed to make and the reason the hostname never leaves the browser: the
  // filter comes here rather than the domain going there. Both targets are
  // relative string literals, and test/wiring.test.js separately checks they
  // are the files the builder writes.
  const ALLOWED = new Set(['js/blocklist.js']);

  for (const module of importGraph('js/app.js')) {
    const source = code(read(module));

    for (const [pattern, name] of REACHES_OUT) {
      if (ALLOWED.has(module) && name === 'fetch()') continue;
      assert.doesNotMatch(source, pattern, `${module} reaches for ${name}`);
    }
  }

  const targets = [...read('js/blocklist.js').matchAll(/fetch\('([^']+)'\)/g)].map(([, url]) => url);
  assert.ok(targets.length > 0, 'the blocklist fetch is still there to be checked');
  for (const target of targets) {
    assert.doesNotMatch(target, /^[a-z]+:|^\/\//i, `${target} is not same-origin`);
    assert.match(target, /^data\//, `${target} is not one of the built assets`);
  }
});

test('the walk covers every module both builds load', () => {
  // A guard that walks the wrong graph is a list with extra steps. This is the
  // assertion that would have caught the original defect: the hand-kept list
  // named five files and the two entry points load fifteen between them.
  const shipped = everythingShipped();

  assert.ok(shipped.size >= 15, `only ${shipped.size} modules walked`);
  for (const module of ['js/senders.js', 'js/decode.js', 'js/control.js', 'js/snapshot.js', 'js/keys.js']) {
    assert.ok(shipped.has(module), `${module} is loaded but not walked`);
  }
});

test('no module opens a subprocess except the one that must', () => {
  // Reading the clipboard means running pbpaste or wl-paste, and the README
  // names that as the one place the sandboxed mode has to give something up.
  // Everywhere else it would be a way out of every guarantee above.
  for (const module of everythingShipped()) {
    if (module === 'js/clipboard.js') continue;
    assert.doesNotMatch(code(read(module)), /child_process|execFile|execSync|\bspawn\s*\(/, `${module} spawns something`);
  }
});
