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
  // Listed exhaustively rather than as a stem: `https?` cannot match
  // `node:http2`, because after `http` the \b would have to sit between `p` and
  // `2`, and both are word characters. That one is the whole point — http2 is a
  // network client. worker_threads and inspector are here because either can
  // reach out on behalf of a module that cannot.
  [/\bnode:(http|https|http2|net|dns|dgram|tls|worker_threads|inspector|cluster)\b/, 'a Node network module'],
  [/\brequire\(['"](http|https|http2|net|dns|dgram|tls|worker_threads|inspector|cluster)['"]\)/, 'a Node network require'],
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

  // The exemption is for two specific calls, not for a file. Counting every
  // `fetch(` and then checking only the ones written as single-quoted literals
  // would let a template literal or a computed URL through without the test
  // seeing it at all — the exemption would have widened itself.
  const blocklist = code(read('js/blocklist.js'));
  const calls = [...blocklist.matchAll(/fetch\s*\(/g)].length;
  const literals = [...blocklist.matchAll(/fetch\('([^']+)'\)/g)].map(([, url]) => url);

  assert.equal(literals.length, calls, 'every fetch here is a plain single-quoted literal, so this test can read them all');
  assert.equal(calls, 2, 'exactly the metadata and the filter');
  for (const target of literals) {
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
