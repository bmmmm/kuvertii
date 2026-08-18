// What the development server will and will not hand out.
//
// The real `resolve` from tools/serve.mjs, not a copy of it — a test that
// reimplements the rule it is checking cannot fail when the rule changes.
//
// The predecessor, `python3 -m http.server`, would have failed every one of the
// blocked cases below: it binds to all interfaces by default, lists
// directories, and has no notion of a file it should not serve.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { BIND, CSP, createDevServer, resolve } from '../tools/serve.mjs';

const served = (path) => resolve(path) !== null;

test('the page and its assets are served', () => {
  for (const path of ['/', '/index.html', '/css/style.css', '/js/app.js', '/data/blocklist.bin', '/robots.txt', '/sitemap.xml']) {
    assert.ok(served(path), `${path} should be served`);
  }
});

test('nothing beginning with a dot is reachable', () => {
  // The three that matter: the git directory carries the remote URL and the
  // maintainer's address, and the other two are project configuration.
  for (const path of ['/.git/config', '/.git/HEAD', '/.claude/settings.local.json', '/.github/workflows/pages.yml', '/.gitignore']) {
    assert.ok(!served(path), `${path} must not be served`);
  }
});

test('local test headers are unreachable', () => {
  // README.md tells developers to keep real headers here, and a real header
  // contains a real address. This is the file the old dev command exposed that
  // most directly contradicted the point of the project.
  assert.ok(!served('/samples/real.eml'));
  assert.ok(!served('/samples/'));
});

test('nothing outside the site is reachable, however it is spelled', () => {
  for (const path of [
    '/package.json',
    '/bin/kuvertii.js',
    '/test/app.test.js',
    '/tools/build-psl.mjs',
    '/../etc/passwd',
    '/js/../../etc/passwd',
    '/%2e%2e/etc/passwd',
    '/js/%2e%2e/%2e%2e/etc/passwd',
    '/js/%2E%2E/../package.json',
    '//etc/passwd',
  ]) {
    assert.ok(!served(path), `${path} must not be served`);
  }
});

test('a malformed request path is refused rather than thrown on', () => {
  // decodeURIComponent throws on a lone percent; a dev server that crashes on
  // one is its own kind of problem.
  assert.equal(resolve('/%'), null);
  assert.equal(resolve('/%zz'), null);
});

test('a query string does not smuggle a path past the allowlist', () => {
  assert.ok(served('/js/app.js?v=2'));
  assert.ok(!served('/.git/config?x=/js/app.js'));
});

test('the served policy is the page policy, plus what a header can carry', () => {
  // frame-ancestors is ignored in a meta element and honoured in a header, so
  // local dev is the one place it does anything. If it is dropped from here it
  // is not enforced anywhere.
  assert.match(CSP, /default-src 'none'/);
  assert.match(CSP, /frame-ancestors 'none'/);
  assert.match(CSP, /require-trusted-types-for 'script'/);
});

test('the dev server binds loopback only, and is asked rather than read', async () => {
  // The one line of tools/serve.mjs nothing asserted, and the one that decides
  // who can reach it. This server hands out a page whose entire claim is that
  // nothing leaves the machine; on 0.0.0.0 it would offer a header paste and a
  // phishing blocklist to whatever network the laptop is on.
  //
  // Bound for real on an ephemeral port rather than compared against the source
  // text, because a test that reads the constant passes just as happily when
  // the constant has stopped being the thing `listen` is handed.
  const server = createDevServer();

  await new Promise((done, fail) => {
    server.once('error', fail);
    server.listen(0, BIND, done);
  });

  try {
    const address = server.address();
    assert.equal(address.address, '127.0.0.1', `bound to ${address.address}`);
    assert.notEqual(address.address, '0.0.0.0');
  } finally {
    await new Promise((done) => server.close(done));
  }
});
