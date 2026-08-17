// Checks the parts a unit test normally misses and only a browser would show:
// that every element the UI reaches for exists, that every asset path resolves,
// and that the CSP permits exactly what the page needs and nothing more.

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(join(ROOT, p), 'utf8');

const html = read('index.html');
const appJs = read('js/app.js');

test('every element app.js queries exists in the markup', () => {
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]);
  const queried = [...appJs.matchAll(/querySelector\('#([^']+)'\)/g)].map((m) => m[1]);
  assert.ok(queried.length >= 5, 'sanity: found the query sites');
  for (const id of queried) {
    assert.ok(ids.includes(id), `#${id} is queried but never rendered`);
  }
});

test('every module import resolves to a file that exists', () => {
  const modules = ['js/app.js', 'js/findings.js', 'js/links.js', 'js/decode.js',
    'js/unfold.js', 'js/blocklist.js', 'js/bloom.js', 'js/senders.js'];
  for (const module of modules) {
    const source = read(module);
    for (const [, spec] of source.matchAll(/from '(\.[^']+)'/g)) {
      const target = resolve(ROOT, dirname(module), spec);
      assert.ok(existsSync(target), `${module} imports missing ${spec}`);
    }
  }
});

test('asset paths are relative, because Pages serves from a subpath', () => {
  // An absolute /css/style.css works on localhost and 404s only after deploy.
  for (const [, attr] of html.matchAll(/(?:href|src)="(\/[^"/][^"]*)"/g)) {
    assert.fail(`absolute asset path would break on a project page: ${attr}`);
  }
  assert.match(html, /href="css\/style\.css"/);
  assert.match(html, /src="js\/app\.js"/);
});

test('referenced local assets exist', () => {
  for (const [, path] of html.matchAll(/(?:href|src)="((?!https?:|data:|mailto:)[^"]+)"/g)) {
    assert.ok(existsSync(join(ROOT, path)), `missing asset: ${path}`);
  }
});

test('the fetch targets match what the build script writes', () => {
  const blocklist = read('js/blocklist.js');
  const builder = read('tools/build-blocklist.mjs');
  for (const [, path] of blocklist.matchAll(/fetch\('([^']+)'\)/g)) {
    assert.ok(
      builder.includes(path.replace(/^data\//, 'data/')),
      `blocklist.js fetches ${path}, which the builder never writes`,
    );
  }
});

test('the CSP allows the page to work and nothing beyond it', () => {
  const csp = html.match(/Content-Security-Policy" content="([^"]+)"/)?.[1];
  assert.ok(csp, 'a CSP is present');

  // Required for the page to function.
  assert.match(csp, /script-src 'self'/, 'ES modules must load');
  assert.match(csp, /connect-src 'self'/, 'the blocklist fetch must be allowed');

  // Required for the privacy claim to hold.
  assert.match(csp, /default-src 'none'/, 'deny by default');
  assert.ok(!/connect-src[^;]*\*/.test(csp), 'no wildcard may appear in connect-src');
  assert.ok(!/'unsafe-inline'/.test(csp), 'inline script would defeat the policy');
  assert.ok(!/https?:\/\//.test(csp), 'no third-party origin may be allowed');
  assert.match(csp, /form-action 'none'/, 'nothing may be submitted anywhere');
});

test('the page makes no storage calls at all', () => {
  for (const module of ['js/app.js', 'js/findings.js', 'js/blocklist.js', 'js/links.js']) {
    assert.ok(!/localStorage|sessionStorage|document\.cookie|indexedDB/.test(code(read(module))),
      `${module} touches persistent storage`);
  }
});

/** Source with comment lines removed, so prose about a pattern is not a hit. */
function code(source) {
  return source
    .split('\n')
    .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
    .join('\n');
}

test('untrusted header text never reaches innerHTML', () => {
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML/.test(code(appJs)),
    'header content must only ever be set via textContent');
});
