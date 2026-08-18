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

/**
 * Every module reachable from an entry point.
 *
 * Matches every specifier, not only the relative ones. The previous pattern was
 * `/from '(\.[^']+)'/g`, which could not see a bare specifier at all —
 * `import chalk from 'chalk'` in js/microsoft.js passed this file 9/9. The
 * zero-dependency claim then rested on the accident that CI never runs an
 * install, and would have evaporated the moment one was added.
 */
function importGraph(entry) {
  const seen = new Set();
  const walk = (module) => {
    if (seen.has(module)) return;
    seen.add(module);
    for (const [, spec] of read(module).matchAll(/(?:from|import) '([^']+)'/g)) {
      assert.ok(
        spec.startsWith('.') || spec.startsWith('node:'),
        `${module} imports ${spec}, which is neither a relative path nor Node stdlib`,
      );
      if (!spec.startsWith('.')) continue;
      const target = resolve(ROOT, dirname(module), spec);
      assert.ok(existsSync(target), `${module} imports missing ${spec}`);
      walk(target.slice(ROOT.length + 1));
    }
  };
  walk(entry);
  return seen;
}

test('every module import resolves to a file that exists', () => {
  // Walked rather than listed, so a new module cannot be added without being
  // checked, and a stale entry cannot rot in a hand-kept list.
  const browser = importGraph('js/app.js');
  const cli = importGraph('bin/kuvertii.js');
  assert.ok(browser.size >= 8, `sanity: browser graph looks too small (${browser.size})`);
  assert.ok(cli.size >= 5, `sanity: CLI graph looks too small (${cli.size})`);
});

test('nothing the browser loads reaches for a Node built-in', () => {
  // The CLI shares the analysis modules but adds its own — clipboard access
  // spawns a process, and the terminal renderer is no use to a page. If one of
  // those were ever imported from the browser graph the page would break on
  // load, and the CSP story with it, so the boundary is asserted rather than
  // left to the directory layout.
  for (const module of importGraph('js/app.js')) {
    assert.doesNotMatch(read(module), /from 'node:/, `${module} is browser code`);
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
  // Checked as a policy rather than as a string.
  //
  // This used to be a handful of negative regexes, and they had the hole every
  // denylist has: `connect-src 'self' https:` contains no wildcard and no
  // `//`, so it passed both guards while permitting the page to send a pasted
  // header to any origin on the web. A scheme-source has no slashes, which is
  // exactly what the "no third-party origin" check was looking for.
  //
  // So every source token is now checked against what that directive is allowed
  // to contain. Adding anything — a CDN, a font host, an analytics endpoint —
  // fails here until somebody writes down why it belongs, which is the point.
  const csp = html.match(/Content-Security-Policy" content="([^"]+)"/)?.[1];
  assert.ok(csp, 'a CSP is present');

  // Parsed the way a user agent parses it, which is not the way
  // Object.fromEntries does. CSP3 says a duplicate directive after the first is
  // ignored; Object.fromEntries keeps the LAST. A policy listing
  // `connect-src https:` and then `connect-src 'self'` would therefore have
  // passed this check while the browser enforced the permissive half — the same
  // hole this test was written to close, reopened by how the test reads.
  const declared = csp.split(';').map((part) => part.trim()).filter(Boolean)
    .map((part) => {
      const [name, ...sources] = part.split(/\s+/);
      return [name.toLowerCase(), sources];
    });

  const duplicates = declared.map(([name]) => name)
    .filter((name, i, all) => all.indexOf(name) !== i);
  assert.deepEqual(duplicates, [], 'a directive is declared twice, and only the first one counts');

  const policy = Object.fromEntries(declared);

  // What each directive may contain, exhaustively. `data:` appears once, for
  // the inline SVG marks, and nowhere that could carry a request off-origin.
  const ALLOWED = {
    'default-src': ["'none'"],
    'script-src': ["'self'"],
    'style-src': ["'self'"],
    'connect-src': ["'self'"],
    'img-src': ["'self'", 'data:'],
    'base-uri': ["'none'"],
    'form-action': ["'none'"],
    'frame-ancestors': ["'none'"],
    'require-trusted-types-for': ["'script'"],
    'trusted-types': ["'none'"],
  };

  for (const [directive, sources] of Object.entries(policy)) {
    assert.ok(ALLOWED[directive], `${directive} is not a directive this page has decided about`);
    for (const source of sources) {
      assert.ok(
        ALLOWED[directive].includes(source),
        `${directive} allows ${source}, which is not on its list`,
      );
    }
  }

  // And the directives that must be present, since an allowlist says nothing
  // about what is missing: a policy with no connect-src falls back to
  // default-src, which is fine here, but a policy that dropped default-src
  // would fall back to nothing at all.
  for (const required of ['default-src', 'script-src', 'connect-src', 'form-action', 'require-trusted-types-for']) {
    assert.ok(policy[required], `${required} is missing`);
  }
});

test('the page makes no storage calls at all', () => {
  // Walked, not listed. The hand-kept list named four modules; the browser
  // loads nine, so bloom.js, decode.js, senders.js, microsoft.js, psl.js and
  // unfold.js were never checked.
  const graph = importGraph('js/app.js');
  assert.ok(graph.size >= 9, `sanity: the graph looks too small (${graph.size})`);
  for (const module of graph) {
    assert.ok(!/localStorage|sessionStorage|document\.cookie|indexedDB|caches\b/.test(code(read(module))),
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

test('untrusted header text never reaches a markup sink', () => {
  // Every module the page loads, not only app.js — and every sink, not only the
  // three obvious ones. setAttribute is here because an attribute built from
  // header text is the same class of mistake wearing different clothes.
  const SINKS = /innerHTML|outerHTML|insertAdjacentHTML|document\.write|setAttribute|eval\(|new Function|srcdoc/;
  for (const module of importGraph('js/app.js')) {
    assert.ok(!SINKS.test(code(read(module))),
      `${module}: header content must only ever be set via textContent`);
  }
});

test('the zero-dependency claim is enforced, not merely true today', () => {
  const pkg = JSON.parse(read('package.json'));
  for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    assert.equal(pkg[field], undefined, `package.json declares ${field}`);
  }
  for (const lockfile of ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'npm-shrinkwrap.json']) {
    assert.ok(!existsSync(join(ROOT, lockfile)), `${lockfile} exists, so something is being installed`);
  }

  // The tooling and the tests are held to it too — they are the likeliest place
  // for a convenience dependency to appear.
  for (const entry of ['bin/kuvertii.js', 'tools/build-blocklist.mjs', 'tools/build-psl.mjs', 'tools/serve.mjs']) {
    importGraph(entry);
  }
});

test('the page assigns only the four node properties it has decided about', () => {
  // The sink check above bans the names somebody thought of — innerHTML,
  // setAttribute, srcdoc. It did not ban `link.href = value`, because nobody
  // thought of that one, and an anchor built from header text would have
  // rendered a phishing destination as a live click target with the whole suite
  // green. Enumerating dangerous sinks is the wrong shape: the list of ways to
  // reach the DOM is the platform's and it grows, while the list of properties
  // this page needs is ours and is four items long.
  //
  // So the assertion runs the other way. Anything outside the four fails, and
  // whoever adds the fifth has to say here what it is for.
  const ALLOWED = new Set(['className', 'hidden', 'textContent', 'value']);
  const assigned = new Set();

  for (const [, property] of code(read('js/app.js')).matchAll(/\.\s*([A-Za-z_$][\w$]*)\s*(?:=[^=]|\+=)/g)) {
    assigned.add(property);
  }

  assert.ok(assigned.size > 0, 'the scan found nothing, which means it is not scanning');
  for (const property of assigned) {
    assert.ok(ALLOWED.has(property), `js/app.js assigns .${property}, which is not on the list`);
  }
});
