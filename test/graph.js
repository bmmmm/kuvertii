// Walking what the code actually loads, rather than listing what we remember.
//
// Both primitives here started life inside test/wiring.test.js, and both are
// there because a hand-kept list had already failed twice: once when the module
// list named four files and the page loaded nine, and once when the network
// check named five and the two entry points loaded fifteen between them. A list
// is a snapshot of somebody's attention on the day they wrote it.
//
// Shared so that every gate asks the same question of the same set of files. A
// second copy of a walk is a second thing to forget to update.

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import assert from 'node:assert/strict';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** One file's source, by repo-relative path. */
export const read = (path) => readFileSync(join(ROOT, path), 'utf8');

/**
 * Source with comment lines removed, so prose about a pattern is not a hit.
 *
 * Every gate below searches for the name of something dangerous, and this
 * project explains at length why it does not do those things — without this,
 * the explanations would fail the tests they explain.
 */
export function code(source) {
  return source
    .split('\n')
    .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
    .join('\n');
}

/**
 * Every module reachable from an entry point.
 *
 * Specifiers must be relative or `node:` — a bare one would mean a dependency,
 * and this project has none, so the walk asserts that rather than skipping past
 * it. Missing files are an error for the same reason: a graph that silently
 * omits what it could not resolve reports a smaller, cleaner repository than
 * the one that exists.
 */
// Every spelling a module can be named in: single or double quotes, any
// spacing, and the parenthesis of a dynamic import. Bounded to one line,
// because a specifier is never longer than one and an unbounded group ran
// across half a file looking for its closing quote.
const SPECIFIER = /\b(?:from|import)\s*\(?\s*['"]([^'"\n]{1,200})['"]/g;

export function importGraph(entry) {
  const seen = new Set();

  const walk = (module) => {
    if (seen.has(module)) return;
    seen.add(module);
    // Every spelling, because a walk that misses one is a list again — and
    // this walk is what several gates now rest on. The old pattern required a
    // single space and single quotes, so `import {x} from "./a.js"` and
    // `await import('./a.js')` were both invisible: a module could be loaded by
    // the page and checked by nothing, which is the exact defect the walk
    // replaced, one level up.
    for (const [, spec] of read(module).matchAll(SPECIFIER)) {
      // A module specifier never contains whitespace. Without that check the
      // widened pattern reaches into prose and regex literals — the first
      // version reported that js/unfold.js imports \`)) return headers;\`,
      // because the specifier group ran across newlines to the next quote.
      if (/\s/.test(spec)) continue;
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

/** Everything either build loads: the union of both entry points. */
export function everythingShipped() {
  return new Set([...importGraph('js/app.js'), ...importGraph('bin/kuvertii.js')]);
}
