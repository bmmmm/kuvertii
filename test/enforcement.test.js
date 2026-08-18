// Where each guard runs, and whether it can run there.
//
// A guard can be correct, documented, covered by a unit test, and still never
// execute in the place it was written for. The drift check in
// tools/build-blocklist.mjs was all four: it compared each build against the
// previous one by reading data/blocklist.json — which works on a developer's
// machine and never once ran in CI, because `data/` is gitignored and every
// scheduled run starts from a fresh checkout. `previous` was null, the
// comparison was skipped, and the only floor between a collapsed feed and the
// published site was `entries < 1000`.
//
// So this file asks a question the rest of the suite does not: not "is the rule
// right" but "can the rule fire where it is supposed to". It answers by running
// the guard the way CI runs it — a fresh checkout, no data/, a feed from disk —
// and checking that it refuses.

import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';

import { ROOT } from './graph.js';

const run = promisify(execFile);
const BUILDER = join(ROOT, 'tools/build-blocklist.mjs');

/** Run the builder against a feed on disk, resolving rather than throwing. */
async function build(feed) {
  try {
    const { stdout, stderr } = await run(process.execPath, [BUILDER, feed], {
      cwd: ROOT, encoding: 'utf8', timeout: 60_000,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    return { code: error.code ?? 1, stdout: error.stdout ?? '', stderr: error.stderr ?? '' };
  }
}

async function feedOf(count, prefix = 'phish') {
  const dir = await mkdtemp(join(tmpdir(), 'kuvertii-feed-'));
  const path = join(dir, 'feed.txt');
  await writeFile(path, Array.from({ length: count }, (_, i) => `${prefix}${i}.example`).join('\n'));
  return path;
}

test('the drift guard has a reference that survives a fresh checkout', async () => {
  // Committed rather than cached or carried over from the last build, because
  // both of those can be absent without anybody noticing — which is exactly
  // how this guard spent its life not running.
  const baseline = JSON.parse(await readFile(join(ROOT, 'tools/feed-baseline.json'), 'utf8'));

  assert.ok(Number.isFinite(baseline.entries) && baseline.entries > 0, 'the baseline names a count');
  assert.match(await readFile(BUILDER, 'utf8'), /tools\/feed-baseline\.json/, 'and the builder reads that file');
});

test('a feed that collapsed is refused, in the environment CI builds in', async () => {
  // The scenario: the upstream feed is truncated or partially served, 391,406
  // entries become 1,500. That clears the `entries < 1000` floor comfortably,
  // and before this the ratio check was skipped, so the site would have
  // published a filter holding 0.4% of the snapshot — reporting almost every
  // phishing domain as absent, in the same words it uses for a real miss.
  const { code, stderr } = await build(await feedOf(1500));

  assert.notEqual(code, 0, 'the build fails rather than publishing');
  assert.match(stderr, /refusing to publish a list that changed this much/);
});

test('a feed that exploded is refused as well', async () => {
  // A flood is as much a fault as a collapse: every visitor downloads this
  // asset whole, and a sevenfold one is a 4 MB download nobody chose.
  const { code, stderr } = await build(await feedOf(900_000, 'flood'));

  assert.notEqual(code, 0);
  assert.match(stderr, /refusing to publish a list that changed this much/);
});

test('a guard that cannot run is not mistaken for one that passed', async () => {
  // The failure mode this whole file exists for. With no reference to compare
  // against, the old code skipped the comparison and carried on; it now refuses
  // to build at all, because "we could not check" and "we checked and it was
  // fine" must never produce the same outcome.
  const builder = await readFile(BUILDER, 'utf8');

  assert.match(
    builder,
    /A guard that cannot run must not be mistaken for one that passed/,
    'the builder refuses rather than skipping',
  );
  assert.doesNotMatch(
    builder,
    /const previous = await readFile\(join\(ROOT, 'data\//,
    'and it no longer reads its reference from the gitignored build output',
  );
});
