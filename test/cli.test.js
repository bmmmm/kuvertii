// The command itself: argument handling, the three input routes, exit codes.
//
// The interactive keypress loop is not covered here — it needs a real TTY, and
// faking one would test the fake. What it does once a header is in hand is the
// same code path as the file route below.

import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';

import { BULK_HEADER, MICROSOFT_HEADER } from './fixtures.js';

const run = promisify(execFile);
const CLI = new URL('../bin/kuvertii.js', import.meta.url).pathname;

/**
 * Run the CLI, resolving to {code, stdout, stderr} rather than throwing.
 *
 * stdin is always closed, and there is a timeout on top: with neither, a run
 * that waits for input blocks the whole suite instead of failing one test.
 */
async function cli(args = [], input = '') {
  try {
    const child = run(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 20_000 });
    child.child.stdin.end(input);
    const { stdout, stderr } = await child;
    return { code: 0, stdout, stderr };
  } catch (error) {
    return { code: error.code ?? 1, stdout: error.stdout ?? '', stderr: error.stderr ?? '' };
  }
}

test('--help explains the three ways in', async () => {
  const { code, stdout } = await cli(['--help']);
  assert.equal(code, 0);
  assert.match(stdout, /clipboard/);
  assert.match(stdout, /\.eml/);
  assert.match(stdout, /--keep/);
});

test('--version prints the package version', async () => {
  const { code, stdout } = await cli(['--version']);
  assert.equal(code, 0);
  assert.match(stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test('a header arriving on stdin is analysed', async () => {
  const { code, stdout } = await cli([], BULK_HEADER);
  assert.equal(code, 0);
  assert.match(stdout, /addressed to/i);
  assert.match(stdout, /maja\.beispiel@example\.org/);
});

test('a file is analysed, and its body is left alone', async () => {
  const path = join(tmpdir(), 'kuvertii-test.eml');
  // A .eml is a header block, a blank line, then content. A Subject: quoted
  // in the body must not be read as a field.
  await writeFile(path, `${MICROSOFT_HEADER}\nSubject: quoted in the body\nregards\n`);

  const { code, stdout } = await cli([path]);
  assert.equal(code, 0);
  assert.match(stdout, /did not check out/);
  assert.doesNotMatch(stdout, /quoted in the body/);
});

test('a missing file fails with a message rather than a stack', async () => {
  const { code, stderr } = await cli([join(tmpdir(), 'kuvertii-does-not-exist.eml')]);
  assert.equal(code, 1);
  assert.match(stderr, /Cannot read/);
  assert.doesNotMatch(stderr, /at Object|node:internal/, 'no stack trace');
});

test('input that is not a header is reported, not crashed on', async () => {
  // A stray line is kept as an unlabelled field — that is deliberate, since a
  // copied header often loses the name of its Message-ID line. So the honest
  // outcome here is "read it, found nothing", not a parse failure.
  const { code, stdout, stderr } = await cli([], 'just some prose with no colon-led fields\n');
  assert.equal(code, 0);
  assert.equal(stderr, '');
  // It is read, and the reader is told plainly that this was not a header.
  assert.match(stdout, /part of a header, not all of it/);
  assert.match(stdout, /From is missing/);
});

test('empty stdin says so and exits non-zero', async () => {
  const { code, stderr } = await cli([], '   \n');
  assert.equal(code, 1);
  assert.match(stderr, /Nothing on stdin/);
});

test('piped output carries no colour and no live link', async () => {
  // execFile gives the child a pipe, not a TTY — the case a file or pager sees.
  const { stdout } = await cli([], MICROSOFT_HEADER);
  assert.doesNotMatch(stdout, /\x1b\[/, 'no escape sequences');
  assert.doesNotMatch(stdout, /https?:\/\//, 'no clickable link');
});

// NO_COLOR is not tested here on purpose: with a pipe rather than a TTY,
// colour is already off, so the run would pass without exercising the flag.
// createRenderer's colour switch is covered directly in terminal.test.js.

test('a file argument wins over anything on stdin', async () => {
  const path = join(tmpdir(), 'kuvertii-precedence.txt');
  await writeFile(path, 'From: sender@example.org\nTo: only-in-the-file@example.net\n');

  const { stdout } = await cli([path], BULK_HEADER);
  assert.match(stdout, /only-in-the-file@example\.net/, 'the file was read');
  assert.doesNotMatch(stdout, /maja\.beispiel/, 'and stdin was not read as well');
});
