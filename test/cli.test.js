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
  // Revised 2026-08-28: prose used to be kept as an unlabelled field and the
  // report called it "part of a header, not all of it" — a factual claim
  // about the paste that was false. It is now read as the message body it
  // is, and the reader is told where their mail program keeps the header.
  const { code, stdout, stderr } = await cli([], 'just some prose with no colon-led fields\n');
  assert.equal(code, 0);
  assert.equal(stderr, '');
  assert.match(stdout, /A message body without its header/);
  assert.match(stdout, /cannot be answered\s+here/, 'the wrap may fall inside the phrase');
  assert.doesNotMatch(stdout, /part of a header, not all of it/);
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

test('input cut at the ceiling is announced, not silently tallied', async () => {
  // The page said "Only the first 1024 KB was read"; the command clipped in
  // silence and closed with "3 header fields read. Nothing left this machine."
  // — with the fields past the cut simply gone from the account. A sender who
  // opens with a megabyte of padding decides what disappears, so the cut has
  // to be part of the tally it truncates.
  const padded = `From: a@b.example\nSubject: probe\nX-Blob: ${'x'.repeat(1024 * 1024)}\nX-After-Cut: gone@example.net\n`;
  const { code, stdout } = await cli([], padded);

  assert.equal(code, 0);
  assert.match(stdout, /Only the first 1024 KB were read/);
  assert.doesNotMatch(stdout, /gone@example\.net/, 'the field past the cut really was not read');

  // The still-must-stay-quiet side: an ordinary header carries no such note.
  const ordinary = await cli([], BULK_HEADER);
  assert.doesNotMatch(ordinary.stdout, /Only the first/);
});

test('a report longer than a pipe buffer arrives whole', async () => {
  // execFile gives the child a pipe, which is the case that used to fail:
  // writes to a pipe are asynchronous, a terminal takes them synchronously,
  // and `process.exit` discarded whatever was still buffered. A 601-hop chain
  // came to 93,000 bytes on a terminal and 66,264 through `| cat` — the report
  // stopped mid-sentence at hop 175, stderr was empty, and the exit code said
  // it had worked. The last line is the assertion that matters: it is written
  // last, so it is the first thing a truncated stream loses.
  const lines = ['From: a@b.example', 'To: c@d.example', 'Subject: long'];
  for (let i = 600; i >= 1; i--) {
    lines.push(
      `Received: from host${i}.sub${i}.example.com (host${i}.sub${i}.example.com [10.0.0.${i % 255}])`
      + ` by mx${i}.relay.example.net with ESMTPS id abc${i}; Mon, 17 Aug 2026 09:14:02 -0700 (PDT)`,
    );
  }

  const { code, stdout } = await cli([], lines.join('\n'));

  assert.equal(code, 0);
  assert.ok(stdout.length > 70_000, `only ${stdout.length} bytes came back`);
  assert.match(stdout.trimEnd().split('\n').pop(), /header fields read\. Nothing left this machine\./);
});
