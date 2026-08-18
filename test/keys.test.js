// What arrives on a raw-mode read, and what it means.
//
// The interactive loop itself still needs a real TTY, and faking one would test
// the fake — the position test/cli.test.js takes and this file does not change.
// What it does change is that the decision the loop makes is no longer buried
// in a TTY callback: which keys are in this chunk is now a question that can be
// asked directly, and a paste spanning several reads is the reason the reader
// holds state rather than being a pure function.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { createKeyReader, isQuit, untilQuit } from '../js/keys.js';

const ESC = '\u001b';
const PASTE_ON = `${ESC}[200~`;
const PASTE_OFF = `${ESC}[201~`;

test('one key is one key', () => {
  const keys = createKeyReader();
  assert.deepEqual(keys.read(' '), [' ']);
  assert.deepEqual(keys.read('q'), ['q']);
});

test('two keys arriving together are two keys', () => {
  // This is the failure that started this file. A single read carrying `' q'`
  // matched neither `' '` nor `'q'` when the whole chunk was compared against
  // one character, so both were dropped — and q is the only documented way out
  // of the loop, which left the process alive with no way to end it politely.
  const keys = createKeyReader();
  assert.deepEqual(keys.read(' q'), [' ', 'q']);
  assert.deepEqual(keys.read('qq'), ['q', 'q']);
  assert.deepEqual(keys.read('  '), [' ', ' ']);
});

test('a quit key is recognised wherever it sits in the chunk', () => {
  const keys = createKeyReader();
  assert.ok(keys.read(' q').some(isQuit));
  assert.ok(keys.read('xq').some(isQuit));
  assert.ok(keys.read('\u0003').some(isQuit), 'Ctrl-C');
  assert.ok(keys.read('\u0004').some(isQuit), 'Ctrl-D');
  assert.ok(!keys.read('abc ').some(isQuit));
});

test('pasted text is data, not a burst of keypresses', () => {
  // Bracketed paste is the terminal saying "the reader copied this, they did
  // not type it". A 30 KB header pasted here would otherwise read as thousands
  // of keypresses, hundreds of them spaces, each asking to re-read the
  // clipboard — and any q inside it would quit.
  const keys = createKeyReader();
  const pasted = `${PASTE_ON}From: a@b.example q q q${PASTE_OFF}`;

  assert.deepEqual(keys.read(pasted), []);
  assert.deepEqual(keys.read(`${pasted} `), [' '], 'a real key after the paste still counts');
  assert.ok(!keys.read(pasted).some(isQuit), 'a q inside a paste does not quit');
});

test('a paste split across reads stays a paste', () => {
  // The reason this reader holds state. A 30 KB paste does not arrive in one
  // read: the opening marker and the closing one land in different chunks. A
  // stateless version dropped the first piece correctly and then read the rest
  // as typing — the same failure, one read later, and harder to see.
  const keys = createKeyReader();

  assert.deepEqual(keys.read(`${PASTE_ON}From: a@b.example`), [], 'the opening piece is dropped');
  assert.equal(keys.pasting, true, 'and the reader knows it is still inside one');
  assert.deepEqual(keys.read(' q q more pasted text'), [], 'so is the middle');
  assert.deepEqual(keys.read(`tail${PASTE_OFF}`), [], 'and the closing piece');
  assert.equal(keys.pasting, false);
  assert.deepEqual(keys.read(' '), [' '], 'typing resumes afterwards');
});

test('two pastes in one chunk leave only what was typed between them', () => {
  const keys = createKeyReader();
  const chunk = `${PASTE_ON}aaa${PASTE_OFF}q${PASTE_ON}bbb${PASTE_OFF} `;

  assert.deepEqual(keys.read(chunk), ['q', ' ']);
});

test('an astral character counts once, not twice', () => {
  // Iterating UTF-16 units would split it into two halves that match nothing —
  // harmless here, and exactly the kind of harmless that stops being harmless
  // once someone compares against a multi-byte key.
  assert.deepEqual(createKeyReader().read('📦'), ['📦']);
});

test('nothing at all is no keys, not a crash', () => {
  const keys = createKeyReader();
  assert.deepEqual(keys.read(''), []);
  assert.deepEqual(keys.read(null), []);
  assert.deepEqual(keys.read(undefined), []);
});

test('nothing after the quit key is handed on', () => {
  // Resolving the loop's promise does not stop a loop already running. `q `
  // therefore quit and then read the clipboard and emptied it, after the reader
  // had said they were done — one keystroke of theirs, two actions taken.
  assert.deepEqual(untilQuit([' ', 'q', ' ', ' ']), [' ', 'q']);
  assert.deepEqual(untilQuit(['q']), ['q']);
  assert.deepEqual(untilQuit([' ', ' ']), [' ', ' '], 'nothing to cut short');
  assert.deepEqual(untilQuit([]), []);
});
