// What arrives on a raw-mode read, and what it means.
//
// The interactive loop itself still needs a real TTY, and faking one would test
// the fake — the position test/cli.test.js takes and this file does not change.
// What it does change is that the decision the loop makes is no longer buried
// in a TTY callback: the question "which keys are in this chunk" is now a pure
// function, and a pure function can be asked.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { isQuit, keypresses } from '../js/keys.js';

const ESC = '\u001b';
const PASTE_ON = `${ESC}[200~`;
const PASTE_OFF = `${ESC}[201~`;

test('one key is one key', () => {
  assert.deepEqual(keypresses(' '), [' ']);
  assert.deepEqual(keypresses('q'), ['q']);
});

test('two keys arriving together are two keys', () => {
  // This is the failure that started this file. A single read carrying `' q'`
  // matched neither `' '` nor `'q'` when the whole chunk was compared against
  // one character, so both were dropped — and q is the only documented way out
  // of the loop, which left the process alive with no way to end it politely.
  assert.deepEqual(keypresses(' q'), [' ', 'q']);
  assert.deepEqual(keypresses('qq'), ['q', 'q']);
  assert.deepEqual(keypresses('  '), [' ', ' ']);
});

test('a quit key is recognised wherever it sits in the chunk', () => {
  assert.ok(keypresses(' q').some(isQuit));
  assert.ok(keypresses('xq').some(isQuit));
  assert.ok(keypresses('\u0003').some(isQuit), 'Ctrl-C');
  assert.ok(keypresses('\u0004').some(isQuit), 'Ctrl-D');
  assert.ok(!keypresses('abc ').some(isQuit));
});

test('pasted text is data, not a burst of keypresses', () => {
  // Bracketed paste is the terminal saying "the reader copied this, they did
  // not type it". A 30 KB header pasted here would otherwise read as thousands
  // of keypresses, hundreds of them spaces, each asking to re-read the
  // clipboard — and any q inside it would quit.
  const pasted = `${PASTE_ON}From: a@b.example q q q${PASTE_OFF}`;
  assert.deepEqual(keypresses(pasted), []);
  assert.deepEqual(keypresses(`${pasted} `), [' '], 'a real key after the paste still counts');
  assert.ok(!keypresses(pasted).some(isQuit), 'a q inside a paste does not quit');
});

test('a paste with no end marker does not leak its contents as keys', () => {
  // The chunk boundary can land inside a paste. Treating the unterminated
  // remainder as data is the safe reading: the alternative hands the loop a
  // few thousand keypresses the reader never made.
  assert.deepEqual(keypresses(`${PASTE_ON}q q q`), []);
});

test('an astral character counts once, not twice', () => {
  // Iterating UTF-16 units would split it into two halves that match nothing —
  // harmless here, and exactly the kind of harmless that stops being harmless
  // once someone compares against a multi-byte key.
  assert.deepEqual(keypresses('📦'), ['📦']);
});

test('nothing at all is no keys, not a crash', () => {
  assert.deepEqual(keypresses(''), []);
  assert.deepEqual(keypresses(null), []);
  assert.deepEqual(keypresses(undefined), []);
});
