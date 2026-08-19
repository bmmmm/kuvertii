// The clipboard bridge: what a failed read is allowed to claim.
//
// Everything else in js/clipboard.js is a thin wrapper around the platform
// tools and is exercised by using the CLI; what needs a gate is the sentence
// chosen when a read fails, because that sentence directs the repair. Measured
// on darwin with a 33 MB clipboard: the tool ran fine, the content overflowed
// maxBuffer, and the reader was told "no clipboard tool worked — tried
// pbpaste (ENOBUFS)" — an instruction to install something, for a problem
// that copying less would have solved.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { contentFailure } from '../js/clipboard.js';

test('a clipboard too large to read is not blamed on the tool', () => {
  const failure = contentFailure({ code: 'ENOBUFS' });

  assert.ok(failure, 'an overflow is about the content and must be said so');
  assert.match(failure.error, /more than 32 MB/);
  assert.match(failure.error, /header/i, 'the sentence must name the repair: copy just the header');
  assert.doesNotMatch(failure.error, /no clipboard tool/);
});

test('a missing tool is still a missing tool', () => {
  // The side that must stay quiet: every other failure keeps walking the
  // candidate list, so a Linux box without wl-paste still gets told what to
  // install rather than being told its clipboard is too big.
  assert.equal(contentFailure({ code: 'ENOENT' }), null);
  assert.equal(contentFailure({ code: 'EPERM' }), null);
  assert.equal(contentFailure(new Error('plain failure')), null);
  assert.equal(contentFailure(undefined), null);
});
