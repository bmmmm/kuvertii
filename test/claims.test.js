// What the three surfaces claim this tool does — and the one thing they must
// not claim.
//
// Every other gate here checks that the code keeps a promise. This one checks
// that the prose does not make a promise the code was never in a position to
// keep, which is a different failure and the easier one to commit: nothing goes
// red when a README sentence quietly grows.
//
// The claim being guarded against is a claim of protection. kuvertii reads a
// message that has already been delivered, fetched, laid out and stored by a
// mail client — it arrives fourth, out of a text box, with every remote
// consequence of opening already spent. Naming a tracking pixel does not call
// its request back. The findings are worth something because the *next*
// decision is still open, not because the message was ever intercepted.
//
// The distinction survives in the text today. It survives by being written
// down, and tools/promises.mjs already names the reason prose is the thing that
// rots: it is the part nothing executes. So this executes it.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { read } from './graph.js';

// The sentence that carries the distinction, kept identical across all three
// surfaces so that one search finds every place it has to hold. Deleting it
// from any of them is the drift this file exists to catch.
const ORDER = /no message becomes safe by being read twice/i;

/**
 * Ways of claiming protection, written as the phrases people actually reach
 * for rather than as a wordlist.
 *
 * `safe` alone would be useless here: the README says `safe-senders entry`
 * about a Microsoft verdict and `a mailto: is harmless` about a link, and both
 * are statements about the message, not about this tool. Each pattern below
 * needs a subject — you, the reader, the message — before it fires.
 */
const PROTECTION = [
  [/\bprotects?\s+you\b/i, 'protects you'],
  [/\bkeeps?\s+you\s+safe\b/i, 'keeps you safe'],
  [/\bshields?\s+you\b/i, 'shields you'],
  [/\bmakes?\s+(?:it|them|the\s+message|a\s+message|any\s+message|the\s+mail|your\s+mail)\s+safe\b/i, 'makes it safe'],
  [/\bsafe\s+to\s+(?:open|click|read|trust|visit)\b/i, 'safe to open'],
  [/\bcannot\s+harm\s+you\b/i, 'cannot harm you'],
  [/\brenders?\s+(?:it|them|the\s+message)\s+harmless\b/i, 'renders it harmless'],
  [/\byou\s+are\s+(?:now\s+)?(?:safe|protected)\b/i, 'you are protected'],
];

/** The usage text alone, so that a comment about the mail is not a hit. */
function usage() {
  const source = read('bin/kuvertii.js');
  const [, block] = source.match(/const USAGE = `([\s\S]*?)`;/) ?? [];
  assert.ok(block, 'sanity: found the USAGE block');
  return block;
}

const SURFACES = [
  ['README.md', () => read('README.md')],
  ['index.html', () => read('index.html')],
  ['bin/kuvertii.js usage', usage],
];

for (const [name, load] of SURFACES) {
  test(`${name} does not claim to protect the reader`, () => {
    const text = load();
    assert.ok(text.length > 200, `sanity: ${name} has text to check`);

    for (const [pattern, phrase] of PROTECTION) {
      const hit = text.match(pattern);
      assert.equal(
        hit,
        null,
        `${name} says "${hit?.[0]}" — a claim of protection ("${phrase}"). `
        + 'This tool reads a message the client already opened; it does not stand between the two.',
      );
    }
  });

  test(`${name} says the reading happens after the fact`, () => {
    assert.match(
      load(),
      ORDER,
      `${name} no longer carries the sentence placing this tool after the mail client. `
      + 'Without it the surrounding promises — nothing fetched, nothing rendered, nothing sent — '
      + 'read as though the message had been held at arm\'s length, which it never was.',
    );
  });
}
