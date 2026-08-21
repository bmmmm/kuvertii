// Properties every report must have, whatever the message said.
//
// The other test files ask whether a particular header produces a particular
// sentence. This one asks a different question: is the report internally
// consistent — does the headline agree with the rows underneath it. That is a
// property of the data, checkable without reading any of the English, and it is
// the check that was missing when a card announced "Every check passed" above a
// red SPF row.
//
// Driven by test/verdicts.js rather than by fixtures, because a fixture pair
// cannot express the combinations where a summary and its rows come apart.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { ALL_CLEAR_TITLE, analyse } from '../js/findings.js';
import { createRenderer } from '../js/terminal.js';
import { parseHeaders } from '../js/unfold.js';
import { authCombinations, compauthCombinations, DECISIVE } from './verdicts.js';

test('a card carrying a failure is never toned as though it were not', () => {
  // `bad` is the level reserved for "this is wrong and you should act on it".
  // A card containing one and toned `info` reads, at a glance and in colour, as
  // routine — and the glance is what most readers give it.
  const offenders = [];
  const everyMessage = [...authCombinations(), ...compauthCombinations()];

  for (const { verdicts, compauth, header } of everyMessage) {
    for (const finding of analyse(parseHeaders(header))) {
      const bad = finding.items.filter((i) => i.level === 'bad');
      if (bad.length && finding.tone !== 'alert') {
        const which = compauth ? `compauth=${compauth}` : JSON.stringify(verdicts);
        offenders.push(`${which} → ${finding.id} toned ${finding.tone} with ${bad.length} bad row(s)`);
      }
    }
  }

  assert.deepEqual(offenders.slice(0, 5), [], `${offenders.length} card(s) understate a failure`);
});

test('"every check passed" is never printed over a check that did not', () => {
  // The title is compared against the constant the code itself uses, so that
  // rewording it cannot quietly disarm this test — the failure mode a test
  // matching on its own copy of a sentence always has.
  const offenders = [];

  for (const { verdicts, header } of authCombinations()) {
    // Not just `fail`. The first version of this test asked only about the word
    // that had been reported, so the first version of the fix only handled that
    // word — and softfail, neutral, temperror, permerror, DKIM policy and DMARC
    // none all kept the all-clear headline. 168 combinations, invisible to a
    // test written against one example. A pass is a pass; everything else is
    // something a reader is owed.
    const notPassed = DECISIVE.filter((m) => verdicts[m] && verdicts[m] !== 'pass');
    if (!notPassed.length) continue;

    const auth = analyse(parseHeaders(header)).find((f) => f.id === 'auth');
    if (auth?.title === ALL_CLEAR_TITLE) {
      offenders.push(`${JSON.stringify(verdicts)} — ${notPassed.map((m) => `${m}=${verdicts[m]}`).join(', ')}`);
    }
  }

  assert.deepEqual(offenders.slice(0, 5), [], `${offenders.length} failing message(s) titled as clean`);
});

test('a composite-authentication failure also disqualifies "every check passed"', () => {
  // Microsoft's `compauth=fail` means someone outside wrote as though they were
  // a colleague. It rides in the same header, it is rendered as a red row, and
  // it fed nothing that decided the headline — so SPF, DKIM and DMARC all
  // passing was enough to title the card clean over it.
  for (const { compauth, header } of compauthCombinations()) {
    const auth = analyse(parseHeaders(header)).find((f) => f.id === 'auth');
    if (compauth === 'fail') {
      assert.notEqual(auth.title, ALL_CLEAR_TITLE, 'compauth=fail was titled as a clean pass');
      assert.equal(auth.tone, 'alert');
    }
  }
});

test('no combination of verdicts makes the analysis throw', () => {
  // The fault boundary exists so a producer that throws costs one section. It
  // must never be load-bearing for input the tool claims to understand, and
  // this is the widest set of such input there is.
  for (const { verdicts, header } of authCombinations()) {
    const faults = analyse(parseHeaders(header)).filter((f) => String(f.id).startsWith('fault:'));
    assert.deepEqual(faults, [], `a producer threw on ${JSON.stringify(verdicts)}`);
  }
});

// Fields whose values this tool decodes rather than merely prints. Everything
// a decoder can invent has to come out of one of these.
const DECODED_FIELDS = [
  'X-Mailer-Info', 'X-Mailer-Info-Extra', 'List-Unsubscribe', 'Feedback-Id',
  'X-Campaign-Id', 'Return-Path', 'X-SG-EID',
];

/** An opaque blob of the kind every bulk sender stamps — bytes, deterministically. */
const blob = (seed, length) => Buffer.from(
  Uint8Array.from({ length }, (_, i) => (i * seed + 11) % 256),
).toString('base64');

test('a decode the tool could not read is never put on screen', () => {
  // U+FFFD is the one character on a report that can only have come from this
  // tool: TextDecoder emits it where the bytes were not UTF-8, which is the
  // decoder saying it failed. So if the header carries none, no rendered line
  // may carry one either — a property of the output, checkable without reading
  // a word of it, and true of every message rather than of a chosen fixture.
  //
  // What it would have caught: a Klaviyo X-Mailer-Info folded mid-token. Half a
  // base64 token decodes to noise; the noise counted its replacement characters
  // as printable, scored 0.52 as prose, and was printed to the reader as
  // campaign metadata. Then the stray control bytes that come with random data
  // were read as intent, and an ordinary newsletter was headlined as a
  // deliberate attempt to control the reader's terminal.
  const offenders = [];

  for (const field of DECODED_FIELDS) {
    for (const seed of [7, 13, 37, 91, 137]) {
      for (const length of [24, 48, 96, 192]) {
        const token = blob(seed, length);
        // Folded and whole: the fold is what cuts a token in half, and half a
        // token is what decodes to bytes.
        for (const value of [token, `${token.slice(0, 40)}\n ${token.slice(40)}`]) {
          const header = `From: Sender <s@sender.example>\nTo: you@example.org\n${field}: ${value}\n`;
          const rendered = createRenderer({ colour: false, width: 80 }).render(analyse(parseHeaders(header)));
          if (rendered.includes('\uFFFD')) {
            offenders.push(`${field} seed=${seed} len=${length}${value.includes('\n') ? ' folded' : ''}`);
          }
        }
      }
    }
  }

  assert.deepEqual(offenders.slice(0, 5), [], `${offenders.length} render(s) printed a failed decode`);
});
