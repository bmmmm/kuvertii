// Every authentication verdict a receiver can hand us, as headers.
//
// The two fixtures in test/fixtures.js are a message that passes everything and
// a message that fails everything. Between those poles sits the space where the
// interesting mistakes live: two passes and two failures, a pass on a mechanism
// that carries no weight, a failure on one that does. A card was titled "Every
// check passed" over a red SPF row for months, and neither fixture could
// produce the combination that shows it.
//
// So the combinations are enumerated rather than chosen. The vocabulary is the
// one js/findings.js already tabulates — SPF from RFC 7208 §2.6, DKIM from RFC
// 6376 §3.9, DMARC plus Microsoft's non-standard `bestguesspass`, and the two
// mechanisms that carry no weight. Enumerating is what makes this a gate: a
// hand-picked case list can only contain the cases someone thought of, which is
// the same failure as the fixture pair, one level up.

/** Result words per mechanism, exactly as js/findings.js explains them. */
export const RESULTS = {
  spf: ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror'],
  dkim: ['pass', 'fail', 'none', 'neutral', 'policy', 'temperror', 'permerror'],
  dmarc: ['pass', 'fail', 'none', 'bestguesspass', 'temperror', 'permerror'],
  arc: ['pass', 'fail', 'none'],
  bimi: ['pass', 'fail', 'skipped', 'none'],
};

/** The three that decide anything. ARC and BIMI are commentary. */
export const DECISIVE = ['spf', 'dkim', 'dmarc'];

/** Microsoft's composite verdict, which rides in the same header. */
export const COMPAUTH = ['pass', 'fail', 'softpass', 'none'];

/**
 * Every combination of the five mechanisms, as {verdicts, header}.
 *
 * 7 × 7 × 6 × 3 × 4 = 3,528 messages. `analyse` costs about 0.08 ms, so the
 * whole space runs in well under a second — cheap enough that there is no
 * argument for sampling it.
 */
export function* authCombinations() {
  for (const spf of RESULTS.spf) {
    for (const dkim of RESULTS.dkim) {
      for (const dmarc of RESULTS.dmarc) {
        for (const arc of RESULTS.arc) {
          for (const bimi of RESULTS.bimi) {
            const verdicts = { spf, dkim, dmarc, arc, bimi };
            yield { verdicts, header: headerFor(verdicts) };
          }
        }
      }
    }
  }
}

/** The same, plus Microsoft's composite verdict on a passing message. */
export function* compauthCombinations() {
  for (const compauth of COMPAUTH) {
    const verdicts = { spf: 'pass', dkim: 'pass', dmarc: 'pass' };
    yield { verdicts, compauth, header: headerFor(verdicts, compauth) };
  }
}

function headerFor(verdicts, compauth) {
  const results = Object.entries(verdicts).map(([m, v]) => `${m}=${v}`);
  if (compauth) results.push(`compauth=${compauth} reason=001`);
  return [
    'From: Bank <service@bank.example>',
    'To: reader@example.org',
    'Subject: statement',
    'Date: Mon, 17 Aug 2026 18:13:58 +0200',
    'Message-ID: <x@bank.example>',
    `Authentication-Results: mx.example.org; ${results.join('; ')}`,
  ].join('\n');
}
