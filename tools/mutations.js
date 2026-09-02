// The mutations each promise must not survive.
//
// A test suite that passes proves the code does what the tests describe. It
// does not prove the tests describe anything that matters — a gate written
// against a hand-kept list, or against the text of a source file rather than
// its behaviour, goes green whether or not the property it names still holds.
// The only way to find out is to break the property on purpose and watch.
//
// test/hostile.test.js:11-15 already states this in prose: stub `neutralise` to
// the identity function and six named tests turn red. That sentence is the most
// valuable line in the suite and it is checked by nobody. This file turns it
// into something a machine runs.
//
// Each entry names a promise, a way to break it, and the tests that must notice.
// `tools/mutate.mjs` applies one at a time to a throwaway copy of the tree and
// fails when the suite stays green.
//
// This lives beside the harness rather than in test/, where it would look like
// it belongs. `node --test` counts every file under test/ as a test file, so a
// registry kept there adds a passing test that asserts nothing — and the README
// quotes the test count.
//
// Two rules keep this honest:
//
//   1. `find` must occur EXACTLY once in the file. A mutation whose anchor has
//      drifted would otherwise be applied to nothing, the suite would stay
//      green for the most boring possible reason, and the harness would report
//      an unguarded promise that is in fact guarded — or worse, the reverse.
//      The harness treats a missing or ambiguous anchor as a hard error.
//   2. `mustKill` names the tests that SHOULD catch it. When a mutation dies to
//      some entirely unrelated test, that is worth seeing: it usually means the
//      mutation broke syntax rather than behaviour.
//
// An entry with `expectedToSurvive: true` documents a gap we have measured and
// not yet closed. It keeps the harness green while naming the hole out loud,
// so the list of unguarded promises is a fact in the repository rather than a
// note in somebody's head. Removing that flag is what "we fixed it" means here.
//
// `expectedToSurvive` may also be a list of platforms, for the case where a
// promise cannot be broken on a given system and so cannot be tested there
// either. That is not a gap in the gate — it is a gate whose subject does not
// exist on that platform, and the two must not be reported as the same thing.
// See `exit-discards-buffer` for the one instance, which CI found on its first
// run: the mutation is lethal on darwin and inert on linux, and marking it
// simply "expected to survive" would have quietly stopped guarding the
// platform where the bug is real.

export const MUTATIONS = [
  // ---------------------------------------------------------- the control case
  //
  // This one is already lethal. It is in the registry precisely because it is:
  // a harness that reports every mutation as caught is indistinguishable from a
  // harness that is broken, and this entry is how we tell the difference.
  {
    id: 'neutralise-identity',
    promise: 'No control byte from a header ever reaches the screen.',
    file: 'js/control.js',
    find: `export function neutralise(text) {
  return String(text ?? '')`,
    replace: `export function neutralise(text) {
  return String(text ?? '');
}

function neutraliseDisabledByMutation(text) {
  return String(text ?? '')`,
    mustKill: [
      'no control byte from a header ever reaches the screen',
      'bidi and zero-width controls never reach a value',
    ],
  },

  // ------------------------------------------------------ promises now guarded
  {
    id: 'fault-boundary-removed',
    promise: 'A section that throws costs that section and nothing else.',
    file: 'js/findings.js',
    find: `  try {
    return produce();
  } catch (error) {`,
    replace: `  return produce();
  // eslint-disable-next-line no-unreachable
  try {
    return produce();
  } catch (error) {`,
    mustKill: ['a section that throws costs that section and nothing else'],
  },

  {
    id: 'unguarded-signature-time',
    promise: 'A sender-written timestamp cannot suppress the report.',
    file: 'js/findings.js',
    find: `  const at = new Date(Number(seconds) * 1000);
  return Number.isNaN(at.getTime()) ? null : at;`,
    replace: `  return new Date(Number(seconds) * 1000);`,
    mustKill: [
      'a timestamp too large to be a time is named, not thrown on',
      'an expiry too large to be a time does not silently answer',
    ],
  },

  {
    id: 'allpass-counts-any-pass',
    promise: 'A headline of "every check passed" survives no decisive failure.',
    file: 'js/findings.js',
    find: `  const allPass = decisiveVerdicts.length >= 2
    && decisiveVerdicts.every((verdict) => verdict === 'pass')
    && compauth !== 'fail'
    && !items.some((item) => item.level === 'bad');`,
    replace: `  const allPass = !failed.length && compauth !== 'fail' && decisiveVerdicts.length >= 2;`,
    mustKill: [
      '"every check passed" is never printed over a check that did not',
      'a composite-authentication failure also disqualifies',
    ],
    // The replacement is not the original — it is the FIRST fix, which handled
    // only the word that had been reported. `fail` disqualified the headline
    // and softfail, neutral, temperror, permerror, DKIM policy and DMARC none
    // did not, so 168 combinations kept "Every check passed" over a row saying
    // the opposite. A fix written against one example, caught by an invariant
    // widened to the whole vocabulary.
  },

  {
    id: 'allclear-ignores-bad-rows',
    promise: 'The all-clear headline is denied by any bad row the card carries.',
    file: 'js/findings.js',
    find: `    && compauth !== 'fail'
    && !items.some((item) => item.level === 'bad');`,
    replace: `    && compauth !== 'fail';`,
    mustKill: ['a bad reason row denies the all-clear headline, even when every verdict passed'],
    // Microsoft's `compauth=pass reason=000` writes a good compauth row and a bad
    // reason row saying the message failed outright. With the clause gone, the
    // word-level test prints "every check passed" over that red row — the tone
    // reads the rows, and the headline has to read the same ones. A generative
    // probe over full messages found it; the two fixtures never could.
  },

  {
    id: 'tone-computed-beside-items',
    promise: 'A card carrying a failure is toned as one.',
    file: 'js/findings.js',
    find: `    tone: items.some((item) => item.level === 'bad') ? 'alert' : 'info',`,
    replace: `    tone: failed.length ? 'alert' : 'info',`,
    mustKill: ['a card carrying a failure is never toned as though it were not'],
    // `failed` only ever held SPF, DKIM and DMARC, so a red compauth row sat in
    // a blue card — routine at a glance, which is the glance most rows get.
  },

  {
    id: 'rate-ignores-the-label-walk',
    promise: 'The printed false-alarm rate is the rate of the lookup that was made.',
    file: 'js/snapshot.js',
    find: `  const chance = 1 - ((1 - perProbe) ** Math.max(probes, 1));`,
    replace: `  const chance = perProbe;`,
    mustKill: ['the printed false-alarm rate matches what a measurement finds'],
    // The original figure was the rate of one Bloom probe, printed beside a
    // lookup that makes one per label boundary — 1 in 200 claimed where the
    // four-label ESP hostnames it is usually shown for are 1 in 65.
  },

  {
    id: 'lookup-accepts-unchecked-bytes',
    promise: 'A filter that was never validated cannot answer.',
    file: 'js/snapshot.js',
    find: `  if (!snapshot?.[CHECKED]) {
    throw new TypeError('lookup needs a snapshot from validate(); an unchecked filter cannot answer honestly');
  }`,
    replace: '',
    mustKill: ['an unvalidated filter cannot be looked up in at all'],
    // The command-line build mirrored the page's lookup without the page's
    // refusal, so a truncated .bin answered "not in the snapshot" for every
    // host. The brand is what stops that being a rule someone must remember.
  },

  {
    id: 'exit-discards-buffer',
    promise: 'A report longer than a pipe buffer arrives whole.',
    file: 'bin/kuvertii.js',
    find: `  (code) => { process.exitCode = code ?? 0; },`,
    replace: `  (code) => process.exit(code ?? 0),`,
    mustKill: ['a report longer than a pipe buffer arrives whole'],
    // Node writes stdout to a pipe synchronously on Linux and Windows, and
    // asynchronously on macOS. `process.exit` can therefore only discard a
    // buffer on macOS — which is where the truncation was found, and where
    // this mutation kills. On Linux there is nothing to discard, so no test
    // can go red and the mutation survives for a reason that says nothing
    // about the gate. Recorded rather than papered over: CI is Linux, the
    // maintainer is on darwin, and a registry that called this a gap would
    // have read as "unguarded" on the one platform where it is guarded.
    expectedToSurvive: ['linux', 'win32'],
  },

  {
    id: 'chunk-is-one-key',
    promise: 'Two keys arriving in one read are two keys.',
    file: 'js/keys.js',
    find: `      return [...typed];`,
    replace: `      return [String(chunk ?? '')];`,
    mustKill: [
      'two keys arriving together are two keys',
      'pasted text is data, not a burst of keypresses',
    ],
  },

  {
    id: 'contradictions-finding-anonymous',
    promise: 'A duplicated-field alert is reachable by its id, never only by its position.',
    file: 'js/findings.js',
    find: `    id: 'contradictions',`,
    replace: `    id: undefined,`,
    mustKill: ['two alerts firing together keep distinct, addressable ids'],
    // A real message carried a duplicated singleton beside a control byte, and
    // this finding shipped with no id while every other one had one — so a
    // selector asking for it by id got whichever alert the array put first.
  },

  {
    id: 'controls-finding-anonymous',
    promise: 'A control-byte alert is reachable by its id, never only by its position.',
    file: 'js/findings.js',
    find: `    id: 'controls',`,
    replace: `    id: undefined,`,
    mustKill: ['two alerts firing together keep distinct, addressable ids'],
    // The other half of the same omission: the control-characters finding sat at
    // the front of the report addressable only by position, which the tests it
    // had could reach but a caller keyed on id could not.
  },

  {
    id: 'controls-listed-not-categorised',
    promise: 'Every control and format character is caught, not a list of them.',
    file: 'js/control.js',
    find: `const HOSTILE = /[\\p{Cc}\\p{Cf}\\p{Co}\\p{Cs}\\p{Zl}\\p{Zp}]/u;`,
    replace: `const HOSTILE = /[\\x00-\\x08\\x0b-\\x1f\\x7f\\u061C\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\u2066-\\u2069\\uFEFF]/u;`,
    mustKill: [
      'the 8-bit escape introducers are neutralised like their ESC forms',
      'the characters the old ranges forgot are all caught now',
    ],
    // The exact two ranges this file used to carry. They are the reason the
    // whole C1 block, U+2028, private use and U+180E reached the screen while
    // the report said nothing had been found.
  },

  {
    id: 'c1-neutralised-but-unreported',
    promise: 'A sequence that is defused is also named.',
    file: 'js/control.js',
    find: `  let normalised = value;
  for (const [c1, escaped] of C1_INTRODUCERS) {
    if (normalised.includes(c1)) normalised = normalised.split(c1).join(escaped);
  }`,
    replace: `  const normalised = value;`,
    mustKill: ['an 8-bit sequence is reported, in the same words as its ESC form'],
    // Neutralising without reporting is the half-fix that hides itself: the
    // reader sees <U+009D> in the output and no finding explaining it.
  },

  {
    id: 'defang-needs-a-word-boundary',
    promise: 'No live URL survives into terminal output.',
    file: 'js/terminal.js',
    find: `const URL_RE = /(?:https?|ftps?):\\/\\/[^\\s<>"'\`]+/i;`,
    replace: `const URL_RE = /\\b(?:https?|ftps?):\\/\\/[^\\s<>"'\`]+/i;`,
    mustKill: ['a scheme is broken wherever it appears, not only at a word boundary'],
    // One underscore in front of the scheme was the whole bypass: no word
    // boundary, no split, and the hostname pass then spared it as a payload.
  },

  {
    id: 'payload-lines-unquoted',
    promise: 'The sender cannot write a line that reads as one of our verdicts.',
    file: 'js/terminal.js',
    find: `      const gutter = lines.length > 1 ? '│ ' : '';`,
    replace: `      const gutter = '';`,
    mustKill: ['a decoded payload cannot forge a row in either renderer'],
    // A base64 field decoding to a tick, a verdict and a reassuring sentence
    // rendered as further rows in this tool's own idiom. Nothing computed them.
  },

  {
    id: "truncation-goes-unreported",
    promise: "A report that covers less than was pasted says so.",
    file: "js/unfold.js",
    find: "  if (!lines) return '';",
    replace: "  return '';\n  // eslint-disable-next-line no-unreachable\n  if (!lines) return '';",
    mustKill: ["a line of whitespace ends the header, and the report says so"],
    // A ten-field header with one stray space analysed as six and reported it
    // in the same tone a complete one gets.
  },

  {
    id: "mojibake-scores-as-prose",
    promise: "What the decoder could not read is not shown as if it had been.",
    file: "js/decode.js",
    find: "    if (c === '\\uFFFD') return false;\n",
    replace: "",
    mustKill: [
      "bytes that are not text do not become text by being printed",
      "a decode the tool could not read is never put on screen",
    ],
    // U+FFFD counted as printable let a blob score 0.52 as prose. A real
    // newsletter printed five of them as campaign metadata, and the control
    // bytes alongside them were then read as an attack on the reader.
  },

  {
    id: "fold-splits-a-token",
    promise: "A field folded mid-token is read as the token it was.",
    file: "js/decode.js",
    find: "    if (halves.every((candidates) => candidates.length)) {",
    replace: "    if (halves.length) {",
    mustKill: ["a fold inside a token does not hide what it carries"],
    // Unfolding removes the line break, not the space. Splitting on whitespace
    // handed the decoder two halves of one base64 token, and the recipient's
    // own address inside it went unreported on real mail.
  },

  {
    id: "qp-decodes-any-escape",
    promise: "A decoding that is not text was not that encoding.",
    file: "js/decode.js",
    find: "    offer(textFromBytes(decodeQuotedPrintable(raw)), 'quoted-printable');",
    replace: "    offer(decodeQuotedPrintable(raw), 'quoted-printable');",
    mustKill: [
      "an ordinary Gmail message id is not a hidden address",
      "genuine quoted-printable decodes to the text it encodes",
    ],
    // Without the UTF-8 check, =8b in a Gmail message id decoded to a lone
    // continuation byte and the leftovers read as a recipient who never existed.
  },

  {
    id: "qp-decodes-printable-ascii-escape",
    promise: "A lone printable-ASCII =XX in an opaque id is not quoted-printable.",
    file: "js/decode.js",
    find: "  } else if (QP_HIGH_BYTE_RE.test(raw)) {",
    replace: "  } else if (/=[0-9A-F]{2}/i.test(raw)) {",
    mustKill: [
      "a printable-ASCII =XX in an opaque id is not a hidden recipient",
    ],
    // The =8b fix rejected an invalid-UTF-8 byte and left =41, =2E, =5F, =2B
    // open; real DKIM base64 (=` padding + two hex) manufactured a recipient.
  },

  {
    id: "encoded-word-whitespace-kept",
    promise: "Whitespace between two adjacent encoded-words is removed, as a client removes it.",
    file: "js/decode.js",
    find: "    .replace(/\\?=\\s+=\\?/g, '?==?')",
    replace: "    .replace(/\\?=\\s+=\\?/g, '?= =?')",
    mustKill: [
      "adjacent encoded-words join without the whitespace a client removes",
    ],
    // RFC 2047 §6.2. Keeping the space rendered café as `caf é` and let a
    // dangerous filename or a hidden address be split across two words.
  },

  {
    id: "encoded-word-language-tag-unstripped",
    promise: "An RFC 2231 language tag on the charset does not stop the word decoding.",
    file: "js/decode.js",
    find: "          const label = charset.toLowerCase().split('*')[0];",
    replace: "          const label = charset.toLowerCase();",
    mustKill: [
      "a language-tagged encoded-word filename is decoded before the danger check",
      "an encoded-word with an RFC 2231 language tag is still decoded",
    ],
    // RFC 2231 §5. `TextDecoder('utf-8*en')` throws, so the raw word was kept —
    // a filename =?utf-8*en?B?<report.exe>?= stayed opaque and the executable
    // check went silent on a file a client runs.
  },

  {
    id: "percent-encoding-unknown",
    promise: "The encoding every click tracker uses is one this tool reads.",
    file: "js/decode.js",
    find: "  if (/%[0-9A-F]{2}/i.test(raw)) {\n    offer(decodePercent(raw), 'percent-encoded');\n  }",
    replace: "",
    mustKill: [
      "a percent-encoded address is an encoded copy like any other",
      "an address hidden two layers deep is counted, not just displayed",
    ],
  },

  {
    id: "received-reads-its-comments",
    promise: "A hop encrypted with TLS is not reported as plaintext.",
    file: "js/findings.js",
    find: "  const clause = withoutComments(head);",
    replace: "  const clause = head;",
    mustKill: ["a hop encrypted with TLS is not reported as plaintext"],
    // RFC 5322 comments can hold anything, including the word the parser was
    // looking for: (Postfix with SMTP) answered before "with ESMTPS" was read.
  },

  {
    id: "drift-guard-cannot-fire",
    promise: "The drift guard runs where the build runs.",
    file: "tools/build-blocklist.mjs",
    find: "  const previous = await readFile(join(ROOT, 'tools/feed-baseline.json'), 'utf8')",
    replace: "  const previous = await readFile(join(ROOT, 'data/blocklist.json'), 'utf8')",
    mustKill: [
      "a feed that collapsed is refused, in the environment CI builds in",
      "a guard that cannot run is not mistaken for one that passed",
    ],
    // The original. It reads the previous build own metadata, which exists on a
    // developer machine and never in CI, where data/ is gitignored and every
    // run is a fresh checkout. The guard was documented, correct, and had never
    // once executed in production.
  },

  {
    id: 'controls-accused-not-named',
    promise: 'Nothing is accused without being named.',
    file: 'js/control.js',
    find: `  if (!effects.length && hasControls(value)) {`,
    replace: `  if (false && hasControls(value)) {`,
    mustKill: ['nothing is accused without being named'],
    // 148 codepoints made hasControls true and scanControls empty, so the card
    // fired and the row read "It ." with no cause given.
  },

  {
    id: 'email-swallows-the-scheme',
    promise: 'No address-shaped prefix can hide a live URL.',
    file: 'js/terminal.js',
    find: `\\.[a-z]{2,24}\\b(?!:\\/\\/)/i;`,
    replace: `\\.[a-z]{2,24}\\b/i;`,
    mustKill: ['an address-shaped prefix cannot hide the scheme behind it'],
  },

  {
    id: 'token-boundary-ascii-only',
    promise: 'The payload exemption and the line wrapper agree on what a word is.',
    file: 'js/terminal.js',
    find: `  const SPACE = /\\s/;`,
    replace: `  const SPACE = / /;`,
    mustKill: ['a no-break space separates words here exactly as it does on screen'],
  },

  {
    id: 'tls-reads-the-whole-clause',
    promise: 'A claim about what a comment says is read from the comment.',
    file: 'js/findings.js',
    find: `    tlsInComment: TLS_TOKEN.test(commentsOnly(head)),`,
    replace: `    tlsInComment: TLS_TOKEN.test(head),`,
    mustKill: ['a TLS-shaped hostname does not make a plaintext hop encrypted'],
    // `from` is the name the connecting client supplies, so this was a false
    // security claim from attacker-controlled input.
  },

  {
    id: 'tls-token-needs-a-boundary',
    promise: 'TLS is recognised in the spellings servers actually write.',
    file: 'js/findings.js',
    find: `const TLS_TOKEN = /\\bTLS[v._\\d]*/i;`,
    replace: `const TLS_TOKEN = /\\bTLS(?:v[\\d.]+)?\\b/i;`,
    mustKill: ['a Microsoft 365 hop declaring TLS1_2 is not called plaintext'],
    // `TLS1_2` never provides the trailing word boundary, so the guard written
    // for Microsoft 365 hops fired on none of them.
  },

  {
    id: 'plaintext-counted-as-hidden',
    promise: 'An address written in the open is never called a hidden one.',
    file: 'js/findings.js',
    find: `        if (inTheClear.has(address)) continue;`,
    replace: '',
    mustKill: ['an address written in the open is never called a hidden one'],
    // A decoder returns the whole value with one part changed, so plaintext
    // beside an encoded token rode along and was reported as recoverable only
    // by decoding.
  },

  {
    id: 'paste-state-forgotten',
    promise: 'A paste split across reads is still a paste.',
    file: 'js/keys.js',
    find: `          if (end === -1) return [...typed]; // the paste continues into the next read`,
    replace: `          if (end === -1) { pasting = false; return [...typed]; }`,
    mustKill: ['a paste split across reads stays a paste'],
  },

  {
    id: 'keys-after-quit',
    promise: 'No key after the decision to leave is acted on.',
    file: 'js/keys.js',
    find: `    if (isQuit(key)) break;`,
    replace: "",
    mustKill: ['nothing after the quit key is handed on'],
  },

  {
    id: 'unbalanced-comment-eats-the-clause',
    promise: 'A comment that never closes is not a comment.',
    file: 'js/findings.js',
    find: `  return depth === 0 ? out : text;`,
    replace: `  return out;`,
    mustKill: ['an unbalanced parenthesis does not erase the receiving server'],
  },

  {
    id: 'import-walk-one-spelling',
    promise: 'The walk sees every way a module can be named.',
    file: 'test/graph.js',
    find: "const SPECIFIER = /\\b(?:from|import)\\s*\\(?\\s*['\"]([^'\"\\n]{1,200})['\"]/g;",
    replace: "const SPECIFIER = /(?:from|import) '([^']+)'/g;",
    mustKill: ['the walk sees a module however its import is written'],
  },

  // ------------------------------------------------- promises with no gate yet
  //
  // Everything below is expected to survive today. Each one is a promise the
  // README or the code's own comments make, with nothing standing behind it.
  {
    id: 'senders-fetch',
    promise: 'No module the CLI loads can reach the network.',
    file: 'js/senders.js',
    find: `export function identifySender(`,
    replace: `export async function enrichSenderByMutation(ip) {
  const response = await fetch(\`https://mutation.invalid/whois?ip=\${ip}\`);
  return response.text();
}

export function identifySender(`,
    mustKill: [
      'nothing the command loads can reach the network',
      'the page reaches only for its own two static assets',
    ],
    // Was a known gap until test/network.test.js replaced the hand-written list
    // of five filenames with a walk of both import graphs. js/senders.js is one
    // of the ten modules that list never covered, and the CLI has no CSP
    // underneath to catch what a test misses.
  },

  {
    id: 'app-anchor-href',
    promise: 'A URL out of a header never becomes clickable.',
    file: 'js/app.js',
    find: `function el(tag, className, text) {
  const node = document.createElement(tag);`,
    replace: `function elByMutation(value) {
  const link = document.createElement('a');
  link.href = String(value);
  return link;
}

function el(tag, className, text) {
  const node = document.createElement(tag);`,
    mustKill: ['the page assigns only the node properties it has decided about'],
    // Was a known gap: the sink regex banned the names somebody thought of and
    // not property assignment, so `link.href = …` was invisible to it. The
    // check now runs the other way — an allowlist of properties, anything else
    // fails — because the list of ways to reach the DOM is the platform's and
    // grows, while the list this page needs is ours and is written down.
  },

  {
    id: 'app-neutralise-removed',
    promise: 'The page renders header text inert, exactly as the terminal does.',
    file: 'js/app.js',
    find: `if (text !== undefined && text !== null) node.textContent = neutralise(text);`,
    replace: `if (text !== undefined && text !== null) node.textContent = String(text);`,
    mustKill: ['no hostile byte from a header reaches the page'],
    // Was a known gap: every escape-stripping test drove the terminal renderer,
    // so the browser's single call site could be deleted with the whole suite
    // green. test/app.test.js now asks the DOM the same question.
  },

  {
    id: 'csp-scheme-source',
    promise: 'The page cannot talk to any origin but its own.',
    file: 'index.html',
    find: `connect-src 'self';`,
    replace: `connect-src 'self' https:;`,
    mustKill: ['the CSP allows the page to work and nothing beyond it'],
    // Was a known gap. A scheme-source has no slashes, so it matched neither
    // the wildcard check nor the `https://host` check the old test made — the
    // page could have sent a pasted address anywhere on the web with CI green.
    // The policy is now parsed and every source checked against a per-directive
    // allowlist, so a new source fails until somebody writes down why it belongs.
  },

  // ------------------------------------------------------ round three
  //
  // All three are the same shape as round two's: a rule that was right about
  // the example it was written from, and silent about the rest of the range
  // that example came from.

  {
    id: 'date-separator-ignores-comments',
    promise: 'A semicolon a sender puts in a comment is not the date separator.',
    file: 'js/findings.js',
    find: `  return depth === 0 ? index : text.lastIndexOf(';');`,
    replace: `  return text.lastIndexOf(';');`,
    mustKill: [
      'a semicolon inside a comment is not mistaken for the date separator',
      'a comment in the route cannot suppress an expired signature',
    ],
    // The replacement is the code as it stood: `unbalanced-comment-eats-the-clause`
    // closed this defect at `withoutComments` and left the same erasure
    // reachable one function earlier, through the split that feeds it.
  },

  {
    id: 'dkim-reads-one-signature',
    promise: 'Every DKIM signature is described, not just the first.',
    file: 'js/findings.js',
    find: `  const dkimSignatures = getAll(headers, 'dkim-signature');`,
    replace: `  const dkimSignatures = getAll(headers, 'dkim-signature').slice(0, 1);`,
    mustKill: ['a second DKIM signature is described, not hidden behind the first'],
  },

  {
    id: 'signature-rows-unbounded',
    promise: 'The sender cannot decide how many rows the authentication card has.',
    file: 'js/findings.js',
    find: `  for (const rows of ordered.slice(0, DESCRIBED_AT_MOST)) items.push(...rows);`,
    replace: `  for (const rows of ordered) items.push(...rows);`,
    mustKill: ['a flood of DKIM signatures is bounded, and the warnings survive it'],
    // This one was introduced by the fix directly above it. Reading every
    // signature was right; leaving the count to the sender while doing it was
    // the same defect the fix had just closed, one field further out.
  },

  {
    id: 'verdict-position-unread',
    promise: 'A verdict the last hop did not write is not presented as one it did.',
    file: 'js/findings.js',
    find: `    const below = lastHop !== -1 && headers.indexOf(field) > lastHop;`,
    replace: `    const below = false;`,
    mustKill: ['a verdict written below a Received is reported as not the last hop\'s'],
  },

  {
    id: 'auth-first-hop-cries-wolf',
    promise: 'The delivering provider\'s own Authentication-Results, sitting mid-chain, is not accused.',
    file: 'js/findings.js',
    find: `  const lastHop = headers.findLastIndex((h) => lower(h.name) === 'received');`,
    replace: `  const lastHop = headers.findIndex((h) => lower(h.name) === 'received');`,
    mustKill: ['an Authentication-Results mid-chain is not accused — internal hops stack above it'],
    // The standing gap made concrete by the corpus: "below the first Received"
    // accused the delivering provider's own results on all 25 real messages, 17
    // with no forwarding. Received-SPF and Forefront were corrected months
    // earlier; this is the same fix arriving late to the third check.
  },

  {
    id: 'verdict-cfws-hides-fail',
    promise: 'A decisive verdict is read whether or not a space sits around its `=`.',
    file: 'js/findings.js',
    find: `    for (const [, mechanism, verdict] of field.value.matchAll(/\\b(spf|dkim|dmarc|arc|bimi)[ \\t]*=[ \\t]*(\\w+)/gi)) {`,
    replace: `    for (const [, mechanism, verdict] of field.value.matchAll(/\\b(spf|dkim|dmarc|arc|bimi)=(\\w+)/gi)) {`,
    mustKill: ['a decisive verdict spelled with a space around = is still read as a failure'],
    // RFC 8601 allows CFWS around `=`; the bare-`=` scanner missed `dkim = fail`
    // and headlined all-clear over it.
  },

  {
    id: 'compauth-cfws-hides-fail',
    promise: 'compauth is read whether or not a space sits around its `=`.',
    file: 'js/findings.js',
    find: `  const compauth = results.match(/\\bcompauth[ \\t]*=[ \\t]*(\\w+)/i)?.[1]?.toLowerCase();`,
    replace: `  const compauth = results.match(/\\bcompauth=(\\w+)/i)?.[1]?.toLowerCase();`,
    mustKill: ['a decisive verdict spelled with a space around = is still read as a failure'],
    // `compauth = fail` written no bad row, and its absence let the headline read
    // all-clear over a composite failure.
  },

  {
    id: 'reason-cfws-hides-bad-code',
    promise: 'A compauth reason code is read whether or not a space sits around its `=`.',
    file: 'js/findings.js',
    find: `    const code = results.match(/\\breason[ \\t]*=[ \\t]*(\\d{3})/i)?.[1];`,
    replace: `    const code = results.match(/\\breason=(\\d{3})/i)?.[1];`,
    mustKill: ['a decisive verdict spelled with a space around = is still read as a failure'],
    // The round-9 defect (a bad reason row denies the headline) returning through
    // the CFWS gap: `reason = 000` wrote no row, so the headline went all-clear.
  },

  {
    id: 'score-falls-through-to-the-worst-branch',
    promise: 'A score field that holds no score is not read as the highest one.',
    file: 'js/microsoft.js',
    find: `  if (!/^-?\\d+$/.test(text)) return null;
  const value = Number(text);
  return value >= min && value <= max ? value : null;`,
    replace: `  return Number(text);`,
    mustKill: ['a score that is not a score is not read as the worst one'],
    // The replacement is what the code did: `Number()` and a chain of `<=`,
    // where every comparison against NaN is false and the chain ends in the
    // most severe reading the score has.
  },

  {
    id: 'zero-length-reads-as-partial',
    promise: 'A signature covering none of the body says so, rather than counting to zero.',
    file: 'js/findings.js',
    find: `        : bytes === 0
          ? {
            label: forSignature('None of the message body is signed', domain),`,
    replace: `        : false
          ? {
            label: forSignature('None of the message body is signed', domain),`,
    mustKill: ['a signed length that is not a length is not printed as a figure'],
    // Separate from `signed-length-unbounded` because it is a separate promise:
    // that one is about a value too large to mean anything, this one about the
    // smallest value the tag can take being the most serious.
  },

  {
    id: 'signed-length-unbounded',
    promise: 'A length too large to be a length is named, not printed as a figure.',
    file: 'js/findings.js',
    find: `      collect(rows, !Number.isSafeInteger(bytes)`,
    replace: `      collect(rows, false`,
    mustKill: ['a signed length that is not a length is not printed as a figure'],
  },

  {
    id: 'address-literal-ipv4-only',
    promise: 'A link to a bare address is named whichever family the address is from.',
    file: 'js/links.js',
    find: `  return IPV4_RE.test(hostname) || hostname.startsWith('[');`,
    replace: `  return IPV4_RE.test(hostname);`,
    mustKill: ['a bare IPv6 address is named as a bare address'],
  },

  {
    id: 'angle-brackets-swallow-the-tag',
    promise: 'A markup tag never swallows the URL inside it.',
    file: 'js/links.js',
    find: `    /<((?:https?:\\/\\/|mailto:)[^\\s>]+)>|(https?:\\/\\/[^\\s<>"']+)|(mailto:[^\\s<>"',]+)/gi,`,
    replace: `    /<([^>]+)>|(https?:\\/\\/[^\\s<>"']+)|(mailto:[^\\s<>"',]+)/gi,`,
    mustKill: [
      'a markup tag does not swallow the url inside it',
      'an image source inside a tag is found too',
    ],
    // Round 7. The angle-bracket branch is there to unwrap <https://…>; it
    // accepted anything between the brackets and then discarded whatever did
    // not begin with a scheme, so `<a href="…">` was consumed whole and the
    // destination went with the tag. In any body read as plain text the href
    // was deleted and the link text survived.
  },

  {
    id: 'serve-public-bind',
    promise: 'The dev server listens on loopback only.',
    file: 'tools/serve.mjs',
    find: `export const BIND = '127.0.0.1';`,
    replace: `export const BIND = '0.0.0.0';`,
    mustKill: ['the dev server binds loopback only, and is asked rather than read'],
    // Was a known gap: test/serve.test.js exercised the real `resolve` but never
    // the bind address — the one part of that file deciding who can reach it.
    // The test now binds an ephemeral port and asks the socket, because reading
    // the constant would pass just as happily once `listen` stopped using it.
  },

  {
    id: 'inconclusive-scored-as-survived',
    promise: 'A mutation run that never reached a verdict is inconclusive, not a survivor.',
    file: 'tools/mutate.mjs',
    find: `  if (!ranToCompletion) return 'inconclusive';`,
    replace: `  if (false) return 'inconclusive';`,
    mustKill: ['a run that never reached a verdict is inconclusive, never a survivor'],
    // The harness scoring its own aborted runs. `status !== 0 && ranToCompletion`
    // read a timed-out or failed-to-spawn run — non-zero exit, no plan emitted —
    // as SURVIVED, and a live mutation was reported as an unguarded promise on a
    // byte-identical tree (zero-length-reads-as-partial, 2026-08-20). Without
    // this guard classifyRun falls back to status alone, so the third outcome
    // collapses into the two that assume the suite answered.
  },

  {
    id: 'port-strip-eats-hextet',
    promise: 'An address literal survives normalisation as the address it is.',
    file: 'js/bloom.js',
    find: `  const stripped = /^[^:]+:\\d+$/.test(text) ? text.replace(/:\\d+$/, '') : text;`,
    replace: `  const stripped = text.replace(/:\\d+$/, '');`,
    mustKill: ['an address literal survives normalisation intact'],
    // The original. ":digits at the end" is a port on a hostname and the last
    // hextet on an IPv6 literal, so `::1` normalised to `:` and the report
    // named a host nobody asked about.
  },

  {
    id: 'ipv6-probed-anyway',
    promise: 'A question the filter cannot hold an answer to is not answered from it.',
    file: 'js/snapshot.js',
    find: `  if (host.includes(':')) {`,
    replace: `  if (false) {`,
    mustKill: ['an IPv6 literal is reported as unchecked, never as absent'],
    // Removing the branch sends an IPv4-mapped literal into the label walk,
    // where its dots read as label boundaries and the zero-basis miss comes
    // back phrased like a real one.
  },

  {
    id: 'single-label-zero-probe-miss',
    promise: 'Zero probes never produce the sentence a real miss earns.',
    file: 'js/snapshot.js',
    find: `  if (labels.length < 2) {`,
    replace: `  if (false) {`,
    mustKill: ['a single-label name is reported as unchecked, never as absent'],
    // The original, by omission: `localhost` fell out of the walk with zero
    // probes and still rendered "is not in the blocklist snapshot".
  },

  {
    id: 'clip-note-never-written',
    promise: 'Input cut at the ceiling is announced wherever the tally is printed.',
    file: 'js/unfold.js',
    find: `  if (originalLength <= MAX_HEADER_BYTES) return '';`,
    replace: `  return '';`,
    mustKill: [
      'input cut at the ceiling says so, and an uncut input says nothing',
      'input cut at the ceiling is announced, not silently tallied',
    ],
  },

  {
    id: 'cli-clips-in-silence',
    promise: 'The command announces the cut in the same breath as the tally.',
    file: 'bin/kuvertii.js',
    find: '${bodySkipped}${notes.join(\'\')}${clipped} Nothing left this machine.',
    replace: '${bodySkipped}${notes.join(\'\')} Nothing left this machine.',
    mustKill: ['input cut at the ceiling is announced, not silently tallied'],
    // The original. The page carried the note and the command did not — two
    // copies of one claim, one of them lost. The wording now lives in
    // clippedNote and both renderers print what it returns.
  },

  {
    id: 'received-spf-always-receivers-words',
    promise: 'A field is quoted as the receiver\'s words only where a receiver would have put it.',
    file: 'js/findings.js',
    find: `      const below = lastHop !== -1 && headers.indexOf(receivedSpfField) > lastHop;`,
    replace: `      const below = false;`,
    mustKill: ['a Received-SPF below a Received is not quoted as the receiver\'s words'],
    // The original, in effect: the note always read "The receiving server's
    // own words" — for a field a sender writes in one line.
  },

  {
    id: 'received-spf-first-hop-cries-wolf',
    promise: 'The receiver\'s own Received-SPF, sitting mid-chain, is not accused.',
    file: 'js/findings.js',
    find: `      const lastHop = headers.findLastIndex((h) => h.name.toLowerCase() === 'received');`,
    replace: `      const lastHop = headers.findIndex((h) => h.name.toLowerCase() === 'received');`,
    mustKill: ['a Received-SPF mid-chain is not accused — internal hops stack above it'],
    // The first cut of the check, caught on a real iCloud message the day it
    // shipped: smtpin records the check, mailgateway stamps a Received on
    // top, and "below the first Received" marked the receiver's own field.
  },

  {
    id: 'forefront-position-unread',
    promise: 'A Microsoft filter report no hop wrote is marked as arriving pre-written.',
    file: 'js/microsoft.js',
    find: `  if (reports.length && lastHop !== -1 && headers.indexOf(reports[0]) > lastHop) {`,
    replace: `  if (false) {`,
    mustKill: ['a forefront report below a Received is marked as an earlier hop\'s'],
  },

  {
    id: 'forefront-first-hop-cries-wolf',
    promise: 'Microsoft\'s own mid-chain filter report is not accused.',
    file: 'js/microsoft.js',
    find: `  const lastHop = headers.findLastIndex((h) => h.name.toLowerCase() === 'received');`,
    replace: `  const lastHop = headers.findIndex((h) => h.name.toLowerCase() === 'received');`,
    mustKill: ['a forefront report below a Received is marked as an earlier hop\'s'],
    // Real M365 mail carries internal Received lines above the report; asking
    // "below the first Received?" cries wolf on every ordinary delivery.
  },

  {
    id: 'forefront-second-copy-invisible',
    promise: 'A second filter report is named, never silently unreachable.',
    file: 'js/microsoft.js',
    find: `  if (reports.length > 1) {`,
    replace: `  if (false) {`,
    mustKill: ['a second forefront report is named, not silently unreachable'],
    // The probe put a fabricated CAT:NONE above Microsoft's real CAT:PHSH and
    // the phishing verdict was not merely unreported but unreachable.
  },

  {
    id: 'original-recipient-not-in-the-clear',
    promise: 'A field that names the recipient counts as naming the recipient.',
    file: 'js/findings.js',
    find: `const RECIPIENT_PRESENT = ['to', 'cc', 'delivered-to', 'x-original-to', 'envelope-to', 'x-rcpt-to', 'original-recipient'];`,
    replace: `const RECIPIENT_PRESENT = ['to', 'cc', 'delivered-to', 'x-original-to', 'envelope-to'];`,
    mustKill: ['a recipient named only in Original-Recipient is named in the clear'],
    // The original list. A real iCloud message carried Original-Recipient and
    // rendered "no recipient is named in the clear" one card above the card
    // reading the recipient openly out of exactly that field.
  },

  {
    id: 'lede-leans-on-missing-to',
    promise: 'No sentence leans on a field the paste does not carry.',
    file: 'js/findings.js',
    find: `  const hasTo = Boolean(get(headers, 'to').trim());`,
    replace: `  const hasTo = true;`,
    mustKill: ['a recipient named only in Original-Recipient is named in the clear'],
  },

  {
    id: 'dmarc-record-printed-raw',
    promise: 'A policy row prints a policy word, never a raw record.',
    file: 'js/findings.js',
    find: `  const policy = record.match(/\\bp=(none|quarantine|reject)\\b/i)?.[1]
    ?? fieldRecord.trim().match(/^(none|quarantine|reject)$/i)?.[1];`,
    replace: `  const policy = fieldRecord || dmarc.match(/\\bp=(none|quarantine|reject)\\b/i)?.[1];`,
    mustKill: ['a receiver\'s copy of the whole DMARC record is read, never printed raw'],
    // The original. iCloud's X-DMARC-Policy carries the fetched record
    // verbatim, and a real message rendered "v=DMARC1; p=reject; adkim=s;
    // aspf=r; rf=afrf; pct=100;." as the published policy.
  },

  {
    id: 'return-path-disagreement-swallowed',
    promise: 'Two bounce addresses on one message are pointed out, not first-wins resolved.',
    file: 'js/findings.js',
    find: `  if (new Set(returnPaths.map((v) => v.trim().toLowerCase())).size > 1) {`,
    replace: `  if (false) {`,
    mustKill: ['two Return-Path lines naming different addresses are pointed out'],
  },

  {
    id: 'psl-line-becomes-code',
    promise: 'No upstream line reaches the generated module without matching the shape of a rule.',
    file: 'tools/build-psl.mjs',
    find: `  if (!RULE_RE.test(name)) {`,
    replace: `  if (false) {`,
    mustKill: ['a line that is not a rule stops the build instead of becoming code'],
    // The original, by omission: every non-comment line was interpolated into
    // a template literal inside committed, browser-executed js/psl.js. A line
    // carrying a backtick or ${ would not have been a bad entry — it would
    // have been code.
  },

  {
    id: 'overflow-blamed-on-tool',
    promise: 'A clipboard too large to read is not reported as a broken tool.',
    file: 'js/clipboard.js',
    find: `  if (error?.code !== 'ENOBUFS') return null;`,
    replace: `  return null;`,
    mustKill: ['a clipboard too large to read is not blamed on the tool'],
    // The original, by omission: ENOBUFS fell into the same bucket as ENOENT,
    // and a 33 MB clipboard printed "no clipboard tool worked" — directing the
    // reader to install something, for a problem copying less would solve.
  },

  {
    id: 'ipv4-walked-over-octets',
    promise: 'An IPv4 literal is asked of the filter exactly, not walked like a name.',
    file: 'js/snapshot.js',
    find: `  if (IPV4_RE.test(host)) {`,
    replace: `  if (false) {`,
    mustKill: ['an IPv4 literal gets one exact probe and no label walk'],
    // Without the branch, `192.0.2.7` makes three probes — one of them asking
    // whether `0.2.7` is a phishing domain — and the printed false-alarm odds
    // are computed for questions that were never worth asking.
  },

  // ------------------------------------------------------------ the body path
  {
    id: 'mime-depth-unbounded',
    promise: 'MIME nesting past the ceiling is kept unopened, and the report says so.',
    file: 'js/mime.js',
    find: `    if (depth >= MAX_DEPTH) {`,
    replace: `    if (false) {`,
    mustKill: ['nesting past the depth ceiling is kept unopened, and says so'],
    // The sender writes the nesting. Without the ceiling a boundary bomb
    // recurses as deep as its author cared to type, on the browser's main
    // thread, with the reader watching a frozen tab.
  },

  {
    id: 'mime-part-count-unbounded',
    promise: 'Parts past the ceiling are counted out loud, never silently dropped or endlessly read.',
    file: 'js/mime.js',
    find: `  if (parts.length >= MAX_PARTS) {`,
    replace: `  if (false) {`,
    mustKill: ['more parts than the ceiling are counted, not silently dropped'],
  },

  {
    id: 'body-clip-silent',
    promise: 'A body cut at the ceiling is announced, not silently tallied as read.',
    file: 'js/mime.js',
    find: `  if (originalLength <= MAX_BODY_BYTES) return '';`,
    replace: `  return '';
  // eslint-disable-next-line no-unreachable
  if (originalLength <= MAX_BODY_BYTES) return '';`,
    mustKill: [
      'an oversized body is clipped, and the note says exactly that',
      'a body under the ceiling earns no note',
    ],
    // The round-5 lesson, applied on day one instead of after the fact: a
    // silent clip makes the closing tally a lie about what was read.
  },

  {
    id: 'body-mismatch-string-compare',
    promise: 'A link\'s claim is compared by registrable domain, never by hostname string.',
    file: 'js/body.js',
    find: `      if (claimedDomain !== linkDomain && claimedDomain !== effectiveDomain) {`,
    replace: `      if (claimed !== linkHost && claimed !== effective.hostname) {`,
    mustKill: [
      'the same registrable domain is never a mismatch',
      'a subdomain of the claimed domain is never a mismatch',
    ],
    // The replacement is the obvious first draft: string against string. It
    // fires on `www.paypal.com` over a paypal.com link — a warning printed on
    // half of all honest mail, which is how a warning stops being read.
  },

  {
    id: 'address-dressed-as-domain',
    promise: 'An address literal is named whole, never squeezed through the domain logic.',
    file: 'js/body.js',
    find: `  return isAddressLiteral(host) ? host : registrableDomain(host);`,
    replace: `  return registrableDomain(host);`,
    mustKill: ['an address literal is named whole, never as two octets in a domain suit'],
    // The original, found on the second real-shaped probe: registrableDomain
    // reads 203.0.113.44 as labels and answers "113.44", and the card printed
    // that as where the link goes.
  },

  {
    id: 'inventory-prints-the-reading',
    promise: 'A row that says "declared" reads the declaration, not the reading.',
    file: 'js/body.js',
    find: `    const stated = part.declaredType ?? part.contentType;`,
    replace: `    const stated = part.contentType;`,
    mustKill: ['the inventory names the type the part declared, not the one it was read as'],
    // Round 7, self-inflicted. Once content outranks the declaration, a .txt
    // attachment holding markup is read as text/html — and this card said
    // "Declared as text/html" over a part that declared text/plain, in the one
    // card whose subject is precisely that difference.
  },

  {
    id: 'autolinked-url-unread',
    promise: 'A URL a mail client would turn into a link is a destination like any other.',
    file: 'js/body.js',
    find: `      for (const url of autolinkedUrls(scan)) collected.push({ href: url, text: '' });`,
    replace: '',
    mustKill: ['a url written into the visible text of an html part is a destination'],
    // Round 7. Only hrefs and form actions were read out of an HTML part, so a
    // message whose one destination was typed into a paragraph — which every
    // client autolinks, and which much ordinary bulk mail does — produced no
    // link card whatever. The real binary said nothing at all about
    // tracker.evil.example.
  },

  {
    id: 'link-text-counted-as-destination',
    promise: 'A link\'s own text is a claim about it, never a place the message goes.',
    file: 'js/body.js',
    find: `  const claimed = new Set(scan.links.flatMap((link) => extractUrls(link.text)));
  return extractUrls(scan.text).filter((url) => !claimed.has(url));`,
    replace: `  return extractUrls(scan.text);`,
    mustKill: ['a link\'s own text is a claim, never counted as a place the message goes'],
    // The other half of the entry above: reading the visible text for
    // destinations puts the decoy back on the card as somewhere the reader can
    // land, which is the one thing the mismatch rule exists to prevent.
  },

  {
    id: 'divergence-pairs-on-the-reading',
    promise: 'The two versions are paired by what the message offered, not by how each was read.',
    file: 'js/body.js',
    find: `  const offeredAs = (part) => part.declaredType ?? part.contentType;`,
    replace: `  const offeredAs = (part) => part.contentType;`,
    mustKill: ['a plain version that mentions a tag is still the plain version'],
    // Round 7, self-inflicted and found by probing the fix rather than the
    // bug: once content outranks the declaration, a text/plain part that
    // mentions a <table> in prose is read as markup — correctly — and pairing
    // on the reading then left the message with no plain side, so the card
    // silently stopped comparing.
  },

  {
    id: 'body-only-notice-promises-a-reading',
    promise: 'The body-only notice never promises a reading that did not happen.',
    file: 'js/body.js',
    find: `  const rest = bodyWasRead
    ? ' What the body itself says is read below.'
    : ' The body was not read either, so nothing below describes it.';`,
    replace: `  const rest = ' What the body itself says is read below.';`,
    mustKill: ['the notice does not promise a reading that did not happen'],
    // Round 7, found by running the real binary: `kuvertii --headers-only`
    // over a body-only paste printed one card announcing that the body was
    // read below, and then the report ended.
  },

  {
    id: 'body-form-quiet',
    promise: 'A form inside a mail body is always a warning row.',
    file: 'js/body.js',
    find: `    warn(\`form:\${host ?? '(unstated)'}\`, {`,
    replace: `    if (false) warn(\`form:\${host ?? '(unstated)'}\`, {`,
    mustKill: ['a form in a mail body is bad, named with its action'],
  },

  {
    id: 'undeclared-markup-read-as-plain',
    promise: 'A body that is visibly markup is judged by its hrefs, never by its decoy text.',
    file: 'js/mime.js',
    find: `  const contentType = typeForContent(declared, body);`,
    replace: `  const contentType = parseContentType(declared);`,
    mustKill: [
      'an undeclared body that is visibly markup is read as HTML',
      'a body-only html paste judges the hrefs, not the decoy text',
    ],
    // The original, found by running the real binary over a body-only paste:
    // with no Content-Type the HTML was read as plain text, the hrefs
    // vanished inside their angle brackets, and the card tallied "dhl.de —
    // 1 link" for a link that went to a bare IP.
  },

  {
    id: 'absent-size-reads-as-zero',
    promise: 'A size nobody stated is unstated, never a stated zero.',
    file: 'js/mime.js',
    find: `  const declared = parameter(raw, 'size');
  const size = declared === null ? null : Number(declared);`,
    replace: `  const size = Number(parameter(raw, 'size'));`,
    mustKill: [
      'an attachment with no size= is measured, not called zero bytes',
      'a size= that is not a size is no size at all',
    ],
    // Round 7, and older than the body path. `size=` is optional and most
    // mailers never write it; `Number(null)` is 0, which passed the
    // safe-integer check as a stated size of zero, so bytesDeclared never fell
    // through to the decoded length. The real binary printed "Declared as
    // application/pdf, 0 bytes." over an ordinary invoice. It survived five
    // audit rounds because the fixture beside it states size=90210.
  },

  {
    id: 'tally-with-nothing-to-count',
    promise: 'The closing tally can say that nothing was read.',
    file: 'js/mime.js',
    find: '  return read ? `${read} read.` : \'Nothing was read.\';',
    replace: '  return `${read} read.`;',
    mustKill: ['a tally with nothing to count says so, rather than opening with a blank'],
    // Round 7. Built by joining the non-zero counts, the line printed a bare
    // " read." with no subject whenever both were zero — on the command line
    // with --headers-only over a body-only paste, and on the page when
    // parseParts degrades to no parts. The one sentence whose job is a
    // complete account of the input could not say the input had not been read.
  },

  {
    id: 'declaration-outranks-content',
    promise: 'A body that is visibly markup is read as markup whatever it declares.',
    file: 'js/mime.js',
    find: `  const openToReading = !String(declared ?? '').trim() || parsed.type.startsWith('text/');`,
    replace: `  const openToReading = !String(declared ?? '').trim();`,
    mustKill: [
      'a declared text/plain over markup is read as markup all the same',
    ],
    // Round 7. The rule above held only where nothing was declared — and the
    // declaration is written by the party that gains from the misreading. One
    // `Content-Type: text/plain` over an HTML body put it back on the plain
    // path, where the href vanished inside its tag: the real binary printed
    // paypal.com as the destination of a link going to tracker.evil.example
    // and never named that host anywhere.
  },

  {
    id: 'lost-boundary-swallows-the-body',
    promise: 'A multipart whose parts cannot be told apart keeps its content, and says so.',
    file: 'js/mime.js',
    find: `      state.unreadableStructure = true;
      leaf(typeForContent('', body), encoding, disposition, body, parts, state, {});`,
    replace: `      leaf(contentType, encoding, disposition, body, parts, state, { opaque: true });`,
    mustKill: [
      'a boundary that never appears keeps the content and announces itself',
      'a lost boundary does not hide the links underneath it',
      'a multipart with no boundary parameter is read as one part, and says so',
    ],
    // Round 7, and the cheapest attack the body path had. A `boundary=` the
    // sender never uses cost one header line and emptied the entire body
    // report: the content was kept as an opaque part, every producer skips a
    // part with no text, and the tally still read "1 body part read". A
    // lookalike link and a tracking pixel drew no card at all. The other three
    // unreadable outcomes here — too deep, too many parts, too large — all
    // announced themselves; this was the only one that did not, and the only
    // one the sender could trigger for free.
  },

  {
    id: 'unreadable-structure-unannounced',
    promise: 'A structure that could not be followed is said out loud, not merely worked around.',
    file: 'js/mime.js',
    find: `  if (state.unreadableStructure) {`,
    replace: `  if (false) {`,
    mustKill: [
      'a boundary that never appears keeps the content and announces itself',
      'a multipart with no boundary parameter is read as one part, and says so',
    ],
  },

  {
    id: 'pixel-geometry-unread',
    promise: 'A 1x1 image is named as the tracking pixel it is.',
    file: 'js/body.js',
    find: `    if (Number.isInteger(width) && Number.isInteger(height) && width <= 1 && height <= 1) {`,
    replace: `    if (false) {`,
    mustKill: [
      'a 1x1 image is named a tracking pixel, with its host',
      'a pixel carrying an opaque id is marked as identifying this copy',
    ],
  },

  {
    id: 'address-spellings-unsearched',
    promise: 'The reader\'s address is searched for in every cheap spelling, base64 included.',
    file: 'js/body.js',
    find: `      ['base64', base64Trimmed(address)],
      ['base64, URL-safe', base64Trimmed(address).replace(/\\+/g, '-').replace(/\\//g, '_')],`,
    replace: ``,
    mustKill: ['the base64 spellings are found, both alphabets'],
    // Base64 is how the address most often travels — an open substring
    // search alone answers "not carried" about a link that carries it.
  },

  {
    id: 'crossref-matches-the-hostname',
    promise: 'A header id joins a link through its path or query, never through the hostname.',
    file: 'js/body.js',
    find: `      if ((parsed.pathname + parsed.search).includes(token)) joined.add(party(parsed.hostname));`,
    replace: `      if (url.includes(token)) joined.add(party(parsed.hostname));`,
    mustKill: ['an id that merely echoes the hostname joins nothing'],
    // The replacement accuses every link on the sender's own numbered
    // subdomain of tying the mailbox to the click.
  },

  {
    id: 'hash-compared-case-sensitively',
    promise: 'Hex is compared without case, because hex has none.',
    file: 'js/emailhash.js',
    find: `    const normalised = token.toLowerCase();`,
    replace: `    const normalised = token;`,
    mustKill: ['an uppercase hex token still matches — hex has no case'],
  },

  {
    id: 'md5-gap-unstated',
    promise: 'An MD5-shaped token this tool cannot check is reported as unchecked, never skipped.',
    file: 'js/emailhash.js',
    find: `  if (byLength.has(MD5_HEX_LENGTH)) {`,
    replace: `  if (false) {`,
    mustKill: ['an MD5-shaped token is reported as unchecked, never silently skipped'],
    // Saying nothing about the one digest crypto.subtle refuses would read
    // as "checked and clean" — the false reassurance this project is
    // written against.
  },

  {
    id: 'double-extension-unread',
    promise: 'A name wearing two extensions is called the trick it is, not a mere executable.',
    file: 'js/body.js',
    find: `    if (DOUBLE_EXTENSION_RE.test(runs)) {`,
    replace: `    if (false) {`,
    mustKill: ['a double extension is bad, and the trick is explained'],
    // The fallthrough still marks it executable, so the level survives — what
    // is lost is the explanation of the disguise, which is what the reader
    // needed: clients that hide known extensions show only the harmless half.
  },

  {
    id: 'filename-danger-reads-raw-name',
    promise: 'The danger checks read the name the OS runs, not the name as written.',
    file: 'js/body.js',
    find: `    const runs = osResolvedName(name);`,
    replace: `    const runs = name;`,
    mustKill: ['a name the OS strips to an executable is not read as harmless'],
    // A trailing dot, space or `::$DATA` suffix hid the extension from the
    // `$`-anchored checks; Windows strips it and runs the file anyway.
  },

  {
    id: 'continuation-filename-unread',
    promise: 'A filename split across RFC 2231 continuation segments is reassembled, as a client reassembles it.',
    file: 'js/mime.js',
    find: `  if (!segments.length) return null;\n  segments.sort((a, b) => a.index - b.index);`,
    replace: `  return null;`,
    mustKill: ['a filename split across RFC 2231 continuation segments is reassembled first'],
    // filename*0=/filename*1= matched neither filename= nor filename*=, so the
    // part came out unnamed and the executable check ran on "(unnamed)".
  },

  {
    id: 'magic-bytes-unread',
    promise: 'The declared type is checked against the part\'s first bytes, the one look taken inside.',
    file: 'js/body.js',
    find: `    const actual = magicOf(part.head);`,
    replace: `    const actual = null;`,
    mustKill: [
      'a declared PDF whose first bytes are a program is code, said plainly',
      'a declared PDF that begins like a PNG is a mismatch, stated as one',
    ],
  },

  {
    id: 'divergence-compares-the-hop',
    promise: 'The two versions are compared where the reader lands, not where the link hops.',
    file: 'js/body.js',
    find: `    const unwrapped = unwrapRedirect(parsed.href)?.destination;`,
    replace: `    const unwrapped = null;`,
    mustKill: ['a decodable redirect counts as where it lands, not where it hops'],
    // Compared at the hop, every tracked HTML link diverges from its plain
    // twin, and the card cries wolf on every newsletter with a tracker.
  },

  {
    id: 'markup-script-read-as-text',
    promise: 'Script and style content is never read as reader-visible text or links.',
    file: 'js/markup.js',
    find: `        const close = lower.indexOf(\`</\${tag.name}\`, i);
        i = close === -1 ? n : close;
        break;`,
    replace: `        break;`,
    mustKill: [
      'script and style content is not text and yields no links',
      'a script that never closes swallows the rest, like a browser',
    ],
    // Without the skip, a URL inside a <script> block counts as a link the
    // reader could click — a claim about text no mail client ever shows.
  },

  {
    id: 'mail-only-charset-unread',
    promise: 'A charset a mail client honours is decoded, whatever the browser\'s Encoding Standard says about it.',
    file: 'js/decode.js',
    find: `export function decodeMailCharset(bytes, label) {
  const family = mailOnlyCharset(label);`,
    replace: `export function decodeMailCharset() {
  return null;
}

function decodeMailCharsetDisabledByMutation(bytes, label) {
  const family = mailOnlyCharset(label);`,
    mustKill: [
      'a charset only mail uses reads as the message its 8-bit twin does',
      'a charset the browser refuses but mail uses is read before the checks run',
    ],
    // TextDecoder refuses UTF-7 and maps ISO-2022-KR and HZ onto "replacement"
    // — a browser decision this tool inherited into a place it never applies.
    // Without the shim a phishing anchor written `+ADw-a href…` draws no link
    // card, and a Korean attachment name ending .exe draws no warning.
  },

  {
    id: 'mail-only-charset-skips-verbatim',
    promise: 'A transfer encoding does not decide whether the declared charset is honoured.',
    file: 'js/mime.js',
    find: `  if (!mailOnlyCharset(charset) || hasNonAscii(slice)) return slice;`,
    replace: `  return slice;`,
    mustKill: ['a charset only mail uses reads as the message its 8-bit twin does'],
    // These charsets are 7-bit, so they need no transfer encoding — which is
    // the path that never reached a charset at all. `charset=utf-7` with
    // `Content-Transfer-Encoding: 7bit` is the pairing a sender would write.
  },

  {
    id: 'shifted-run-raises-control-bytes',
    promise: 'Decoding a shifted run never promotes a control byte into a C1 introducer.',
    file: 'js/decode.js',
    find: `    const graphic = byte > 0x20 && byte < 0x7f;
    out.push(shifted && graphic ? byte | 0x80 : byte);`,
    replace: `    out.push(shifted ? byte | 0x80 : byte);`,
    mustKill: ['a 7-bit charset never manufactures a control character out of a control byte'],
    // 0x1B with the high bit raised is 0x9B, the C1 spelling of CSI — the
    // introducer js/control.js exists because of. Measured: `SO ESC [ 2 J SI`
    // grows a U+009B out of bytes that carried none, and the tool would then be
    // reporting its own decoder's output as the sender's intent.
  },

  // ------------------------------------------------- what the prose may claim
  //
  // Every mutation above breaks behaviour. This one breaks a sentence, because
  // the failure it guards against is a sentence.
  //
  // The surfaces describe at length what this tool does not do — nothing
  // fetched, nothing rendered, nothing opened, nothing sent — and each of those
  // is true. Added up by a reader they become a protection that was never on
  // offer: the message was delivered, opened, laid out and stored by a mail
  // client before any of this ran. The one sentence that keeps the sum honest
  // is the one that states the order, and prose is precisely the part of a
  // repository nothing executes. So this executes it.
  {
    id: 'claims-protection',
    promise: 'No surface claims this tool stands between the reader and the message.',
    file: 'index.html',
    find: `No message becomes safe by being read twice.`,
    replace: `It protects you from the message.`,
    mustKill: [
      'index.html does not claim to protect the reader',
      'index.html says the reading happens after the fact',
    ],
  },

  {
    id: 'junk-verdict-rows-stay-neutral',
    promise: 'An explicit junk verdict colours its row, and the card\'s tone with it.',
    file: 'js/findings.js',
    find: `    if (value) items.push({ label, value, level: verdict?.test(value) ? 'bad' : null });`,
    replace: `    if (value) items.push({ label, value, level: null });`,
    mustKill: ['an explicit junk verdict raises the card, red rows included'],
    // Four headers on real iCloud junk said "junk" outright and the card
    // rendered five neutral dots. The tone reads the rows, so rows that never
    // colour kept the one card about the verdict permanently neutral.
  },

  {
    id: 'suspected-spam-reads-yes-only',
    promise: 'X-Suspected-Spam counts in the words iCloud writes, not only in ours.',
    file: 'js/findings.js',
    find: `  ['x-suspected-spam', 'Suspected spam', /^(?:yes|true)\\b/i],`,
    replace: `  ['x-suspected-spam', 'Suspected spam', /^yes\\b/i],`,
    mustKill: ['iCloud writes true rather than yes into X-Suspected-Spam'],
    // The old test was written for the value we expected, not the value the
    // provider sends: iCloud writes `true`, and `^yes` read that as nothing.
  },

  {
    id: 'junk-headline-reads-all-clear',
    promise: 'A junk-filed all-pass is titled as one, not as a plain all-clear.',
    file: 'js/findings.js',
    find: `      ? (wasFiledAsSpam(headers) ? PASSED_BUT_JUNK_TITLE : ALL_CLEAR_TITLE)`,
    replace: `      ? ALL_CLEAR_TITLE`,
    mustKill: ['a junk filing takes over the all-clear headline'],
    // The lede carried the junk clause; the headline — the sentence a glance
    // actually reads — still announced a plain all-clear over a message the
    // provider had filed as junk.
  },

  {
    id: 'alert-judgement-stays-a-footnote',
    promise: 'A judgement carrying a verdict leads the report; only a verdict-free one is a footnote.',
    file: 'js/findings.js',
    find: `    const at = findings.findIndex((f) => f.id === 'completeness') + 1;
    if (judgement.tone === 'alert') findings.splice(at, 0, judgement);
    else findings.push(judgement);`,
    replace: `    findings.push(judgement);`,
    mustKill: ['an alert judgement leads the report instead of footnoting it'],
    // With the card at the bottom, a junk-filed message read top-down as
    // passes and routes first and only ended on the ruling that had already
    // decided its folder.
  },

  {
    id: 'prose-paste-read-as-header',
    promise: 'A paste in which no line was written as a field is read as the message text it is.',
    file: 'js/mime.js',
    find: `  if (!looksLikeHeaderBlock(headerText) && text.trim()
    && (MARKUP_RE.test(text) || !carriesAnyLabelledField(headerText))) {`,
    replace: `  if (!looksLikeHeaderBlock(headerText) && MARKUP_RE.test(text)) {`,
    mustKill: ['prose with no labelled field is a body, not a mangled header'],
    // With markup as the only body evidence, "Sehr geehrter Kunde," parsed as
    // one unlabelled header fragment and the completeness card told the
    // reader their message text looked like part of a header.
  },

  {
    id: 'body-only-notice-names-a-phone-path',
    promise: 'The body-only notice tells a phone reader how to get at the raw message too, not only a desktop reader.',
    file: 'js/body.js',
    find: `      {
        label: 'iPhone Mail',
        value: 'No raw view: drag the message onto a minimised compose window — it attaches as an .eml, saved from there to Files. On iPad, drag it into Files directly in Split View.',
      },`,
    replace: '',
    mustKill: ['the notice tells a phone reader where the raw message hides'],
    // Every desktop menu path above assumes a desktop app. None of the four
    // mail apps most readers carry in a pocket expose a raw view there, and a
    // notice that only ever named the desktop path left a phone reader with
    // instructions for a program they were not looking at.
  },

  {
    id: 'paste-needs-a-second-click',
    promise: 'Pasting a message reads it — the button is for text that was edited.',
    file: 'js/app.js',
    find: `input.addEventListener('paste', () => {`,
    replace: `input.addEventListener('paste-disabled-by-mutation', () => {`,
    mustKill: ['a paste reads the message without a second click'],
    // A paste is the whole gesture on this page. Asking for a click afterwards
    // is asking the reader to confirm what they just did — and on a phone the
    // button is below the fold of the field they pasted into.
  },

  {
    id: 'report-left-below-the-fold',
    promise: 'A finished report is brought into view and takes focus with it.',
    file: 'js/app.js',
    find: `  overview.scrollIntoView({ block: 'start' });
  overview.focus();`,
    replace: `  void overview;`,
    mustKill: ['a finished report is brought into view rather than left below the fold'],
    // Without it a phone reader taps Read it, the page silently grows eleven
    // cards below the fold, the viewport has not moved and focus is on the
    // body — indistinguishable, from where they are standing, from nothing
    // having happened.
  },

  {
    id: 'jump-leaves-the-card-closed',
    promise: 'A jump opens the card it points at before scrolling to it.',
    file: 'js/app.js',
    find: `      if (collapsible) card.open = true;`,
    replace: `      // opening the target removed by mutation`,
    mustKill: ['a jump opens a collapsed card, scrolls to it and puts focus in it'],
    // Scrolling a collapsed card into view lands the reader on a closed box
    // with the title they just tapped on it, and leaves them to guess that the
    // finding needs a second tap.
  },

  {
    id: 'alert-cards-collapse-too',
    promise: 'An alert card is never collapsed; only notes and neutral cards fold.',
    file: 'js/app.js',
    find: `  const collapsible = finding.tone !== 'alert';`,
    replace: `  const collapsible = true;`,
    mustKill: ['an alert card is never one of the foldable ones'],
    // Folding by width alone reads as tidiness and costs the one thing the
    // reader came for: on a phone the alert would arrive shut, behind a tap,
    // among ten notes that look exactly like it.
  },

  {
    id: 'file-read-uncapped',
    promise: 'A file larger than 32 MB is refused with a sentence, not read.',
    file: 'js/app.js',
    find: `  if (file.size > MAX_FILE_BYTES) {`,
    replace: `  if (false && file.size > MAX_FILE_BYTES) {`,
    mustKill: ['a file too large to be a message is refused rather than read'],
    // The same ceiling the CLI puts on the clipboard. Past it `file.text()`
    // hands the tab a string it cannot hold, and the page stops answering with
    // no message on screen saying why.
  },

  {
    id: 'file-decoded-by-the-browser',
    promise: 'A message file is decoded by this tool, byte for byte, never by the browser\'s UTF-8 default.',
    file: 'js/app.js',
    find: `  input.value = textFromMessageBytes(new Uint8Array(await file.arrayBuffer()));`,
    replace: `  input.value = new TextDecoder().decode(new Uint8Array(await file.arrayBuffer()));`,
    mustKill: ['a file in a legacy charset is read as the sender wrote it, not as U+FFFD'],
    // Found in review on the day the file button shipped: `file.text()` wrote
    // U+FFFD over every byte of a latin-1 8bit body before js/mime.js saw one,
    // and the page's own invariant — no invented U+FFFD on screen — was broken
    // by the feature that had just been added.
  },

  {
    id: 'cli-file-decoded-as-utf8',
    promise: 'The terminal build reads a message file through the same decoder as the page.',
    file: 'bin/kuvertii.js',
    find: `    return (await report(textFromMessageBytes(bytes), renderer, process.stdout, { headersOnly })) ? 0 : 1;`,
    replace: `    return (await report(bytes.toString('utf8'), renderer, process.stdout, { headersOnly })) ? 0 : 1;`,
    mustKill: ['a file in a legacy charset reaches the terminal as the sender wrote it'],
    // The terminal had carried this seam since its first file: readFile with
    // 'utf8' is the obvious call, and it was the wrong one for the same reason.
  },

  {
    id: 'cli-pipe-decoded-as-utf8',
    promise: 'A pipe into the terminal build is read through the same decoder as a file.',
    file: 'bin/kuvertii.js',
    find: `    process.stdin.on('end', () => resolve(textFromMessageBytes(Buffer.concat(chunks))));`,
    replace: `    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));`,
    mustKill: ['a pipe carrying a legacy charset is read the same way'],
    // Two entry points, one decoder. A fix that reached the file and not the
    // pipe would have left `cat mail.eml | kuvertii` with the bug it removed
    // from `kuvertii mail.eml`.
  },

  {
    id: 'legacy-charset-fallback-invents-fffd',
    promise: 'Where a message is not UTF-8, the fallback decode is total: no byte becomes U+FFFD.',
    file: 'js/decode.js',
    find: `    return fromWindows1252(bytes);`,
    replace: `    return new TextDecoder('utf-8').decode(bytes);`,
    mustKill: ['a message file in any 8-bit charset never puts U+FFFD on screen'],
    // The fallback is the whole point of the strict first pass: a decoder that
    // could still fail would have moved the replacement character one line
    // down rather than out of the tool.
  },

  {
    id: 'windows-1252-high-bytes-as-controls',
    promise: 'The bytes 0x80–0x9F read as windows-1252 punctuation on every runtime, never as C1 control bytes.',
    file: 'js/decode.js',
    find: `    units[i] = byte >= 0x80 && byte < 0xa0 ? WINDOWS_1252_HIGH[byte - 0x80] : byte;`,
    replace: `    units[i] = byte;`,
    mustKill: ['a UTF-8 message file decodes exactly, and a windows-1252 one keeps its euro'],
    // What Node 20's TextDecoder did, measured on CI: 0x80 as U+0080. A
    // Windows client's curly quotes would then read as control bytes, and the
    // controls card would accuse the sender of steering the reader's terminal.
  },

  {
    id: 'drop-guard-not-window-scoped',
    promise: 'A message file dropped anywhere on this page is read here, never opened by the browser.',
    file: 'js/app.js',
    find: `window.addEventListener('drop', (event) => {`,
    replace: `inputArea.addEventListener('drop', (event) => {`,
    mustKill: ['a file dropped anywhere on the page is read, not opened by the browser'],
    // What the page did until this was moved: `#results` is a sibling of the
    // input area, so once a report was on screen a drop onto it met no guard
    // and the browser navigated to the file — leaving the page and rendering
    // the message in the tab.
  },

  {
    id: 'dragover-guard-not-window-scoped',
    promise: 'A message file dropped anywhere on this page is read here, never opened by the browser.',
    file: 'js/app.js',
    find: `window.addEventListener('dragover', (event) => {`,
    replace: `inputArea.addEventListener('dragover', (event) => {`,
    mustKill: ['a file dropped anywhere on the page is read, not opened by the browser'],
    // Both halves have to be window-wide: a drop guard without a dragover guard
    // never fires, because the drop target was never marked as one.
  },

  {
    id: 'drop-guard-swallows-text-drags',
    promise: 'Dragging selected text inside the field stays the browser\'s gesture; only files are intercepted.',
    file: 'js/app.js',
    find: `const carriesFiles = (event) => Boolean(event.dataTransfer?.types?.includes('Files'));`,
    replace: `const carriesFiles = () => true;`,
    mustKill: ['a drag carrying no file is left to the browser'],
    // The cost of moving the guards to `window`: an ungated preventDefault
    // there also eats moving a selection inside the textarea, which carries no
    // file and is none of this page's business.
  },

  {
    id: 'drag-frame-clears-at-every-boundary',
    promise: 'While a file is over the page, the frame keeps saying where it will land.',
    file: 'js/app.js',
    find: `  if (dragsInside > 0) return;\n`,
    replace: '',
    mustKill: ['a drag across the page keeps saying where the file will land'],
    // dragenter and dragleave nest rather than alternate, and both bubble to
    // window. Uncounted, the frame is cleared at every element boundary the
    // pointer crosses.
  },

  {
    id: 'file-read-rejection-unhandled',
    promise: 'A file this page cannot read is said to be unread, not passed over in silence.',
    file: 'js/app.js',
    find: `    return;
  }
  input.value = text;`,
    replace: `    throw error;
  }
  input.value = text;`,
    mustKill: ['a file that will not be read is reported as unread, by either route'],
    // Both call sites invoke this as a bare statement, so a rethrow is an
    // unhandled rejection: nothing changes on screen and the previous report
    // stays up as though it were about this file.
  },
];
