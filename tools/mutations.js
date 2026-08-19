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
    && compauth !== 'fail';`,
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
    mustKill: ['the page assigns only the four node properties it has decided about'],
    // Was a known gap: the sink regex banned the names somebody thought of and
    // not property assignment, so `link.href = …` was invisible to it. The
    // check now runs the other way — four allowed properties, anything else
    // fails — because the list of ways to reach the DOM is the platform's and
    // grows, while the list this page needs is ours and is four items long.
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
    find: `    const below = firstHop !== -1 && headers.indexOf(field) > firstHop;`,
    replace: `    const below = false;`,
    mustKill: ['a verdict written below a Received is reported as not the last hop\'s'],
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
];
