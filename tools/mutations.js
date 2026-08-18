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
    id: 'exit-discards-buffer',
    promise: 'A report longer than a pipe buffer arrives whole.',
    file: 'bin/kuvertii.js',
    find: `  (code) => { process.exitCode = code ?? 0; },`,
    replace: `  (code) => process.exit(code ?? 0),`,
    mustKill: ['a report longer than a pipe buffer arrives whole'],
  },

  {
    id: 'chunk-is-one-key',
    promise: 'Two keys arriving in one read are two keys.',
    file: 'js/keys.js',
    find: `  return [...String(chunk ?? '').replace(PASTE, '')];`,
    replace: `  return [String(chunk ?? '')];`,
    mustKill: [
      'two keys arriving together are two keys',
      'pasted text is data, not a burst of keypresses',
    ],
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
    mustKill: ['the CLI reaches for nothing that could open a link'],
    // test/terminal.test.js:164 reads a hand-written list of five files.
    // js/senders.js is one of the eight modules the CLI loads that are not on
    // it, and the CLI has no CSP underneath to catch what the test misses.
    expectedToSurvive: true,
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
    mustKill: ['untrusted header text never reaches a markup sink'],
    // The SINKS regex in test/wiring.test.js:143 bans setAttribute but not
    // property assignment, so `link.href = …` is invisible to it. In the
    // terminal this rule has a real gate (defang); on the page it has none.
    expectedToSurvive: true,
  },

  {
    id: 'app-neutralise-removed',
    promise: 'The page renders header text inert, exactly as the terminal does.',
    file: 'js/app.js',
    find: `if (text !== undefined && text !== null) node.textContent = neutralise(text);`,
    replace: `if (text !== undefined && text !== null) node.textContent = String(text);`,
    mustKill: ['untrusted header text never reaches a markup sink'],
    // Every escape-stripping test in the suite drives the terminal renderer.
    // The browser's single call site can be deleted and nothing notices.
    expectedToSurvive: true,
  },

  {
    id: 'csp-scheme-source',
    promise: 'The page cannot talk to any origin but its own.',
    file: 'index.html',
    find: `connect-src 'self';`,
    replace: `connect-src 'self' https:;`,
    mustKill: ['the CSP allows the page to work and nothing beyond it'],
    // A CSP scheme-source has no slashes, so it matches neither the wildcard
    // check nor the `https://host` check in test/wiring.test.js:113. The page
    // could fetch the pasted address to anywhere on the web with CI green.
    expectedToSurvive: true,
  },

  {
    id: 'serve-public-bind',
    promise: 'The dev server listens on loopback only.',
    file: 'tools/serve.mjs',
    find: `createDevServer().listen(PORT, '127.0.0.1', () => {`,
    replace: `createDevServer().listen(PORT, '0.0.0.0', () => {`,
    mustKill: ['nothing outside the site is reachable, however it is spelled'],
    // test/serve.test.js exercises the real `resolve`, which is the right
    // instinct, but the bind address is never asserted at all — the one part of
    // that file that decides who can reach it.
    expectedToSurvive: true,
  },
];
