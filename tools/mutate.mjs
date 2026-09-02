#!/usr/bin/env node
// Break each promise on purpose, and check that the suite notices.
//
//   node tools/mutate.mjs            every mutation in the registry
//   node tools/mutate.mjs csp        only those whose id contains "csp"
//
// The registry lives in tools/mutations.js and says what each mutation is for.
// This file is only the machine: copy the tree, apply one change, run the
// tests, and report whether anything went red.
//
// Why a copy rather than an edit-and-revert in place: a test run that crashes,
// or a machine that loses power halfway, must not be able to leave a sabotaged
// working tree behind. The copy is built from `git ls-files --cached --others
// --exclude-standard`, which is the working tree minus everything .gitignore
// already excludes — so data/ and corpus/ never enter a mutation run, and every
// run starts from the same shape whether or not the blocklist was built today.

import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { MUTATIONS } from './mutations.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const BOLD = '\x1b[1m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const DIM = '\x1b[2m';
const OFF = '\x1b[0m';
const colour = process.stdout.isTTY && !process.env.NO_COLOR;

/**
 * Is this mutation expected to survive here?
 *
 * `true` means a gap we have measured and not closed. A list of platforms means
 * the promise cannot be broken on those systems, so no test there can go red —
 * a different thing entirely, and reporting the two alike would let a real gate
 * read as a hole on the platform where it works.
 */
const survivalExpected = (mutation) => mutation.expectedToSurvive === true
  || (Array.isArray(mutation.expectedToSurvive) && mutation.expectedToSurvive.includes(process.platform));
const paint = (code, text) => (colour ? `${code}${text}${OFF}` : text);

/** The working tree as git sees it: tracked plus untracked, minus ignored. */
function trackedFiles() {
  const out = execFileSync(
    'git',
    ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
    { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
  );
  return out.split('\0').filter(Boolean);
}

function copyTree(files, destination) {
  for (const file of files) {
    const target = join(destination, file);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(join(ROOT, file), target);
  }
}

/**
 * Apply one mutation, or refuse.
 *
 * An anchor that no longer matches is the failure mode this whole harness
 * exists to prevent one level up: the mutation would be applied to nothing, the
 * suite would stay green for a reason that has nothing to do with the promise,
 * and the report would be a lie in whichever direction happens to be worse.
 * Ambiguity is refused for the same reason — two matches means we do not know
 * which one we broke.
 */
function applyMutation(root, mutation) {
  const path = join(root, mutation.file);
  const source = readFileSync(path, 'utf8');
  const occurrences = source.split(mutation.find).length - 1;

  if (occurrences === 0) {
    throw new Error(
      `${mutation.id}: its anchor is no longer in ${mutation.file}. ` +
      'The code moved and the registry did not. Fix the anchor before trusting any result here.',
    );
  }
  if (occurrences > 1) {
    throw new Error(
      `${mutation.id}: its anchor occurs ${occurrences} times in ${mutation.file}, so it does not name one place.`,
    );
  }

  writeFileSync(path, source.replace(mutation.find, mutation.replace));
}

/** Every test name the run reported as failing, from the TAP stream. */
/**
 * Run the suite in `root`, with `applied` naming the mutation in force.
 *
 * The name is passed on to the suite because one test in it — the registry's
 * own anchor check — reads the code the registry points at. Under a mutation
 * that code has been rewritten on purpose, so without being told which entry is
 * in force that test goes red for every mutation, and a mutation nothing
 * catches then reports KILLED anyway. That is not a noisy gate, it is a gate
 * that has quietly stopped answering the only question the sweep asks.
 */
function runSuite(root, applied = '') {
  let stdout = '';
  let status = 0;
  try {
    stdout = execFileSync(process.execPath, ['--test', '--test-reporter=tap'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, KUVERTII_APPLIED_MUTATION: applied },
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
      // node:test has no per-test timeout by default, so the natural mutation
      // for any loop or regex — one that stops terminating — hung this harness
      // with no output and no verdict. A kill is still a kill, but it has to
      // arrive.
      timeout: 5 * 60 * 1000,
    });
  } catch (error) {
    // A red suite exits non-zero, which execFileSync reports as a throw. That
    // is the outcome we are usually hoping for, so it is not an error here.
    stdout = error.stdout ?? '';
    status = error.status ?? 1;
  }

  const failed = [...stdout.matchAll(/^\s*not ok \d+ - (.+)$/gm)].map(([, name]) => name.trim());
  // A timeout or a crashed runner exits non-zero without failing a test, which
  // would otherwise read exactly like a mutation being caught.
  const ranToCompletion = /^1\.\.\d+$/m.test(stdout) || failed.length > 0;
  return { status, failed, stdout, ranToCompletion };
}

/**
 * The verdict on one mutation run — three outcomes, not two.
 *
 * A run that reached a verdict is 'killed' when the suite went red and
 * 'survived' when it stayed green. A run that never reached one — a timeout, a
 * crash, or a child that failed to spawn under the sustained load of a long
 * sweep — is 'inconclusive': the suite could not be asked, so the promise is
 * neither proven guarded nor proven unguarded.
 *
 * Folding that third case into 'survived' is how a transient hiccup once
 * printed a real gate as a hole. On 2026-08-20 `zero-length-reads-as-partial`
 * reported SURVIVED in one full run and KILLED in the next on a byte-identical
 * tree; the mutation was live and the suite would have caught it, but that one
 * run was cut off before it could — `status !== 0 && ranToCompletion` read the
 * abort (`ranToCompletion` false) as a survivor. A gate that scores an unasked
 * question as "unguarded" cannot be trusted to go red for the right reason.
 */
export function classifyRun({ status, ranToCompletion }) {
  if (!ranToCompletion) return 'inconclusive';
  return status !== 0 ? 'killed' : 'survived';
}

/**
 * Run the suite until it reaches a verdict, or give up after a few tries.
 *
 * The causes of an inconclusive run are transient — a slow or failed child
 * spawn late in a 74-mutation sweep, a timeout under momentary load — so a
 * retry usually reaches the verdict the first attempt was denied. A mutation
 * that genuinely hangs costs three timeouts and still ends inconclusive, which
 * is the honest answer: it never turns into a false KILLED or a false SURVIVED.
 */
function runSuiteToVerdict(root, applied, attempts = 3) {
  let last;
  for (let i = 0; i < attempts; i++) {
    last = runSuite(root, applied);
    if (last.ranToCompletion) break;
  }
  return last;
}

function main() {
  const filter = process.argv[2];
  const selected = filter ? MUTATIONS.filter((m) => m.id.includes(filter)) : MUTATIONS;

  if (!selected.length) {
    process.stderr.write(`No mutation matches "${filter}".\n`);
    process.exitCode = 1;
    return;
  }

  const files = trackedFiles();

  // Baseline first. Every verdict below is "the suite went red because of this
  // mutation", and that sentence is only true if the suite was green without
  // it. An untracked scratch test, a half-finished edit, a machine where one
  // test cannot run — any of them would otherwise make all 23 mutations report
  // KILLED and the summary print a confident `unguarded: 0`.
  const baseline = mkdtempSync(join(tmpdir(), 'kuvertii-baseline-'));
  try {
    copyTree(files, baseline);
    const { status, failed } = runSuite(baseline);
    if (status !== 0) {
      process.stderr.write(
        `The suite is not green before any mutation is applied — ${failed.length} test(s) already failing:\n`
        + failed.slice(0, 5).map((name) => `  ${name}\n`).join('')
        + 'Every result below would say KILLED for that reason alone. Fix the tree first.\n',
      );
      process.exitCode = 1;
      return;
    }
  } finally {
    rmSync(baseline, { recursive: true, force: true });
  }
  process.stdout.write(`${paint(DIM, 'baseline: suite green before any mutation')}\n\n`);

  const results = [];

  process.stdout.write(`${paint(BOLD, `Mutating ${selected.length} promise${selected.length === 1 ? '' : 's'}`)} ${paint(DIM, `(${files.length} files per copy)`)}\n\n`);

  for (const mutation of selected) {
    const workspace = mkdtempSync(join(tmpdir(), 'kuvertii-mutate-'));
    try {
      copyTree(files, workspace);
      applyMutation(workspace, mutation);
      const run = runSuiteToVerdict(workspace, mutation.id);
      const { failed } = run;

      const outcome = classifyRun(run);
      const killed = outcome === 'killed';
      const inconclusive = outcome === 'inconclusive';
      const byIntendedTest = mutation.mustKill.filter(
        (name) => failed.some((f) => f.toLowerCase().includes(name.toLowerCase())),
      );

      results.push({ mutation, killed, inconclusive, failed, byIntendedTest });

      const expected = survivalExpected(mutation);
      const verdict = killed
        ? paint(GREEN, 'KILLED  ')
        : inconclusive
          ? paint(YELLOW, 'INCONCL ')
          : expected
            ? paint(YELLOW, 'SURVIVED')
            : paint(RED, 'SURVIVED');

      process.stdout.write(`${verdict} ${paint(BOLD, mutation.id)}\n`);
      process.stdout.write(`         ${mutation.promise}\n`);

      if (killed) {
        process.stdout.write(`         ${paint(DIM, `${failed.length} test${failed.length === 1 ? '' : 's'} went red`)}\n`);
        if (!byIntendedTest.length) {
          process.stdout.write(`         ${paint(YELLOW, 'but none of the tests named in mustKill — check the mutation is behavioural, not a syntax error')}\n`);
          // Which ones, not just "not those". Without this the message says a
          // stranger killed the mutation and refuses to name them, which on a
          // machine you cannot reach is the end of the investigation.
          for (const name of failed.slice(0, 5)) process.stdout.write(`         ${paint(DIM, `red: ${name}`)}\n`);
        }
      } else if (inconclusive) {
        process.stdout.write(`         ${paint(YELLOW, 'the suite never reached a verdict across three tries — a timeout or a failed spawn, not a survivor. Re-run before trusting the summary.')}\n`);
      } else if (expected) {
        process.stdout.write(`         ${paint(DIM, Array.isArray(mutation.expectedToSurvive)
          ? `not breakable on ${process.platform}, by design — see the registry`
          : 'known gap, recorded in the registry')}\n`);
      }
      process.stdout.write('\n');
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  }

  // Three ways to fail, and the third one matters as much as the first two: a
  // mutation flagged as a known gap that now dies means the gap was closed and
  // the registry still says otherwise. A registry that describes a repository
  // we no longer have is worth less than no registry.
  // A mutation that dies to tests nobody named usually broke syntax rather
  // than behaviour, which means the promise is still unguarded and the run just
  // looked green. The registry's own rule 2 said so and enforced nothing.
  const wrongTest = results.filter((r) => r.killed && !r.byIntendedTest.length);
  // Unguarded and known-gap are verdicts about a suite that answered: a promise
  // it did not break (survived) is unguarded unless the registry expected it.
  // An inconclusive run never asked the question, so it belongs in neither — it
  // is its own bucket, counted below and never folded into "unguarded".
  const survived = (r) => !r.killed && !r.inconclusive;
  const unguarded = results.filter((r) => survived(r) && !survivalExpected(r.mutation));
  // A mutation that dies where it was expected to survive is news, but only
  // when the expectation was unconditional. A platform list says "not here",
  // and dying on another platform is exactly what it predicts.
  const staleFlags = results.filter((r) => r.killed && r.mutation.expectedToSurvive === true);
  const knownGaps = results.filter((r) => survived(r) && survivalExpected(r.mutation));
  const inconclusive = results.filter((r) => r.inconclusive);

  process.stdout.write(`${paint(BOLD, 'Summary')}\n`);
  process.stdout.write(`  killed:      ${results.filter((r) => r.killed).length}\n`);
  process.stdout.write(`  known gaps:  ${knownGaps.length}${knownGaps.length ? `  (${knownGaps.map((r) => r.mutation.id).join(', ')})` : ''}\n`);
  process.stdout.write(`  unguarded:   ${unguarded.length}${unguarded.length ? `  (${unguarded.map((r) => r.mutation.id).join(', ')})` : ''}\n`);
  process.stdout.write(`  inconclusive:${inconclusive.length}${inconclusive.length ? `  (${inconclusive.map((r) => r.mutation.id).join(', ')})` : ''}\n`);
  process.stdout.write(`  wrong test:  ${wrongTest.length}${wrongTest.length ? `  (${wrongTest.map((r) => r.mutation.id).join(', ')})` : ''}\n`);

  if (inconclusive.length) {
    process.stdout.write(`\n${paint(YELLOW, 'These never reached a verdict — re-run; a persistent one is a hang to investigate, not a result:')}\n`);
    for (const { mutation } of inconclusive) process.stdout.write(`  ${mutation.id}\n`);
  }

  if (staleFlags.length) {
    process.stdout.write(`\n${paint(YELLOW, 'These are now guarded — drop expectedToSurvive from the registry:')}\n`);
    for (const { mutation } of staleFlags) process.stdout.write(`  ${mutation.id}\n`);
  }

  if (wrongTest.length) {
    process.stdout.write(`\n${paint(YELLOW, 'These died to tests other than the ones they name — check the mutation is behavioural:')}\n`);
    for (const { mutation } of wrongTest) process.stdout.write(`  ${mutation.id}\n`);
  }

  if (unguarded.length || staleFlags.length || wrongTest.length || inconclusive.length) {
    process.exitCode = 1;
  }
}

// Run the sweep only when invoked as a script. Imported for its exported
// helpers (classifyRun) — by test/mutate.test.js — main() must stay quiet.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
