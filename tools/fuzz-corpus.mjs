#!/usr/bin/env node
// Generate whole messages, push them through the pipeline AS BYTES, and check
// the standing invariants on both screens a reader can be looking at.
//
//   node tools/fuzz-corpus.mjs                       # 200 messages from seed 1
//   node tools/fuzz-corpus.mjs --seed 7 --count 2000
//   node tools/fuzz-corpus.mjs --seed 7 --only 143   # that one message again
//
// Why bytes. Since the file-open feature the first thing that touches a message
// is not the parser but a decoder: `textFromMessageBytes` reads the bytes
// strictly as UTF-8 and falls back to windows-1252 whole. tools/corpus-audit.mjs
// reads its files with `readFileSync(path, 'utf8')`, so that seam has never been
// under any audit at all — and neither has the page, which corpus-audit cannot
// drive. This runs the chain the file picker and the drop handler run:
//
//   bytes → textFromMessageBytes → splitMessage → readHeaders → parseParts
//         → analyse + analyseBody → the terminal renderer AND the page
//
// Every message comes from an LCG seeded on the command line, never
// Math.random, so a break is reproducible from (seed, index) alone and the
// report can name those two numbers instead of carrying the message.
//
// Output discipline is tools/corpus-audit.mjs's: counts, finding ids, invariant
// names, codepoints — never a generated address, host or token. The vocabulary
// here is synthetic, but a tool that prints its input teaches the habit of
// running it on input that is not.

import { analyseBody } from '../js/body.js';
import { textFromMessageBytes } from '../js/decode.js';
import { analyse } from '../js/findings.js';
import { parseParts, splitMessage } from '../js/mime.js';
import { createRenderer } from '../js/terminal.js';
import { MAX_HEADER_BYTES, readHeaders } from '../js/unfold.js';
import { loadApp, renderedText, stubFile } from '../test/dom-stub.js';
import { checkFindings, checkScreen, stripAnsi, withBridges } from './report-invariants.mjs';

// ----------------------------------------------------------------- the source

/** The labeller's generator from test/snapshot.test.js, one stream per run. */
function rng(seed = 1) {
  let state = (seed >>> 0) || 1;
  const next = () => (state = (state * 1103515245 + 12345) % 2147483648) / 2147483648;
  return {
    int: (n) => Math.floor(next() * n),
    pick: (list) => list[Math.floor(next() * list.length)],
    chance: (p) => next() < p,
    word: (n) => Array.from({ length: n }, () => 'abcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(next() * 36)]).join(''),
  };
}

// Text that is not ASCII, so the charset choice below has something to decide
// about: Latin, Greek, CJK, and an emoji outside the BMP.
const HIGH_TEXT = ['Bestätigung nötig', 'Grüße von Müller', 'naïve café', 'Ελληνικά', '日本語の件名', 'ok \u{1F389} done'];

// What neutralise exists to remove, and one the sender may legitimately have
// written: an RTL override, a CSI introducer, a zero-width space, and a
// replacement character the message carries itself.
const ODDITIES = ['\u202E', '\u001B[31m', '\u200B', '\uFFFD'];

/** The header shapes real mail carries, hostile ones included. */
function headerLines(r) {
  const host = `${r.word(6)}.example`;
  const lines = [
    `From: ${r.chance(0.5) ? `"${r.pick(HIGH_TEXT)}" ` : ''}<${r.word(8)}@${host}>`,
    `Subject: ${r.chance(0.5) ? r.pick(HIGH_TEXT) : r.word(20)}`,
    `Date: Mon, ${1 + r.int(28)} Jan 2026 00:00:00 +0000`,
    `Message-ID: <${r.word(24)}@${host}>`,
  ];

  const optional = [
    () => `To: ${r.word(7)}@${r.word(5)}.example`,
    () => `Delivered-To: ${r.word(7)}@${r.word(5)}.example`,
    () => `Return-Path: <bounce-${r.word(6)}=${r.word(5)}.example@${host}>`,
    // The percent branch, both sides of the gate it just got: `41` and `7E` are
    // unreserved and encode nothing, `40`, `2540` and `20` are real.
    () => `X-Track-ID: ${r.word(4)}%${r.pick(['41', '40', '2540', '20', '7E', 'C3'])}${r.word(6)}@${host}`,
    () => `X-Mailer-Info: id:${Buffer.from(`${r.word(6)}@${r.word(5)}.example`).toString('base64')}.${r.word(9)}`,
    () => `X-Campaign: =?utf-8?B?${Buffer.from(r.pick(HIGH_TEXT)).toString('base64')}?=`,
    () => 'X-Note: =?iso-8859-1?Q?Best=E4tigung_n=F6tig?=',
    // A fold in the middle of a token, which once hid the reader's own address.
    () => `X-Long: ${r.word(30)}\n ${r.word(30)}`,
    () => 'Authentication-Results: mx.example; '
      + `spf=${r.pick(['pass', 'fail', 'softfail', 'none', 'constructor'])};`
      + ` dkim=${r.pick(['pass', 'fail', 'none'])}; dmarc=${r.pick(['pass', 'fail', 'bestguesspass'])}`,
    () => `Received: from ${r.word(5)}.example (${r.word(5)}.example [${r.int(224)}.${r.int(256)}.${r.int(256)}.${r.int(256)}])`
      + ` by mx.example${r.chance(0.2) ? ' (a comment that never closes' : ''}; Mon, 1 Jan 2026 00:00:00 +0000`,
    () => `List-Unsubscribe: <https://${r.word(8)}.example/u/${r.word(24)}>`,
    () => `X-Suspected-Spam: ${r.pick(['true', 'yes', 'no', 'false'])}`,
    () => `X-Odd: ${r.word(4)}${r.pick(ODDITIES)}${r.word(4)}`,
    () => 'X-Homoglyph: evil。com evil．com',
    () => `X-Blob: ${r.word(5)}`.padEnd(r.chance(0.05) ? 4000 : 20, 'x'),
  ];
  for (let i = r.int(8); i > 0; i -= 1) lines.push(r.pick(optional)());
  return lines;
}

/** A body, sometimes multipart, sometimes with an attachment worth a filename. */
function bodyLines(r, headers) {
  const text = `${r.pick(HIGH_TEXT)} ${r.word(30)}`;

  if (r.chance(0.45)) {
    headers.push('Content-Type: text/plain; charset=utf-8');
    if (!r.chance(0.4)) return [text];
    headers.push('Content-Transfer-Encoding: quoted-printable');
    return [text.replace(
      /[^\x20-\x7e]/g,
      (c) => [...Buffer.from(c)].map((b) => `=${b.toString(16).toUpperCase().padStart(2, '0')}`).join(''),
    )];
  }

  const boundary = `b${r.word(10)}`;
  headers.push(`Content-Type: multipart/${r.pick(['alternative', 'mixed', 'related'])}; boundary="${boundary}"`);

  // Three ways to write a filename, two of which have hidden an extension from
  // the check that reads one: an encoded-word, and RFC 2231 §3 continuation.
  const filename = r.pick([
    `report.${r.pick(['pdf', 'exe', 'txt', 'docx'])}`,
    `=?utf-8?Q?Best=C3=A4tigung.${r.pick(['pdf', 'exe'])}?=`,
    null,
  ]);
  const attachment = filename === null
    ? ['Content-Type: application/octet-stream',
      `Content-Disposition: attachment; filename*0="repo"; filename*1="rt.${r.pick(['exe', 'pdf'])}"`]
    : ['Content-Type: application/octet-stream',
      `Content-Disposition: attachment; filename="${filename}"`];

  return [
    `--${boundary}`, 'Content-Type: text/plain; charset=utf-8', '', text, '',
    `--${boundary}`, 'Content-Type: text/html; charset=utf-8', '',
    `<p>${text}</p><a href="https://${r.word(8)}.example/c/${r.word(20)}">click</a><<<>>>`, '',
    ...(r.chance(0.5) ? [`--${boundary}`, ...attachment, '', Buffer.from(r.word(40)).toString('base64'), ''] : []),
    `--${boundary}--`, '',
  ];
}

/** One message, as the bytes a file would hold. */
function message(r) {
  const headers = headerLines(r);
  const body = bodyLines(r, headers);
  const text = `${headers.join('\n')}\n\n${body.join('\n')}\n`;
  const crlf = r.chance(0.4);
  const withEol = crlf ? text.replace(/\n/g, '\r\n') : text;

  const charset = r.pick(['utf-8', 'utf-8', 'latin-1', 'windows-1252', 'raw-8bit']);
  let bytes;
  if (charset === 'utf-8') {
    bytes = new TextEncoder().encode(withEol);
  } else if (charset === 'raw-8bit') {
    // Bytes no charset explains: what a mailbox file holds when two systems
    // disagreed. The fallback decoder promises to be total over exactly these.
    bytes = new TextEncoder().encode(withEol);
    for (let i = r.int(20); i > 0; i -= 1) bytes[r.int(bytes.length)] = 0x80 + r.int(0x80);
  } else {
    // One byte per character, high ones included: latin-1 and windows-1252 both
    // live in 0x00–0xFF and disagree only over 0x80–0x9F.
    bytes = Uint8Array.from([...withEol].map((c) => (c.codePointAt(0) > 0xff ? 0x3f : c.codePointAt(0))));
  }

  if (r.chance(0.15)) bytes = Uint8Array.from([0xef, 0xbb, 0xbf, ...bytes]);
  // A file that ends where a multi-byte sequence had not: a truncated download,
  // a mailbox cut at a block boundary. Strict UTF-8 refuses it, so the whole
  // message takes the fallback — a branch nothing else here reaches on purpose.
  if (r.chance(0.1) && bytes.length > 40) bytes = bytes.slice(0, bytes.length - 1 - r.int(3));

  return { bytes, charset, crlf };
}

// ------------------------------------------------------------------ the check

/** The chain the CLI runs, from decoded text to findings. */
async function pipeline(text) {
  const { headerText, bodyText, bodyOnly } = splitMessage(text);
  const block = headerText.length > MAX_HEADER_BYTES ? headerText.slice(0, MAX_HEADER_BYTES) : headerText;
  const { headers } = readHeaders(block);
  const { parts } = parseParts(headers, bodyText);
  return withBridges([...analyse(headers), ...analyseBody(parts, { headers, bodyOnly })]);
}

async function auditOne(bytes) {
  const report = { breaks: [], ids: [], fellBack: false, screens: 0 };

  try {
    new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    report.fellBack = true;
  }

  let text;
  try {
    text = textFromMessageBytes(bytes);
  } catch (e) {
    report.breaks.push(`textFromMessageBytes threw (${e.name}) — the fallback is meant to be total`);
    return report;
  }

  let findings;
  try {
    findings = await pipeline(text);
  } catch (e) {
    report.breaks.push(`pipeline threw — it must degrade, not throw (${e.name})`);
    return report;
  }
  report.ids = [...new Set(findings.map((f) => f.id))];
  report.breaks.push(...checkFindings(findings));

  const screens = [];
  for (const colour of [false, true]) {
    try {
      screens.push({
        where: `terminal colour=${colour}`,
        text: stripAnsi(createRenderer({ colour, width: 80 }).render(findings)),
      });
    } catch (e) {
      report.breaks.push(`terminal renderer threw colour=${colour} (${e.name})`);
    }
  }

  // The page, driven the way the file picker drives it: the same bytes into the
  // same handler, so the decode, the render and the neutralise on this screen
  // are the page's own rather than a re-run of the terminal's.
  try {
    const nodes = await loadApp();
    nodes['#file-input'].files = [stubFile('', undefined, bytes)];
    for (const handler of nodes['#file-input'].handlers.change ?? []) handler({ target: nodes['#file-input'] });
    await new Promise((resolve) => { setTimeout(resolve, 0); });
    screens.push({
      where: 'page',
      text: `${renderedText(nodes['#results'])}\n${nodes['#status'].textContent}`,
    });
  } catch (e) {
    report.breaks.push(`the page threw (${e.name}: ${String(e.message).slice(0, 60)})`);
  }

  report.screens = screens.length;
  for (const screen of screens) report.breaks.push(...checkScreen(screen.text, { raw: text, where: screen.where }));
  return report;
}

// -------------------------------------------------------------------- the run

/**
 * Can this probe still say no?
 *
 * A check that cannot fail passes every corpus it is pointed at, and the clean
 * bill it hands back means only that it is blind. So each invariant is shown
 * something that must trip it — and one thing that must not — before a single
 * message is generated, and the run refuses to start if any of them is asleep.
 */
function selfTest() {
  const failures = [];
  const fires = (breaks, name) => breaks.some((b) => b.startsWith(name));

  if (!fires(checkScreen('Subject: he\u202Ello'), 'CONTROL_BYTE')) failures.push('a steering byte on screen goes unnoticed');
  if (!fires(checkScreen('go to https://evil.example/x'), 'LIVE_URL')) failures.push('a clickable URL goes unnoticed');
  if (!fires(checkScreen('it was [object Object]'), 'PLACEHOLDER')) failures.push('machinery on screen goes unnoticed');
  if (!fires(checkScreen('\uFFFD', { raw: 'clean' }), 'MOJIBAKE')) failures.push('an invented U+FFFD goes unnoticed');
  if (fires(checkScreen('\uFFFD', { raw: 'the sender wrote \uFFFD' }), 'MOJIBAKE')) failures.push("MOJIBAKE fires on the sender's own U+FFFD");

  const card = (id) => ({ id, tone: 'info', title: 't', items: [] });
  if (!fires(checkFindings([card('auth'), card('auth')]), 'DUPLICATE')) failures.push('two cards sharing an id go unnoticed');
  if (checkFindings([card('auth'), card('route')]).length) failures.push('a consistent report is reported as broken');
  return failures;
}

function parseArgs(argv) {
  const opts = { seed: 1, count: 200, only: null };
  for (let i = 0; i < argv.length; i += 1) {
    const [key, inline] = argv[i].split('=');
    const value = inline ?? argv[i + 1];
    const step = () => { if (inline === undefined) i += 1; };
    if (key === '--seed') { opts.seed = Number(value); step(); } else if (key === '--count') { opts.count = Number(value); step(); } else if (key === '--only') { opts.only = Number(value); step(); } else {
      process.stderr.write(`unknown argument ${argv[i]}\n`);
      process.exitCode = 1;
    }
  }
  return opts;
}

/**
 * The messages a seed produces, in order.
 *
 * One stream, so index `n` is the same message on every run of that seed —
 * which is what makes `--only` mean anything, and what lets a failing run be
 * named by two integers instead of by the message that broke it.
 */
export function* corpus(seed, count) {
  const r = rng(seed);
  for (let i = 0; i < count; i += 1) yield { index: i, ...message(r) };
}

export { auditOne, selfTest };

async function main() {
  const { seed, count, only } = parseArgs(process.argv.slice(2));

  const blind = selfTest();
  if (blind.length) {
    process.stderr.write(`the invariants cannot fail, so this run would prove nothing:\n${blind.map((b) => `  - ${b}\n`).join('')}`);
    process.exitCode = 1;
    return;
  }

  process.stdout.write(`fuzz — seed ${seed}, ${count} message(s), invariants self-tested (content never printed)\n\n`);

  const idTally = new Map();
  const charsetTally = new Map();
  let fellBack = 0;
  let clean = 0;
  let screens = 0;
  const broken = [];

  for (const { index, bytes, charset } of corpus(seed, count)) {
    if (only !== null && index !== only) continue;
    const r = await auditOne(bytes);
    charsetTally.set(charset, (charsetTally.get(charset) ?? 0) + 1);
    for (const id of r.ids) idTally.set(id, (idTally.get(id) ?? 0) + 1);
    if (r.fellBack) fellBack += 1;
    screens += r.screens;
    if (r.breaks.length === 0) { clean += 1; continue; }
    broken.push(index);
    process.stdout.write(`#${String(index).padStart(5)} BREAK  ${bytes.length}B  [${charset}]\n`);
    for (const b of r.breaks) process.stdout.write(`        ↳ ${b}\n`);
  }

  const ran = clean + broken.length;
  process.stdout.write(`\ncharsets: ${[...charsetTally].map(([c, n]) => `${c}:${n}`).join('  ')}\n`);
  // Not decoration. A run where this is zero never entered the fallback at all,
  // so whatever it proved, it proved nothing about the seam it exists to cover.
  process.stdout.write(`fell back to windows-1252: ${fellBack}/${ran} message(s)\n`);
  process.stdout.write(`screens checked: ${screens} (terminal x2 + the page, per message)\n`);
  process.stdout.write(`findings seen: ${[...idTally].sort((a, b) => b[1] - a[1]).map(([id, n]) => `${id}:${n}`).join('  ') || '(none)'}\n`);
  process.stdout.write(`invariants: ${clean}/${ran} clean, ${broken.length} with a break\n`);

  if (broken.length) {
    process.stdout.write(`\nreproduce: node tools/fuzz-corpus.mjs --seed ${seed} --count ${count} --only ${broken[0]}\n`);
    process.exitCode = 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) await main();
