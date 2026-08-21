#!/usr/bin/env node
// Audit real messages against kuvertii's own analysis — WITHOUT ever printing
// their content. The whole point: real mail carries real addresses, real
// correspondents, real routing. This runs the same offline pipeline the CLI
// and the page run (splitMessage → parseParts → analyse + analyseBody → both
// renderers + the async bridges) over every message in a directory, checks the
// standing invariants, and emits ONLY non-sensitive signal.
//
//   node tools/corpus-audit.mjs [dir]     # default dir: samples/  (gitignored)
//
// What it prints, and nothing else:
//   - integers (counts, sizes rounded to KB, part/depth counts)
//   - MIME content-type tokens (text/html, application/pdf, …) — a type, never
//     its name= parameter
//   - finding ids that fired (body-links, auth, …) — fixed labels, not values
//   - invariant names and pass/fail booleans
//   - Unicode codepoints (U+202E) when a control byte is the finding
//
// It NEVER prints: an address, a domain, an IP, a Message-ID, a subject, body
// text, a tracking token, a filename, or any rendered card. Cards are rendered
// only to run the invariant regexes over them and are then discarded. The raw
// bytes go into this process and never come back out — which is the property
// that makes the output safe to read, and safe to paste anywhere.
//
// Real mail is never committed: keep it in samples/ (gitignored) and distil any
// finding into a SYNTHETIC test case, the standing corpus rule.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { analyseBody } from '../js/body.js';
import { hashedAddressRows } from '../js/emailhash.js';
import { analyse } from '../js/findings.js';
import { parseParts, splitMessage } from '../js/mime.js';
import { verdictRows } from '../js/snapshot.js';
import { createRenderer } from '../js/terminal.js';
import { MAX_HEADER_BYTES, readHeaders } from '../js/unfold.js';

// The phase-5 invariant set, checked against the VISIBLE text of each rendered
// card (this tool's own colour codes stripped first).
const CONTROL_BYTE = /(?![\t\n])[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}]/u;
const LIVE_URL = /(?:https?|ftps?):\/\/[^\s<>"'`)\]]/i; // scheme + a host char = linkifiable
const PLACEHOLDER = /\[object Object\]|native code|\bundefined\b|\bNaN\b|the first ∞|∞ bytes/;
const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');

/** Resolve the two async bridges the front ends resolve, so their rows are checked too. */
async function withBridges(findings) {
  for (const f of findings) {
    if (f.hashCheck) {
      try { f.items = [...f.items, ...await hashedAddressRows(f.hashCheck)]; } catch { /* checked as a fault below */ }
    }
    if (f.hostsToCheck?.length) {
      // The shape checkHosts returns with no snapshot on disk — the path that
      // renders the (hostile) hostnames into row labels.
      const rows = f.hostsToCheck.map((host) => ({ host, unavailable: true, why: 'audit: no snapshot' }));
      try { f.items = [...f.items, ...verdictRows(rows)]; } catch { /* ditto */ }
    }
  }
  return findings;
}

async function auditOne(raw) {
  const report = {
    kb: Math.round(raw.length / 1024),
    parts: 0, types: [], bodyOnly: false, findingIds: [], breaks: [],
  };
  let headerText; let bodyText; let bodyOnly;
  try {
    ({ headerText, bodyText, bodyOnly } = splitMessage(raw));
  } catch (e) { report.breaks.push(`splitMessage threw (${e.name})`); return report; }
  report.bodyOnly = bodyOnly;

  const block = headerText.length > MAX_HEADER_BYTES ? headerText.slice(0, MAX_HEADER_BYTES) : headerText;
  let headers;
  try {
    const rh = readHeaders(block);
    headers = rh.headers;
    // Seam: splitMessage handed readHeaders a header with the body already cut,
    // so nothing inside it should read as body. A non-zero count means the two
    // disagree about where the header ends.
    if (!bodyOnly && rh.skipped.lines > 0) report.breaks.push(`SEAM: readHeaders skipped ${rh.skipped.lines} line(s) inside the header block`);
  } catch (e) { report.breaks.push(`readHeaders threw (${e.name})`); return report; }

  let parts;
  try { ({ parts } = parseParts(headers, bodyText)); } catch (e) { report.breaks.push(`parseParts threw — must degrade, not throw (${e.name})`); return report; }
  report.parts = parts.length;
  report.types = [...new Set(parts.map((p) => p.contentType))].sort(); // a type, never its params

  let findings;
  try {
    findings = await withBridges([...analyse(headers), ...analyseBody(parts, { headers, bodyOnly })]);
  } catch (e) { report.breaks.push(`analyse threw (${e.name})`); return report; }
  report.findingIds = findings.map((f) => f.id);

  // Every finding is reached elsewhere by `find(f => f.id === ...)`. One with no
  // id is addressable only by its position in the array — so two of them, both
  // alerts at the front of the report, answer for each other. A real message
  // surfaced exactly this. Position and tone are fixed labels, never content.
  findings.forEach((f, idx) => {
    if (!f.id) report.breaks.push(`ANON: finding #${idx} carries no id (tone=${f.tone})`);
  });

  // A guardSection caught a throw: the pipeline faulted on this message.
  for (const f of findings) {
    for (const it of f.items ?? []) {
      if (it.level === 'fault') report.breaks.push(`FAULT in finding ${f.id}`);
    }
  }

  for (const colour of [false, true]) {
    let out;
    try { out = createRenderer({ colour, width: 80 }).render(findings); } catch (e) { report.breaks.push(`renderer threw colour=${colour} (${e.name})`); continue; }
    const vis = stripAnsi(out);
    const cb = vis.match(CONTROL_BYTE);
    if (cb) report.breaks.push(`CONTROL_BYTE on screen colour=${colour}: U+${cb[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`);
    // U+FFFD is the one character on a report that can only have come from
    // this tool — TextDecoder emits it where the bytes were not UTF-8, which is
    // a decoder reporting that it failed. A message may well carry one of its
    // own (a mis-encoded display name arrives as one), so what is checked is
    // that the tool did not invent it. A real message spent a whole render
    // showing them as campaign metadata, and every invariant here passed:
    // neutralise had made the control bytes among them printable first.
    if (!raw.includes('\uFFFD') && vis.includes('\uFFFD')) report.breaks.push(`MOJIBAKE on screen colour=${colour}: a decode the tool could not read was printed`);
    if (LIVE_URL.test(vis)) report.breaks.push(`LIVE_URL on screen colour=${colour}`);
    if (PLACEHOLDER.test(vis)) report.breaks.push(`PLACEHOLDER on screen colour=${colour}`);
  }
  return report;
}

async function main() {
  const dir = process.argv[2] ?? 'samples';
  let names;
  try {
    names = readdirSync(dir).filter((n) => /\.(eml|txt|mbox|msg)$/i.test(n) || !n.includes('.'));
  } catch (e) {
    process.stderr.write(`Cannot read ${dir}/: ${e.message}\nPut .eml files there (it is gitignored) and re-run.\n`);
    process.exitCode = 1;
    return;
  }
  if (!names.length) {
    process.stdout.write(`No messages in ${dir}/. Drop .eml files there (gitignored) and re-run.\n`);
    return;
  }

  const idTally = new Map();
  let clean = 0;
  const withBreaks = [];

  process.stdout.write(`corpus audit — ${names.length} message(s) in ${dir}/ (content never printed)\n\n`);
  let i = 0;
  for (const name of names.sort()) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) continue;
    i += 1;
    const raw = readFileSync(path, 'utf8'); // into this process only; never echoed
    const r = await auditOne(raw);
    for (const id of new Set(r.findingIds)) idTally.set(id, (idTally.get(id) ?? 0) + 1);
    const ok = r.breaks.length === 0;
    if (ok) clean += 1; else withBreaks.push({ i, r });
    process.stdout.write(
      `#${String(i).padStart(3)} ${ok ? 'ok ' : 'BREAK'}  ${String(r.kb).padStart(4)}KB  ${String(r.parts).padStart(2)} part(s)`
      + `${r.bodyOnly ? '  body-only' : ''}  [${r.types.join(', ') || 'no parts'}]  {${[...new Set(r.findingIds)].join(', ')}}\n`,
    );
    for (const b of r.breaks) process.stdout.write(`        ↳ ${b}\n`);
  }

  process.stdout.write(`\nfindings seen (message counts): ${[...idTally].sort((a, b) => b[1] - a[1]).map(([id, n]) => `${id}:${n}`).join('  ') || '(none)'}\n`);
  process.stdout.write(`invariants: ${clean}/${i} message(s) clean, ${withBreaks.length} with a break\n`);
  if (withBreaks.length) {
    process.stdout.write('\nBreaks are the whole point of running this — each one is a synthetic test to build.\n');
    process.exitCode = 1;
  }
}

main();
