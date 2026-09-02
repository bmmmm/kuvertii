// The invariants a finished report must satisfy, in one place.
//
// They were written inside tools/corpus-audit.mjs, which runs them over real
// mail through the terminal renderer only. That is one corpus and one front
// end; the same promises hold for generated messages and for the page, so the
// checks live here and the tools that have messages become loops around them.
//
// Nothing here prints anything, and nothing here returns message content: a
// break is a fixed label plus, at most, a Unicode codepoint, an index, a tone
// or a finding id. That is what makes the output of a tool built on this safe
// to read and safe to paste anywhere, whatever went into it.

import { hashedAddressRows } from '../js/emailhash.js';
import { ALL_CLEAR_TITLE, PASSED_BUT_JUNK_TITLE } from '../js/findings.js';
import { verdictRows } from '../js/snapshot.js';

/** Anything that steers a terminal or hides itself, tab and newline excepted. */
export const CONTROL_BYTE = /(?![\t\n])[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}]/u;
/** A scheme plus one host character: enough for a terminal to make it clickable. */
export const LIVE_URL = /(?:https?|ftps?):\/\/[^\s<>"'`)\]]/i;
/** A value that escaped its formatting and reached the screen as machinery. */
export const PLACEHOLDER = /\[object Object\]|native code|\bundefined\b|\bNaN\b|the first ∞|∞ bytes/;

export const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');

/** Resolve the two async bridges the front ends resolve, so their rows are checked too. */
export async function withBridges(findings) {
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

/**
 * The invariants that hold on the findings themselves, before anything renders.
 */
export function checkFindings(findings) {
  const breaks = [];

  // Every finding is reached elsewhere by `find(f => f.id === ...)`. One with no
  // id is addressable only by its position in the array — so two of them, both
  // alerts at the front of the report, answer for each other. A real message
  // surfaced exactly this. Position and tone are fixed labels, never content.
  findings.forEach((f, idx) => {
    if (!f.id) breaks.push(`ANON: finding #${idx} carries no id (tone=${f.tone})`);
  });

  // And the other half of the same promise, which went unchecked: `find` stops
  // at the first match, so a second card wearing an id that already exists is a
  // card nothing can reach — every caller, every test and every jump target in
  // the overview resolves to its twin instead.
  const seen = new Set();
  for (const f of findings) {
    if (!f.id) continue;
    if (seen.has(f.id)) breaks.push(`DUPLICATE ID: two findings share the id ${f.id}`);
    seen.add(f.id);
  }

  // A guardSection caught a throw: the pipeline faulted on this message.
  for (const f of findings) {
    for (const it of f.items ?? []) {
      if (it.level === 'fault') breaks.push(`FAULT in finding ${f.id}`);
    }
  }

  // "Every check passed" over an alert is the report contradicting itself in
  // the two places a glance lands. Individual cases have tests; this says it
  // once for any card, so a headline reaching a new card is caught by the
  // invariant rather than by whoever happens to write that card's test.
  for (const f of findings) {
    if (f.tone !== 'alert') continue;
    if (f.title === ALL_CLEAR_TITLE || f.title === PASSED_BUT_JUNK_TITLE) {
      breaks.push(`ALL-CLEAR ON AN ALERT: finding ${f.id} headlines a clean pass`);
    }
  }

  return breaks;
}

/**
 * The invariants that hold on what a reader actually sees.
 *
 * `raw` is the message the screen came from — needed for one check only, and
 * only to ask whether a character was already in it.
 */
export function checkScreen(visible, { raw = '', where = 'screen' } = {}) {
  const breaks = [];

  const cb = visible.match(CONTROL_BYTE);
  if (cb) {
    const point = cb[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
    breaks.push(`CONTROL_BYTE on screen ${where}: U+${point}`);
  }

  // U+FFFD is the one character on a report that can only have come from this
  // tool — TextDecoder emits it where the bytes were not UTF-8, which is a
  // decoder reporting that it failed. A message may well carry one of its own
  // (a mis-encoded display name arrives as one), so what is checked is that the
  // tool did not invent it. A real message spent a whole render showing them as
  // campaign metadata, and every invariant here passed: neutralise had made the
  // control bytes among them printable first.
  if (!raw.includes('�') && visible.includes('�')) {
    breaks.push(`MOJIBAKE on screen ${where}: a decode the tool could not read was printed`);
  }

  if (LIVE_URL.test(visible)) breaks.push(`LIVE_URL on screen ${where}`);
  if (PLACEHOLDER.test(visible)) breaks.push(`PLACEHOLDER on screen ${where}`);

  return breaks;
}

/**
 * Every invariant at once: the findings, then each screen they were rendered to.
 *
 * `screens` is `[{ where, text }]` — one entry per front end a caller can drive.
 */
export function checkReport({ raw = '', findings = [], screens = [] } = {}) {
  return [
    ...checkFindings(findings),
    ...screens.flatMap(({ where, text }) => checkScreen(text, { raw, where })),
  ];
}
