// UI glue. Holds the pasted header in one variable and nothing else — no
// storage, no history entry, no form restoration.

import { checkHost } from './blocklist.js';
import { verdictRows } from './snapshot.js';
import { neutralise } from './control.js';
import { analyse } from './findings.js';
import { MAX_HEADER_BYTES, readHeaders, skippedNote } from './unfold.js';

const input = document.querySelector('#header-input');
const results = document.querySelector('#results');
const emptyState = document.querySelector('#empty-state');
const status = document.querySelector('#status');

/**
 * Build an element without ever handing untrusted text to innerHTML.
 *
 * Everything rendered here — labels, values, chips — may contain text taken
 * straight from the pasted header, so `textContent` is the only way anything
 * is written. In particular no branch of this file ever creates an `<a>`: a
 * URL out of a header is displayed as inert text and must never become
 * clickable, because the click is the thing the sender is waiting for. The
 * only links on this page are the hand-written ones in the footer.
 *
 * `textContent` settles what the browser will *parse*, and `neutralise` settles
 * what it will *display*. The two are not the same question: U+202E is not
 * markup and survives textContent intact, but it reverses the characters after
 * it, so a hostname whose bytes read `evil` can be shown to the reader as
 * `account.apple.com`. On a page whose entire purpose is to say where a link
 * really goes, that is the whole game — hence the same pass the terminal uses.
 */
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = neutralise(text);
  return node;
}

function renderItem(item, seenNotes) {
  const row = el('div', 'item');
  if (item.emphasis) row.classList.add('item--emphasis');
  if (item.level) row.classList.add(`item--${item.level}`);

  row.append(el('div', 'item__label', item.label));
  // Multi-line mono values are the sender's text rendered with the sender's
  // line breaks — see the note in js/terminal.js. `white-space: pre-wrap` makes
  // the page reproduce them just as faithfully as the terminal does, so it
  // needs the same visible quoting.
  const monoClass = String(item.value ?? '').includes('\n')
    ? 'item__value item__value--mono item__value--quoted'
    : 'item__value item__value--mono';
  const value = el('div', item.mono ? monoClass : 'item__value', item.value);
  row.append(value);

  if (item.chips?.length) {
    const chips = el('div', 'item__chips');
    item.chips.forEach((chip) => chips.append(el('span', 'chip', chip)));
    row.append(chips);
  }

  // A note that applies to several rows is worth reading once. Repeating it on
  // every row is what turns a list of findings into a wall of prose.
  if (item.note && !seenNotes?.has(item.note)) {
    seenNotes?.add(item.note);
    row.append(el('div', 'item__note', item.note));
  }
  return row;
}

function renderFinding(finding) {
  const card = el('section', `card card--${finding.tone}`);
  card.append(el('h2', 'card__title', finding.title));
  if (finding.lede) card.append(el('p', 'card__lede', finding.lede));

  const list = el('div', 'card__items');
  const seenNotes = new Set();
  finding.items.forEach((item) => list.append(renderItem(item, seenNotes)));
  card.append(list);
  return { card, list };
}

/**
 * Append blocklist verdicts once the filter has loaded.
 *
 * Deliberately asymmetric: a hit is stated plainly, a miss is stated as "not in
 * this snapshot" and never as "safe" — the snapshot is days old and phishing
 * domains rarely live that long.
 */
async function appendBlocklistVerdict(list, hosts) {
  const results = [];
  for (const host of hosts) results.push(await checkHost(host));
  for (const row of verdictRows(results)) list.append(renderItem(row));
}

function run() {
  const pasted = input.value;
  // A ceiling on how long this tab can stop responding: analyse() is synchronous
  // and there is no worker behind it. Clipped rather than refused, because the
  // fields worth reading are at the top of a header and a reader who pasted a
  // whole mailbox is better served by an answer than by a complaint.
  const overLength = pasted.length > MAX_HEADER_BYTES;
  const text = overLength ? pasted.slice(0, MAX_HEADER_BYTES) : pasted;
  const clipped = overLength
    ? ` Only the first ${Math.round(MAX_HEADER_BYTES / 1024)} KB of what you pasted was read.`
    : '';
  results.replaceChildren();

  if (!text.trim()) {
    emptyState.hidden = false;
    status.textContent = '';
    return;
  }

  const { headers, skipped } = readHeaders(text);
  if (!headers.length) {
    emptyState.hidden = false;
    status.textContent = `Nothing here parsed as a header block.${clipped}`;
    return;
  }

  const findings = analyse(headers);
  emptyState.hidden = true;

  if (!findings.length) {
    status.textContent = `Parsed ${headers.length} header fields, but found nothing noteworthy in them.${clipped}`;
    return;
  }

  status.textContent = `${headers.length} header fields read.${skippedNote(skipped)} Nothing left this page.${clipped}`;

  for (const finding of findings) {
    const { card, list } = renderFinding(finding);
    results.append(card);
    if (finding.hostsToCheck?.length) {
      appendBlocklistVerdict(list, finding.hostsToCheck).catch((error) => {
        // Not "rendered inline as unavailable", which is what the comment here
        // used to claim. `checkHost` handles a failed *fetch* that way, but a
        // throw from anywhere else — a malformed `meta.source` reaching a
        // template literal, say — happens while building the row, before it is
        // appended. Swallowed, that produced no row, no error and no spinner on
        // precisely the check the reader was waiting for: a phishing hit.
        list.append(renderItem({
          label: 'The blocklist check did not complete',
          value: `No verdict was reached for this link, so treat it as unchecked rather than clean. (${error.message})`,
          level: 'caution',
        }));
      });
    }
  }
}

function clear() {
  input.value = '';
  results.replaceChildren();
  emptyState.hidden = false;
  status.textContent = '';
  input.focus();
}

document.querySelector('#analyse').addEventListener('click', run);
document.querySelector('#clear').addEventListener('click', clear);
input.addEventListener('keydown', (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') run();
});

// Browsers restore form fields on reload and on back-navigation. For this page
// that would resurrect a header the user believed they had discarded.
window.addEventListener('pageshow', (event) => {
  if (event.persisted) clear();
});
input.value = '';
