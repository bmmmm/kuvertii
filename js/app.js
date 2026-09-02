// UI glue. Holds the pasted header in one variable and nothing else — no
// storage, no history entry, no form restoration.

import { checkHost } from './blocklist.js';
import { verdictRows } from './snapshot.js';
import { analyseBody } from './body.js';
import { neutralise } from './control.js';
import { hashedAddressRows } from './emailhash.js';
import { analyse } from './findings.js';
import { parseParts, readTally, splitMessage } from './mime.js';
import { clippedNote, MAX_HEADER_BYTES, readHeaders } from './unfold.js';

const input = document.querySelector('#header-input');
const inputArea = document.querySelector('#input-area');
const fileInput = document.querySelector('#file-input');
const results = document.querySelector('#results');
const emptyState = document.querySelector('#empty-state');
const status = document.querySelector('#status');

/**
 * Wide enough to read eleven cards at once.
 *
 * Below it the report is a scroll: a phone shows about one card per screen, so
 * a reader looking for the one alert swipes past ten notes to find it. Above
 * it everything is open, because a desktop reader can see the shape of the
 * report without touching it.
 */
const WIDE_SCREEN = '(min-width: 48rem)';

/**
 * The same ceiling the CLI puts on the clipboard (js/clipboard.js): past this
 * a file is not a message any more, and `file.text()` on it would hand the tab
 * a string it cannot hold. Refused with a sentence rather than read slowly.
 */
const MAX_FILE_BYTES = 32 * 1024 * 1024;

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

/**
 * Render one card, collapsed on a narrow screen unless it is an alert.
 *
 * An alert stays a plain `<section>` and is therefore always open. A card that
 * has to be tapped before it can be read is a card a hurried reader does not
 * read, and the alert is the one they came for — collapsing it would hide the
 * finding behind the convenience of the ones that do not matter.
 *
 * `tabindex="-1"` on every card is what lets a jump button move the reader's
 * focus into it. It keeps the card out of the tab order: a reader tabbing
 * through the page should reach the buttons, not eleven inert containers.
 */
function renderFinding(finding) {
  const collapsible = finding.tone !== 'alert';
  const card = el(collapsible ? 'details' : 'section', `card card--${finding.tone}`);
  card.tabIndex = -1;

  const title = el('h2', 'card__title', finding.title);
  if (collapsible) {
    // Decided per card at render time rather than by a media query, because
    // `open` is state, not style: CSS can hide the body of a `<details>` but
    // the browser would still report it as expanded to a screen reader.
    card.open = window.matchMedia(WIDE_SCREEN).matches;
    const summary = el('summary', 'card__summary');
    summary.append(title);
    card.append(summary);
  } else {
    card.append(title);
  }

  if (finding.lede) card.append(el('p', 'card__lede', finding.lede));

  const list = el('div', 'card__items');
  const seenNotes = new Set();
  finding.items.forEach((item) => list.append(renderItem(item, seenNotes)));
  card.append(list);
  return { card, list, collapsible };
}

/** How many cards of each tone there are, in the words the page uses for them. */
const TONE_NAMES = {
  alert: ['alert', 'alerts'],
  info: ['note', 'notes'],
  neutral: ['neutral card', 'neutral cards'],
};

function tallySentence(findings) {
  const parts = [];
  for (const [tone, [one, many]] of Object.entries(TONE_NAMES)) {
    const count = findings.filter((finding) => finding.tone === tone).length;
    if (count) parts.push(`${count} ${count === 1 ? one : many}`);
  }
  return `${parts.join(', ')}.`;
}

/**
 * The report's table of contents.
 *
 * A report of eleven cards on a phone is a scroll with no shape. This says how
 * many findings there are and what each one is called before the reader has
 * moved, and lets them jump to the one they want.
 *
 * Buttons, not links. An anchor would put a fragment in the address bar, and
 * that fragment survives in history — on a page whose whole claim is that the
 * message is gone when the tab closes, nothing about a message may be written
 * anywhere the browser keeps. The rest of the file never builds an `<a>` for
 * a different reason; here it is the same rule arriving from the other side.
 */
function renderOverview(cards) {
  const nav = el('nav', 'overview');
  nav.tabIndex = -1;
  // Set through the reflected property, never setAttribute: this file has one
  // way to reach an attribute and it is a fixed string of ours.
  nav.ariaLabel = 'Report overview';
  nav.append(el('p', 'overview__tally', tallySentence(cards.map(({ finding }) => finding))));

  const jumps = el('div', 'overview__jumps');
  for (const { finding, card, collapsible } of cards) {
    const jump = el('button', `overview__jump overview__jump--${finding.tone}`, finding.title);
    jump.type = 'button';
    jump.addEventListener('click', () => {
      // Opened before it is scrolled to: otherwise the reader lands on a closed
      // box and has to guess that it needs a second tap.
      if (collapsible) card.open = true;
      card.scrollIntoView({ block: 'start' });
      card.focus();
    });
    jumps.append(jump);
  }
  nav.append(jumps);
  return nav;
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

/**
 * Append address-hash verdicts — the same bridge shape as the blocklist:
 * the analysis collected candidate tokens synchronously, the digests run
 * here, on crypto.subtle, and only rows that say something are appended.
 */
async function appendHashVerdict(list, hashCheck) {
  for (const row of await hashedAddressRows(hashCheck)) list.append(renderItem(row));
}

function run() {
  const pasted = input.value;
  results.replaceChildren();

  if (!pasted.trim()) {
    emptyState.hidden = false;
    status.textContent = '';
    return;
  }

  // The paste decides what this is: a header block, a whole message, or a
  // body that lost its header. js/mime.js makes that call for both front ends.
  const { headerText, bodyText, bodyOnly } = splitMessage(pasted);
  // A ceiling on how long this tab can stop responding: analyse() is synchronous
  // and there is no worker behind it. Clipped rather than refused, because the
  // fields worth reading are at the top of a header and a reader who pasted a
  // whole mailbox is better served by an answer than by a complaint.
  const text = headerText.length > MAX_HEADER_BYTES ? headerText.slice(0, MAX_HEADER_BYTES) : headerText;
  // One wording for both renderers — see clippedNote for how the two drifted.
  const clipped = clippedNote(headerText.length);

  const { headers } = readHeaders(text);

  let bodyRead;
  try {
    bodyRead = parseParts(headers, bodyText);
  } catch (error) {
    // parseParts promises to degrade rather than throw; this is the last line
    // of that promise, and it reports the failure as what it is.
    bodyRead = {
      parts: [],
      notes: [` The body could not be taken apart (${error.message}). That is a fault in this tool, not a fact about the message — the body findings are missing, not clear.`],
    };
  }
  const { parts, notes } = bodyRead;

  const findings = [...analyse(headers), ...analyseBody(parts, { headers, bodyOnly })];
  if (!headers.length && !findings.length) {
    emptyState.hidden = false;
    status.textContent = `Nothing here parsed as a header block.${clipped}`;
    return;
  }

  emptyState.hidden = true;

  if (!findings.length) {
    status.textContent = `Parsed ${headers.length} header fields, but found nothing noteworthy in them.${clipped}`;
    return;
  }

  // The status line is a complete account of what was read — headers, body
  // parts, and every ceiling that bit along the way.
  status.textContent = `${readTally(headers.length, parts.length)}${notes.join('')} Nothing left this page.${clipped}`;

  // The textarea has done its job; ten rows of raw header between the reader
  // and the report is ten rows of scrolling. A focus on it opens it again.
  inputArea.classList.add('input-area--read');

  const rendered = findings.map((finding) => ({ finding, ...renderFinding(finding) }));
  const overview = renderOverview(rendered);
  results.append(overview);
  for (const { card } of rendered) results.append(card);

  // Where a phone reader is standing when this returns: without it the page has
  // silently grown eleven cards below the fold, the viewport is still at the
  // top of the textarea, and focus is on nothing at all.
  overview.scrollIntoView({ block: 'start' });
  overview.focus();

  for (const { finding, list } of rendered) {
    if (finding.hashCheck) {
      appendHashVerdict(list, finding.hashCheck).catch((error) => {
        list.append(renderItem({
          label: 'The address-hash check did not complete',
          value: `Whether these ids encode your address went unchecked, so treat them as unchecked rather than clean. (${error.message})`,
          level: 'caution',
        }));
      });
    }
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
  inputArea.classList.remove('input-area--read');
  input.focus();
}

/**
 * Read a message out of a file the reader chose or dropped.
 *
 * `file.text()` and nothing else: no FileReader handing back a data: URL, no
 * object URL, no fetch. The bytes go from the disk into the same string a paste
 * would have produced, and the file name is never rendered — it is usually the
 * subject line, sometimes the sender, and this page does not put either on
 * screen unless the message itself said so.
 */
async function readMessageFile(file) {
  if (!file) return;
  if (file.size > MAX_FILE_BYTES) {
    status.textContent = 'That file is larger than 32 MB, which no message reaches. It was not read — open the message file itself rather than an archive or a mailbox.';
    return;
  }
  input.value = await file.text();
  run();
}

document.querySelector('#analyse').addEventListener('click', run);
document.querySelector('#clear').addEventListener('click', clear);
document.querySelector('#open-file').addEventListener('click', () => fileInput.click());
input.addEventListener('keydown', (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') run();
});

// A paste is the whole gesture on this page — asking for a second click on
// "Read it" afterwards is asking the reader to confirm what they just did.
// The button stays for text that was edited rather than pasted.
input.addEventListener('paste', () => {
  // The pasted text is not in the field yet: `paste` fires before the browser
  // writes the value, so reading it here would analyse whatever was there
  // before. One turn of the event loop is enough to let the field settle.
  setTimeout(run, 0);
});

// Editing means the report is about to be about something else, so the field
// goes back to full height. Removed on focus rather than on input: a reader
// who clicks in to change one character should see what they are editing.
input.addEventListener('focus', () => inputArea.classList.remove('input-area--read'));

fileInput.addEventListener('change', (event) => {
  const file = event.target.files?.[0];
  // Cleared before the read, not after it: the element otherwise keeps the
  // chosen file's name in the DOM, and picking the same file a second time
  // would fire no event at all because the value did not change.
  fileInput.value = '';
  readMessageFile(file);
});

// Dropping a saved .eml onto the page is the shortest route from a phone or a
// mail client to a reading, and it touches the bytes exactly the way the file
// picker does.
inputArea.addEventListener('dragover', (event) => {
  // Without preventDefault the browser navigates to the file instead, which
  // leaves the page and renders the message in the tab — the one thing this
  // tool exists not to do.
  event.preventDefault();
  inputArea.classList.add('input-area--drop');
});
inputArea.addEventListener('dragleave', () => inputArea.classList.remove('input-area--drop'));
inputArea.addEventListener('drop', (event) => {
  event.preventDefault();
  inputArea.classList.remove('input-area--drop');
  readMessageFile(event.dataTransfer?.files?.[0]);
});

// Browsers restore form fields on reload and on back-navigation. For this page
// that would resurrect a header the user believed they had discarded.
window.addEventListener('pageshow', (event) => {
  if (event.persisted) clear();
});
input.value = '';
