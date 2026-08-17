// UI glue. Holds the pasted header in one variable and nothing else — no
// storage, no history entry, no form restoration.

import { checkHost } from './blocklist.js';
import { analyse } from './findings.js';
import { parseHeaders } from './unfold.js';

const input = document.querySelector('#header-input');
const results = document.querySelector('#results');
const emptyState = document.querySelector('#empty-state');
const status = document.querySelector('#status');

/** Build an element without ever handing untrusted text to innerHTML. */
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function renderItem(item) {
  const row = el('div', 'item');
  if (item.emphasis) row.classList.add('item--emphasis');
  if (item.level) row.classList.add(`item--${item.level}`);

  row.append(el('div', 'item__label', item.label));
  const value = el('div', item.mono ? 'item__value item__value--mono' : 'item__value', item.value);
  row.append(value);
  if (item.note) row.append(el('div', 'item__note', item.note));
  return row;
}

function renderFinding(finding) {
  const card = el('section', `card card--${finding.tone}`);
  card.append(el('h2', 'card__title', finding.title));
  if (finding.lede) card.append(el('p', 'card__lede', finding.lede));

  const list = el('div', 'card__items');
  finding.items.forEach((item) => list.append(renderItem(item)));
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
async function appendBlocklistVerdict(list, hosts, meta) {
  for (const host of hosts) {
    const result = await checkHost(host);

    if (result.unavailable) {
      list.append(renderItem({
        label: `Blocklist check unavailable (${host})`,
        value: 'The offline blocklist could not be loaded, so no check was made.',
        level: 'caution',
      }));
      continue;
    }

    if (result.listed) {
      list.append(renderItem({
        label: `${result.matched} is on a phishing blocklist`,
        value: `Snapshot of ${result.meta.source.name}, ${result.meta.entries.toLocaleString('en')} domains, built ${result.meta.builtAt}. Treat this link as hostile.`,
        note: `Matching is probabilistic — roughly 1 in ${Math.round(1 / result.meta.falsePositiveRate)} lookups can be a false alarm. Verify at ${result.meta.source.homepage} before concluding.`,
        level: 'bad',
        emphasis: true,
      }));
    } else {
      list.append(renderItem({
        label: `${host} is not in the blocklist snapshot`,
        value: 'This is not a clean bill of health. The snapshot is a point-in-time copy, and phishing domains are typically hours old — the dangerous ones are precisely those no list has caught yet.',
        note: result.meta
          ? `${result.meta.source.name}, built ${result.meta.builtAt}, ${result.meta.entries.toLocaleString('en')} domains.`
          : null,
      }));
    }
  }
  if (meta) status.textContent = '';
}

function run() {
  const text = input.value;
  results.replaceChildren();

  if (!text.trim()) {
    emptyState.hidden = false;
    status.textContent = '';
    return;
  }

  const headers = parseHeaders(text);
  if (!headers.length) {
    emptyState.hidden = false;
    status.textContent = 'Nothing here parsed as a header block.';
    return;
  }

  const findings = analyse(headers);
  emptyState.hidden = true;

  if (!findings.length) {
    status.textContent = `Parsed ${headers.length} header fields, but found nothing noteworthy in them.`;
    return;
  }

  status.textContent = `${headers.length} header fields read. Nothing left this page.`;

  for (const finding of findings) {
    const { card, list } = renderFinding(finding);
    results.append(card);
    if (finding.hostsToCheck?.length) {
      appendBlocklistVerdict(list, finding.hostsToCheck, true).catch(() => {
        /* rendered inline as unavailable */
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
