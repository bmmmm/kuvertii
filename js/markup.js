// A bounded scanner over sender-written HTML.
//
// Not DOMParser: that exists only in the browser, and an analysis the two
// front ends run through different parsers is two analyses that will disagree
// exactly where it matters. Not regex-over-HTML either: an unbounded pattern
// over attacker-length input is the failure class five audit rounds punished.
// This is a single forward pass — every loop moves an index strictly onwards,
// nothing backtracks — that extracts only what the body findings need:
// where links go, what their visible text claims, which images load from
// where, whether the mail carries a form, and the text a plain reading shows.
//
// Nothing here renders anything. The output is data for findings, and every
// string in it reaches the screen only through the same neutralise+defang
// path as every header value.

// Collected items across links, images and forms. Past this the count itself
// is the finding, and `truncated` says the card is not a complete inventory.
export const MAX_MARKUP_ITEMS = 2000;

// Visible text kept per link — enough to compare a claim against a
// destination; a link whose label runs longer is not labelling anything.
const MAX_LINK_TEXT = 500;

// Text runs kept in total. Body text feeds the plain-vs-html comparison and
// the identity scan; past this the body is not prose anyone reads.
const MAX_TEXT = 2 * 1024 * 1024;

// Attribute values are sender-length; a URL has no business past 4 KB.
const MAX_ATTR = 4096;

// The handful of named entities mail bodies actually carry. Numeric
// references are decoded generically below; an unknown name is left as
// written rather than guessed at.
const NAMED_ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ',
  copy: '©', reg: '®', trade: '™', shy: '­',
  mdash: '—', ndash: '–', hellip: '…', middot: '·',
  lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”',
  eacute: 'é', auml: 'ä', ouml: 'ö', uuml: 'ü', szlig: 'ß',
  zwnj: '‌', zwj: '‍',
};

/**
 * Character references, decoded to the real codepoint — deliberately
 * including the hostile ones. `&#x202E;` becomes an actual U+202E here,
 * because the finding has to see the string a mail client would show, and
 * the renderers' `neutralise` pass is what keeps it inert on screen. Decoding
 * it to anything tamer would hide the attack from both.
 */
export function decodeEntities(text) {
  return String(text ?? '').replace(
    /&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|([a-zA-Z]{2,12}));/g,
    (whole, decimal, hex, name) => {
      if (name) return NAMED_ENTITIES[name.toLowerCase()] ?? whole;
      const code = decimal ? Number(decimal) : parseInt(hex, 16);
      return code <= 0x10ffff ? String.fromCodePoint(code) : whole;
    },
  );
}

// Tags whose boundary separates words in every mail client's rendering.
// Without this, `</td><td>` glues two table cells into one token and the
// text comparison reads words nobody was shown.
const BREAKS_WORDS = new Set([
  'p', 'div', 'br', 'tr', 'td', 'th', 'li', 'ul', 'ol', 'table', 'h1', 'h2',
  'h3', 'h4', 'h5', 'h6', 'blockquote', 'hr', 'section', 'article', 'header',
  'footer', 'center',
]);

/**
 * One pass over an HTML body.
 *
 * Returns { links, images, forms, base, text, truncated }:
 *   links  — [{ href, text }], text being what a reader sees for that link,
 *            image alt text included, clipped at MAX_LINK_TEXT
 *   images — [{ src, width, height, alt }], dimensions as written
 *   forms  — [{ action }]
 *   base   — the first <base href>, or null
 *   text   — the visible text runs, entity-decoded, whitespace as written
 *   truncated — true when a collection ceiling bit
 */
export function scanMarkup(input) {
  const html = String(input ?? '');
  // Computed once: a lowercase copy per <script> tag would be quadratic over
  // a body that is nothing but script tags, and the sender writes the body.
  const lower = html.toLowerCase();
  const links = [];
  const images = [];
  const forms = [];
  let base = null;
  let text = '';
  let truncated = false;
  let currentLink = null;

  const room = () => links.length + images.length + forms.length < MAX_MARKUP_ITEMS;

  const pushText = (run) => {
    if (!run) return;
    const decoded = decodeEntities(run);
    if (text.length < MAX_TEXT) text += decoded;
    else truncated = true;
    if (currentLink && currentLink.text.length < MAX_LINK_TEXT) {
      currentLink.text = (currentLink.text + decoded).slice(0, MAX_LINK_TEXT);
    }
  };

  const finishLink = () => {
    if (!currentLink) return;
    if (room()) links.push({ href: currentLink.href, text: currentLink.text.trim() });
    else truncated = true;
    currentLink = null;
  };

  let i = 0;
  const n = html.length;
  while (i < n) {
    const lt = html.indexOf('<', i);
    if (lt === -1) {
      pushText(html.slice(i));
      break;
    }
    pushText(html.slice(i, lt));

    const next = html[lt + 1];
    if (next === '!') {
      // Comments — including Outlook's conditional ones — and doctypes carry
      // no reader-visible content.
      if (html.startsWith('<!--', lt)) {
        const end = html.indexOf('-->', lt + 4);
        i = end === -1 ? n : end + 3;
      } else {
        const end = html.indexOf('>', lt + 2);
        i = end === -1 ? n : end + 1;
      }
      continue;
    }
    if (next === '?') {
      const end = html.indexOf('>', lt + 2);
      i = end === -1 ? n : end + 1;
      continue;
    }

    const tag = readTag(html, lt);
    if (!tag) {
      // A lone `<` that opens nothing is text.
      pushText('<');
      i = lt + 1;
      continue;
    }
    i = tag.end;

    if (tag.closing) {
      if (tag.name === 'a') finishLink();
      if (BREAKS_WORDS.has(tag.name)) pushText(' ');
      continue;
    }

    switch (tag.name) {
      case 'a':
        finishLink();
        currentLink = { href: tag.attrs.href ?? null, text: '' };
        break;
      case 'img': {
        if (room()) {
          images.push({
            src: tag.attrs.src ?? null,
            width: tag.attrs.width ?? null,
            height: tag.attrs.height ?? null,
            alt: tag.attrs.alt ?? null,
          });
        } else truncated = true;
        // The alt text is what a reader sees where the image would be, so it
        // counts as the visible text of a link wrapped around it.
        if (tag.attrs.alt) pushText(tag.attrs.alt);
        break;
      }
      case 'form':
        if (room()) forms.push({ action: tag.attrs.action ?? null });
        else truncated = true;
        break;
      case 'base':
        base ??= tag.attrs.href ?? null;
        break;
      case 'script':
      case 'style': {
        // Content of either is never reader-visible text. Skipped by finding
        // the closing tag; a block that never closes runs to the end, which
        // is also what a browser does with it.
        const close = lower.indexOf(`</${tag.name}`, i);
        i = close === -1 ? n : close;
        break;
      }
      default:
        if (BREAKS_WORDS.has(tag.name)) pushText(' ');
    }
  }
  finishLink();

  return { links, images, forms, base, text, truncated };
}

/**
 * Read one tag starting at `<`.
 *
 * Returns { name, attrs, end, closing } or null when what follows `<` is not
 * a tag at all. Attribute values are entity-decoded and clipped; quoted
 * values may contain `>`, which is why this cannot be an indexOf('>') — the
 * scan is character-wise and quote-aware, and every step moves forward.
 */
function readTag(html, lt) {
  const closing = html[lt + 1] === '/';
  let i = lt + (closing ? 2 : 1);
  const nameStart = i;
  while (i < html.length && i - nameStart < 24 && /[a-zA-Z0-9-]/.test(html[i])) i++;
  if (i === nameStart) return null;
  const name = html.slice(nameStart, i).toLowerCase();
  const attrs = {};

  while (i < html.length) {
    const ch = html[i];
    if (ch === '>') return { name, attrs, end: i + 1, closing };
    if (ch === '"' || ch === "'") {
      // A stray quote outside any attribute: skip its span so a `>` inside
      // does not end the tag early.
      const close = html.indexOf(ch, i + 1);
      i = close === -1 ? html.length : close + 1;
      continue;
    }
    if (/[a-zA-Z]/.test(ch)) {
      const start = i;
      while (i < html.length && i - start < 32 && /[a-zA-Z0-9-]/.test(html[i])) i++;
      const attrName = html.slice(start, i).toLowerCase();
      while (i < html.length && /\s/.test(html[i])) i++;
      if (html[i] !== '=') {
        // A bare attribute; nothing this scanner wants carries meaning bare.
        continue;
      }
      i++;
      while (i < html.length && /\s/.test(html[i])) i++;
      const quote = html[i];
      let value;
      if (quote === '"' || quote === "'") {
        const close = html.indexOf(quote, i + 1);
        value = html.slice(i + 1, close === -1 ? html.length : close);
        i = close === -1 ? html.length : close + 1;
      } else {
        const start2 = i;
        while (i < html.length && !/[\s>]/.test(html[i])) i++;
        value = html.slice(start2, i);
      }
      // First spelling wins, as in a browser.
      attrs[attrName] ??= decodeEntities(value.slice(0, MAX_ATTR));
      continue;
    }
    i++;
  }
  // The tag never closed; whatever was read of it stands, and the scan is at
  // the end of the input either way.
  return { name, attrs, end: html.length, closing };
}
