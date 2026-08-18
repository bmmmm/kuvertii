// Control characters in header text — made inert, and made visible.
//
// Every other module in this project treats a header value as text. This one
// asks the prior question: whether it is text at all. The sender wrote these
// bytes, and in this tool's threat model the sender is the attacker.
//
// A terminal does not separate data from instruction. Bytes arriving on stdout
// are obeyed: `ESC ] 52` writes the reader's clipboard, `ESC ] 8` turns the
// following words into a clickable link, `ESC [ 2J` erases the warning that was
// about to be printed, `ESC [ 8m` renders it invisible. A browser obeys a much
// smaller set, but U+202E reverses a hostname, so the destination the reader is
// shown is not the destination they would reach — which defeats the one thing
// this tool exists to do.
//
// Nothing here deletes anything. Sequences are rewritten into a form no
// terminal and no bidi algorithm acts upon, and left where they were found: a
// header that tried to steer the reader's terminal is evidence, and discarding
// evidence is not this tool's habit. `scanControls` turns that evidence into a
// finding; `neutralise` is what makes printing it safe.
//
// ---------------------------------------------------------------------------
//
// What is dangerous is defined by Unicode category, not by a list kept here.
//
// It used to be two hand-written ranges, and a hand-written range is a bet that
// nobody will find the character it forgot. Somebody did: the whole 8-bit C1
// block, U+0080–U+009F, carries the same OSC, CSI, DCS and APC introducers as
// the ESC-prefixed forms — xterm honours them in UTF-8 mode by default — and
// none of them were in either range. They passed through untouched, and because
// the same ranges also drove `hasControls`, the report additionally said
// nothing had been found. U+2028, private-use characters and U+180E went the
// same way.
//
// Categories close that class rather than that instance:
//
//   Cc  control (C0, DEL, and the C1 block that started this)
//   Cf  format — bidi overrides, zero-width joiners, U+FEFF, and whatever
//       Unicode adds next, which is the part a list can never have
//   Co  private use — renders as whatever the reader's font decides
//   Cs  surrogates, which only appear here unpaired and therefore broken
//   Zl  line separator, Zp paragraph separator
//
// The definition is now maintained by Unicode rather than by us. Measured
// before adopting it: German and French field values, `✓ ✗ ! ○ ▸ ·`, IDN
// hostnames, CJK subjects and emoji all pass through untouched, because none of
// them are in any of those categories — and every hostile case above is caught.
//
// Tab and newline are spared: both are ordinary inside a decoded multi-line
// payload, and neither steers a terminal. Carriage return is NOT spared — on
// its own it returns the cursor to column zero, which is how a line already
// printed gets overwritten by the next one.

const HOSTILE = /[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}]/u;
const HOSTILE_G = new RegExp(HOSTILE.source, 'gu');
const SPARED = new Set(['\t', '\n']);

const ESC = '\u001B';

/**
 * The 8-bit forms of the escape introducers, and their two-character spellings.
 *
 * `ESC [` and U+009B mean the same thing to a terminal that decodes C1, so the
 * cheapest correct way to describe what a C1 sequence would do is to rewrite it
 * as the ESC form and let the table below answer. One vocabulary, not two.
 */
const C1_INTRODUCERS = new Map([
  ['\u009B', `${ESC}[`],
  ['\u009D', `${ESC}]`],
  ['\u0090', `${ESC}P`],
  ['\u009E', `${ESC}^`],
  ['\u009F', `${ESC}_`],
  ['\u009C', `${ESC}\\`],
  ['\u0098', `${ESC}X`],
]);

/**
 * What an escape sequence would have done, matched against the text following
 * the introducer.
 *
 * Ordered by consequence rather than by the structure of the grammar: the
 * reader is owed the clipboard write before the colour change. The last entry
 * matches anything, because an introducer whose body we cannot name is still
 * worth saying out loud.
 */
const SEQUENCES = [
  // The string terminator that closes an OSC. Deliberately described as
  // nothing: it always follows a sequence that has already been named, and
  // reporting it separately would pad every clipboard write with a second,
  // meaningless line about an unidentified escape.
  [/^\\/, null],
  [/^\]52;/, 'writes to your clipboard'],
  [/^\]8;/, 'turns text into a clickable link'],
  [/^\][0-9]*;/, 'sends a command to the terminal itself'],
  [/^[P_^X]/, 'sends a device-control payload'],
  [/^\[[0-9;]*8m/, 'hides the text that follows'],
  [/^\[[0-9;?]*[JK]/, 'erases part of the screen'],
  [/^\[[0-9;?]*[ABCDHfd]/, 'moves the cursor'],
  [/^\[/, 'changes how the terminal renders what follows'],
  [/^/, 'starts a sequence this tool could not identify'],
];

const BIDI = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/;
const INVISIBLE = /[\u200B\u200C\u200D\u2060-\u2064\uFEFF\u180E]/;
const SEPARATOR = /[\u2028\u2029]/;
const PRIVATE_USE = /[\p{Co}\p{Cs}]/u;
// C0 that is neither the escape introducer nor a carriage return — those two
// are described in their own words below, and would otherwise be counted twice.
const OTHER_C0 = /[\u0000-\u0008\u000B\u000C\u000E-\u001A\u001C-\u001F\u007F]/;

/**
 * Rewrite control characters into something inert and legible.
 *
 * `<1b>` rather than a caret: `^[` is itself two characters some terminals can
 * be configured to interpret, and the hex form names the exact byte that was
 * there, which is what a reader comparing two headers actually needs. Anything
 * above the ASCII range is named as a codepoint instead, because there is no
 * single byte to name — U+009B is two bytes in UTF-8, and `<9b>` would be a
 * quietly wrong description of what was in the file.
 *
 * Neutralising the introducer is sufficient on its own. With the ESC rewritten,
 * the remainder of the sequence is ordinary text that no terminal acts on — so
 * there is no need to parse an escape grammar in order to defuse one, and no
 * risk of a novel sequence slipping past a parser that did not expect it.
 */
export function neutralise(text) {
  return String(text ?? '').replace(HOSTILE_G, (ch) => {
    if (SPARED.has(ch)) return ch;
    const code = ch.codePointAt(0);
    return code < 0x80
      ? `<${code.toString(16).padStart(2, '0')}>`
      : `<U+${code.toString(16).toUpperCase().padStart(4, '0')}>`;
  });
}

/** Does this string carry anything `neutralise` would rewrite? */
export function hasControls(text) {
  const value = String(text ?? '');
  if (!HOSTILE.test(value)) return false;
  // Tab and newline match the category and are left alone, so their presence
  // alone is not a finding — `neutralise` and this must agree exactly, or the
  // report announces an attack it then declines to point at.
  return [...value].some((ch) => !SPARED.has(ch) && HOSTILE.test(ch));
}

/**
 * Describe what is hiding in a string, worst first.
 *
 * Returns distinct consequences rather than a count of bytes, because "three
 * escape sequences" tells the reader nothing and "writes to your clipboard"
 * tells them everything.
 */
export function scanControls(text) {
  const value = String(text ?? '');
  const effects = [];
  const add = (effect) => { if (effect && !effects.includes(effect)) effects.push(effect); };

  // C1 introducers first, rewritten to their ESC spelling so that one table
  // answers for both forms. Without this the 8-bit sequences were neutralised
  // and never named, which is the half of the fix that is easy to forget: the
  // reader would see `<U+009D>` in the output and no finding explaining it.
  let normalised = value;
  for (const [c1, escaped] of C1_INTRODUCERS) {
    if (normalised.includes(c1)) normalised = normalised.split(c1).join(escaped);
  }

  // Each introducer is classified separately: one value can carry a colour
  // change and a clipboard write, and naming only the first would understate it
  // by exactly the part that matters.
  if (normalised.includes(ESC)) {
    for (const body of normalised.split(ESC).slice(1)) {
      add(SEQUENCES.find(([pattern]) => pattern.test(body))?.[1]);
    }
  }
  if (BIDI.test(value)) add('reverses the direction the text is read in');
  if (INVISIBLE.test(value)) add('inserts characters that render as nothing at all');
  if (SEPARATOR.test(value)) add('breaks the line where no line break was written');
  if (PRIVATE_USE.test(value)) add('uses characters with no agreed meaning, which every font renders differently');
  if (value.includes('\r')) add('returns the cursor to the start of the line, overwriting it');
  if (OTHER_C0.test(value)) add('carries control bytes a terminal may act on');
  // Anything in the C1 block that is not one of the named introducers.
  if (/[\u0080-\u009F]/.test(value) && !effects.length) add('carries control bytes a terminal may act on');

  return effects;
}
