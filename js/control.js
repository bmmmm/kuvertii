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

// C0 and DEL, minus the two that carry meaning in a value we display: tab, and
// the newline that separates the lines of a decoded multi-line payload.
// Carriage return is NOT spared — on its own it returns the cursor to column
// zero, which is how a line already printed gets overwritten by the next one.
const C0_AND_DEL = /[\x00-\x08\x0b-\x1f\x7f]/;

// Format and bidi controls. These are legal Unicode with legitimate uses in
// running prose, and none at all inside a hostname, a message id or a list
// name — which is the only kind of text this module ever sees.
const UNICODE_CONTROLS = /[\u061C\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/;

const C0_AND_DEL_G = new RegExp(C0_AND_DEL.source, 'g');
const UNICODE_CONTROLS_G = new RegExp(UNICODE_CONTROLS.source, 'g');

const ESC = '\x1b';

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

const BIDI = /[\u061C\u202A-\u202E\u2066-\u2069]/;
const INVISIBLE = /[\u200B-\u200F\u2060-\u2064\uFEFF]/;
// C0 that is neither the escape introducer nor a carriage return — those two
// are described in their own words below, and would otherwise be counted twice.
const OTHER_C0 = /[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]/;

/**
 * Rewrite control characters into something inert and legible.
 *
 * `<1b>` rather than a caret: `^[` is itself two characters some terminals can
 * be configured to interpret, and the hex form names the exact byte that was
 * there, which is what a reader comparing two headers actually needs.
 *
 * Neutralising the introducer is sufficient on its own. With the ESC rewritten,
 * the remainder of the sequence is ordinary text that no terminal acts on — so
 * there is no need to parse an escape grammar in order to defuse one, and no
 * risk of a novel sequence slipping past a parser that did not expect it.
 */
export function neutralise(text) {
  return String(text ?? '')
    .replace(C0_AND_DEL_G, (ch) => `<${ch.codePointAt(0).toString(16).padStart(2, '0')}>`)
    .replace(
      UNICODE_CONTROLS_G,
      (ch) => `<U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}>`,
    );
}

/** Does this string carry anything `neutralise` would rewrite? */
export function hasControls(text) {
  const value = String(text ?? '');
  return C0_AND_DEL.test(value) || UNICODE_CONTROLS.test(value);
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

  // Each introducer is classified separately: one value can carry a colour
  // change and a clipboard write, and naming only the first would understate it
  // by exactly the part that matters.
  if (value.includes(ESC)) {
    for (const body of value.split(ESC).slice(1)) {
      add(SEQUENCES.find(([pattern]) => pattern.test(body))?.[1]);
    }
  }
  if (BIDI.test(value)) add('reverses the direction the text is read in');
  if (INVISIBLE.test(value)) add('inserts characters that render as nothing at all');
  if (value.includes('\r')) add('returns the cursor to the start of the line, overwriting it');
  if (OTHER_C0.test(value)) add('carries control bytes a terminal may act on');

  return effects;
}
