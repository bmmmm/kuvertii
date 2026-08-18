// What a terminal actually delivers when someone presses a key.
//
// A raw-mode `data` event is not a keypress. It is whatever bytes had arrived
// by the time the read happened, which is usually one key and occasionally
// several — two keys typed quickly, a key that arrives while the program is
// busy, an autorepeat, or a terminal that batches. Comparing the whole chunk
// against `'q'` therefore works right up until it does not: send `' q'` in a
// single write and the chunk equals neither `' '` nor `'q'`, both keys are
// dropped, and the only documented way out of the loop goes with them.
//
// Splitting the chunk into keys is the whole job, and it has one wrinkle worth
// naming. Under bracketed paste a terminal wraps pasted text in
// `ESC [ 200 ~ … ESC [ 201 ~`, and that text is data the reader copied, not
// keys they pressed. A 30 KB header pasted into this loop would otherwise read
// as tens of thousands of keypresses, several hundred of them spaces, every one
// asking to re-read the clipboard. The paste is dropped whole.
//
// This program never enables bracketed paste, so the markers only appear when
// something else in the terminal turned it on. Handling them costs one regex
// and removes a failure mode that would be baffling to diagnose.
//
// Control bytes are written as escapes rather than as the bytes themselves: a
// literal ESC in source is invisible in a diff and does not survive every
// copy-paste intact.

const PASTE = /\x1b\[200~[\s\S]*?(?:\x1b\[201~|$)/g;

/**
 * The keys in one raw-mode chunk, in order.
 *
 * Codepoints rather than UTF-16 units, so an astral character counts once
 * rather than as two halves that match nothing.
 */
export function keypresses(chunk) {
  return [...String(chunk ?? '').replace(PASTE, '')];
}

/** Does this key ask to quit? q, Ctrl-C or Ctrl-D. */
export function isQuit(key) {
  return key === 'q' || key === '\u0003' || key === '\u0004';
}
