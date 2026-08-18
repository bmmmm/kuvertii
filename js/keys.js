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
// Splitting the chunk into keys is most of the job. The rest is bracketed
// paste, and the rest is why this holds state.
//
// Under bracketed paste a terminal wraps pasted text in `ESC [ 200 ~ …
// ESC [ 201 ~`, and that text is data the reader copied, not keys they pressed.
// A 30 KB header pasted into this loop would otherwise read as tens of
// thousands of keypresses, several hundred of them spaces, every one asking to
// re-read the clipboard — and any `q` inside it would quit.
//
// A 30 KB paste does not arrive in one read. It arrives in whatever pieces the
// pipe hands over, so the opening marker and the closing one land in different
// chunks, and a function that looks at one chunk at a time sees an unterminated
// paste followed by a chunk of what looks like typing. The first stateless
// version dropped the first piece correctly and then read the rest as keys,
// which is the failure it was written to prevent, arriving one read later.
//
// Control bytes are written as escapes rather than as the bytes themselves: a
// literal ESC in source is invisible in a diff and does not survive every
// copy-paste intact.

const PASTE_START = '\x1b[200~';
const PASTE_END = '\x1b[201~';

/**
 * A reader that remembers whether it is in the middle of a paste.
 *
 * One per session. `read` returns the keys in this chunk, with anything between
 * a start and an end marker removed however those markers are spread across
 * reads.
 */
export function createKeyReader() {
  let pasting = false;

  return {
    read(chunk) {
      let rest = String(chunk ?? '');
      let typed = '';

      while (rest) {
        if (pasting) {
          const end = rest.indexOf(PASTE_END);
          if (end === -1) return [...typed]; // the paste continues into the next read
          rest = rest.slice(end + PASTE_END.length);
          pasting = false;
          continue;
        }

        const start = rest.indexOf(PASTE_START);
        if (start === -1) { typed += rest; break; }
        typed += rest.slice(0, start);
        rest = rest.slice(start + PASTE_START.length);
        pasting = true;
      }

      // Codepoints rather than UTF-16 units, so an astral character counts once
      // rather than as two halves that match nothing.
      return [...typed];
    },

    /** Whether a paste is still open. Exposed so a test can say so. */
    get pasting() { return pasting; },
  };
}

/**
 * The keys up to and including the first one that quits.
 *
 * Resolving a promise does not stop a loop already running, so `q ` — quit,
 * then a space — quit and then went on to read the clipboard and empty it,
 * after the reader had said they were done. Deciding here rather than in the
 * TTY callback is also what makes the rule testable: the callback needs a
 * terminal, this needs an array.
 */
export function untilQuit(keys) {
  const out = [];
  for (const key of keys) {
    out.push(key);
    if (isQuit(key)) break;
  }
  return out;
}

/** Does this key ask to quit? q, Ctrl-C or Ctrl-D. */
export function isQuit(key) {
  return key === 'q' || key === '\u0003' || key === '\u0004';
}
