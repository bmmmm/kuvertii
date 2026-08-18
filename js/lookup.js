// Lookup tables keyed by text taken out of a header.
//
// An ordinary object literal inherits from `Object.prototype`, which means it
// answers to keys nobody put in it. `SPAM_VERDICTS['constructor']` is not
// undefined — it is a function — and every table in this project is looked up
// with a string the sender chose. Left alone, that renders as
//
//   ✗ Safety verdict constructor
//     Flagged as function Object() { [native code] }.
//
// which is a verdict this tool invented, printed in red, on the authority of a
// header field. Nothing is escalated by it — the levels come from literal
// comparisons elsewhere — but a security tool that can be made to state a
// finding it did not compute has lost something worth more than the bug.
//
// A null prototype ends the class rather than the instance: an unknown key
// returns undefined, and every call site already has a branch for that, because
// unknown verdicts were always possible.

/**
 * Build a lookup that answers only for the keys it was given.
 *
 * Use this for every table whose key comes from the header, and a plain object
 * for tables keyed by our own identifiers — the distinction is the point, and
 * it should stay visible at the definition.
 */
export function table(entries) {
  return Object.assign(Object.create(null), entries);
}

/** An empty accumulator safe to fill with keys out of a header. */
export function emptyTable() {
  return Object.create(null);
}
