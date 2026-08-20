#!/usr/bin/env node
// kuvertii on the command line.
//
// Same analysis as the page, rendered for a terminal. Input arrives one of
// three ways: from the clipboard on a keypress, from a file, or from stdin
// when something is piped in — never from a line prompt, which is the one
// method a folded, indentation-sensitive, 30 KB header does not survive.

import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { lookup, validate, verdictRows } from '../js/snapshot.js';
import { analyseBody } from '../js/body.js';
import { clearClipboard, readClipboard } from '../js/clipboard.js';
import { hashedAddressRows } from '../js/emailhash.js';
import { analyse } from '../js/findings.js';
import { createKeyReader, isQuit, untilQuit } from '../js/keys.js';
import { parseParts, readTally, splitMessage } from '../js/mime.js';
import { createRenderer } from '../js/terminal.js';
import { clippedNote, MAX_HEADER_BYTES, readHeaders } from '../js/unfold.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const DATA = join(HERE, '..', 'data');
const VERSION = createRequire(import.meta.url)('../package.json').version;

const USAGE = `kuvertii — read what an email says about you

  kuvertii                 press space to read the clipboard, q to quit
  kuvertii <file>          analyse a message, a header block, or a .eml file
  cat message.eml | kuvertii

Paste the whole "Show Original" / "View Source" output — header and body.
The body is described, never rendered: no image is fetched, no script runs,
no attachment is opened.

Options
  --headers-only  read the header block and leave the body unread
  --keep          do not empty the clipboard after a successful read
  --no-colour     plain output (also honoured: NO_COLOR)
  -h, --help      this text
  -v, --version   version

Nothing is sent anywhere. Links found in the message are printed defanged —
hxxps://example[.]com — so that no terminal turns them into something
clickable. Nothing in this program ever opens one.`;

// ------------------------------------------------------------------- blocklist

/**
 * Check hostnames against the baked-in snapshot, if there is one.
 *
 * Mirrors js/blocklist.js, reading from disk instead of fetching. Absence is
 * reported as unknown and never as clean — the browser build makes the same
 * distinction, and it matters more here, where the file is often simply not
 * built yet.
 */
async function checkHosts(hosts) {
  if (!hosts?.length) return [];

  let data;
  try {
    const meta = JSON.parse(await readFile(join(DATA, 'blocklist.json'), 'utf8'));
    const bytes = new Uint8Array(await readFile(join(DATA, 'blocklist.bin')));
    // The same refusal the page makes, and for the same reason. Mirroring the
    // lookup without it meant a truncated .bin reported every host as absent
    // from a snapshot it could not read — a miss phrased exactly like one the
    // filter had actually earned.
    data = validate(meta, bytes);
  } catch (error) {
    const missing = error?.code === 'ENOENT';
    return hosts.map((host) => ({
      host,
      unavailable: true,
      why: missing
        ? 'No snapshot on disk, so no check was made. Build one with: node tools/build-blocklist.mjs'
        : `The snapshot could not be read, so no check was made: ${error.message}`,
    }));
  }

  return hosts.map((hostname) => lookup(data, hostname));
}

/** Blocklist verdicts as finding items — the same rows the page renders. */
function blocklistItems(results) {
  return verdictRows(results);
}

// ---------------------------------------------------------------------- input

// --------------------------------------------------------------------- report

async function report(text, renderer, out = process.stdout, { headersOnly = false } = {}) {
  // The paste decides what this is: a header block, a whole message, or a
  // body that lost its header. js/mime.js makes that call for both front ends.
  const { headerText, bodyText, bodyOnly } = splitMessage(text);
  // Same ceiling the page applies, for the same reason: a header this long is
  // not one a mail server produced. Clipped rather than refused — the fields
  // worth reading sit at the top — but never in silence: the closing tally
  // reads as a complete account of the input, so it has to say when it is not.
  const block = headerText.length > MAX_HEADER_BYTES ? headerText.slice(0, MAX_HEADER_BYTES) : headerText;
  const clipped = clippedNote(headerText.length);
  const { headers } = readHeaders(block);

  let bodyRead = { parts: [], notes: [] };
  if (!headersOnly) {
    try {
      bodyRead = parseParts(headers, bodyText);
    } catch (error) {
      // parseParts promises to degrade rather than throw; this is the last
      // line of that promise, and it reports the failure as what it is.
      bodyRead = {
        parts: [],
        notes: [` The body could not be taken apart (${error.message}). That is a fault in this tool, not a fact about the message — the body findings are missing, not clear.`],
      };
    }
  }
  const { parts, notes } = bodyRead;

  const findings = [...analyse(headers), ...analyseBody(parts, { headers, bodyOnly })];
  if (!headers.length && !findings.length) {
    out.write(`${renderer.paint('\x1b[33m', `Nothing here parsed as a header block.${clipped}`)}\n`);
    return false;
  }
  if (!findings.length) {
    out.write(`Parsed ${headers.length} header fields, but found nothing noteworthy.${clipped}\n`);
    return true;
  }

  for (const finding of findings) {
    let rendered = finding;
    if (finding.hostsToCheck?.length) {
      const extra = blocklistItems(await checkHosts(finding.hostsToCheck));
      rendered = { ...rendered, items: [...rendered.items, ...extra] };
    }
    // The address-hash bridge — same shape as the blocklist one: the analysis
    // collected candidates synchronously, the digests happen here.
    if (finding.hashCheck) {
      const extra = await hashedAddressRows(finding.hashCheck);
      if (extra.length) rendered = { ...rendered, items: [...rendered.items, ...extra] };
    }
    out.write(`${renderer.renderFinding(rendered)}\n`);
  }

  // The tally is a complete account of what was read — and, under
  // --headers-only, of what deliberately was not.
  const read = readTally(headers.length, parts.length);
  const bodySkipped = headersOnly && /\S/.test(bodyText) ? ' The body was not read, as asked.' : '';
  out.write(`\n${renderer.paint('\x1b[2m', `${read}${bodySkipped}${notes.join('')}${clipped} Nothing left this machine.`)}\n`);
  return true;
}

// ----------------------------------------------------------------------- main

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on('data', (chunk) => chunks.push(chunk));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

/**
 * Interactive loop: space reads the clipboard, q quits.
 *
 * Raw mode is what makes a single keypress possible, and it is restored on
 * every exit path — a terminal left in raw mode stops echoing what is typed.
 */
async function interactive(renderer, { wipe, headersOnly }) {
  const { stdin, stdout } = process;
  stdout.write(`${renderer.paint('\x1b[2m', 'Copy a header, then press space to read it. q to quit.')}\n`);

  stdin.setRawMode(true);
  stdin.resume();
  stdin.setEncoding('utf8');

  const restore = () => {
    if (stdin.isTTY) stdin.setRawMode(false);
    stdin.pause();
  };

  return new Promise((resolve) => {
    let busy = false;
    // Whether the last empty clipboard is this tool's own doing. Without it the
    // loop reports "the clipboard is empty" straight after emptying it, which
    // reads as a fault rather than as the thing it just announced.
    let emptiedByUs = false;

    const handle = async (key) => {
      if (isQuit(key)) {
        restore();
        stdout.write('\n');
        resolve(0);
        return;
      }
      if (key !== ' ' || busy) return;
      busy = true;

      const { text, error } = readClipboard();
      if (error) {
        stdout.write(`${renderer.paint('\x1b[31m', error)}\n`);
        busy = false;
        return;
      }
      if (!text?.trim()) {
        stdout.write(`${renderer.paint('\x1b[33m', emptiedByUs
          ? 'The clipboard is still empty — this tool cleared it after the last read. Copy another header.'
          : 'The clipboard is empty. Copy a header first.')}\n`);
        busy = false;
        return;
      }

      emptiedByUs = false;

      // Leave raw mode while reporting so Ctrl-C works normally during output.
      stdin.setRawMode(false);
      const parsed = await report(text, renderer, process.stdout, { headersOnly });

      // Only wipe once something was actually read. Emptying it after a failed
      // parse would take away the header the reader still needs.
      if (parsed && wipe) {
        const cleared = clearClipboard();
        emptiedByUs = cleared;
        stdout.write(renderer.paint('\x1b[2m', cleared
          ? '\nClipboard emptied. Note that clipboard history tools and device sync keep their own copies.\n'
          : '\nCould not empty the clipboard.\n'));
      }

      stdout.write(`${renderer.paint('\x1b[2m', '\nSpace to read another, q to quit.')}\n`);
      stdin.setRawMode(true);
      busy = false;
    };

    // One data event can carry several keys — two typed quickly, an autorepeat,
    // or one arriving while the loop is busy. Comparing the whole chunk against
    // a single character dropped every key in it when that happened, q
    // included, and q is the only documented way out.
    //
    // The `quitting` check is the other half of that. Resolving the promise does
    // not stop a loop already running, so `q ` — quit, then a space — quit and
    // then went on to read the clipboard and empty it, after the reader had
    // said they were done. A key that arrives after the decision to leave is
    // not a key anybody pressed on purpose.
    const keys = createKeyReader();
    stdin.on('data', async (chunk) => {
      for (const key of untilQuit(keys.read(chunk))) await handle(key);
    });
  });
}

async function main(argv) {
  const args = argv.slice(2);
  if (args.includes('-h') || args.includes('--help')) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  if (args.includes('-v') || args.includes('--version')) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }

  const wipe = !args.includes('--keep');
  const headersOnly = args.includes('--headers-only');
  // Boolean(), not the raw value: process.stdout.isTTY is `undefined` rather
  // than false when stdout is a pipe, and `undefined` would trigger the
  // renderer's default parameter and switch colour back on for exactly the
  // case that must not have it.
  const colour = Boolean(
    !args.includes('--no-colour')
    && !args.includes('--no-color')
    && !process.env.NO_COLOR
    && process.stdout.isTTY,
  );
  const renderer = createRenderer({ colour, width: process.stdout.columns ?? 80 });
  const file = args.find((arg) => !arg.startsWith('-'));

  if (file) {
    const text = await readFile(file, 'utf8').catch((error) => {
      process.stderr.write(`Cannot read ${file}: ${error.message}\n`);
      return null;
    });
    if (text === null) return 1;
    return (await report(text, renderer, process.stdout, { headersOnly })) ? 0 : 1;
  }

  if (!process.stdin.isTTY) {
    const text = await readStdin();
    if (!text.trim()) {
      process.stderr.write('Nothing on stdin.\n');
      return 1;
    }
    return (await report(text, renderer, process.stdout, { headersOnly })) ? 0 : 1;
  }

  return interactive(renderer, { wipe, headersOnly });
}

// `process.exitCode`, never `process.exit()`.
//
// `process.exit` terminates immediately and discards whatever is still sitting
// in stdout's buffer. Writes to a pipe are asynchronous — a terminal takes them
// synchronously, which is why this only ever showed up when the output was
// redirected — so a report longer than one pipe buffer was cut off mid-sentence
// and the process still exited 0. A 601-hop chain came to 93,000 bytes on a
// terminal and 66,264 through `| cat`: 340 findings gone, stderr empty, exit
// code claiming success. Setting the code and letting the loop drain naturally
// is what makes the last line of a long report as reliable as the first.
//
// This works only because every path releases what it holds: `interactive`
// pauses stdin and leaves raw mode in `restore()`, and nothing else here keeps
// a handle open. A path that forgets would hang rather than truncate — louder,
// and caught by test/cli.test.js, which runs the real binary to completion.
main(process.argv).then(
  (code) => { process.exitCode = code ?? 0; },
  (error) => {
    process.stderr.write(`${error.stack ?? error}\n`);
    process.exitCode = 1;
  },
);
