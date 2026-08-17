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

import { has, normaliseHost } from '../js/bloom.js';
import { clearClipboard, readClipboard } from '../js/clipboard.js';
import { analyse } from '../js/findings.js';
import { createRenderer } from '../js/terminal.js';
import { parseHeaders } from '../js/unfold.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const DATA = join(HERE, '..', 'data');
const VERSION = createRequire(import.meta.url)('../package.json').version;

const USAGE = `kuvertii — read what an email header says about you

  kuvertii                 press space to read the clipboard, q to quit
  kuvertii <file>          analyse a header or .eml file
  cat header.txt | kuvertii

Options
  --keep         do not empty the clipboard after a successful read
  --no-colour    plain output (also honoured: NO_COLOR)
  -h, --help     this text
  -v, --version  version

Nothing is sent anywhere. Links found in the header are printed defanged —
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
  let meta;
  let bytes;
  try {
    meta = JSON.parse(await readFile(join(DATA, 'blocklist.json'), 'utf8'));
    bytes = new Uint8Array(await readFile(join(DATA, 'blocklist.bin')));
  } catch {
    return hosts.map((host) => ({ host, unavailable: true }));
  }

  return hosts.map((hostname) => {
    const host = normaliseHost(hostname);
    const labels = host.split('.');
    for (let i = 0; i + 1 < labels.length; i++) {
      const candidate = labels.slice(i).join('.');
      if (has(bytes, candidate, meta.bits, meta.hashes)) {
        return { host, listed: true, matched: candidate, meta };
      }
    }
    return { host, listed: false, meta };
  });
}

/** Blocklist verdicts as finding items, in the same shape the page renders. */
function blocklistItems(results) {
  return results.map((result) => {
    if (result.unavailable) {
      return {
        label: `Blocklist check unavailable (${result.host})`,
        value: 'No snapshot on disk, so no check was made. Build one with: node tools/build-blocklist.mjs',
        level: 'caution',
      };
    }
    if (result.listed) {
      return {
        label: `${result.matched} is on a phishing blocklist`,
        value: `Snapshot of ${result.meta.source.name}, ${result.meta.entries.toLocaleString('en')} domains, built ${result.meta.builtAt}. Treat this link as hostile.`,
        note: `Matching is probabilistic — roughly 1 in ${Math.round(1 / result.meta.falsePositiveRate)} lookups can be a false alarm.`,
        level: 'bad',
        emphasis: true,
      };
    }
    return {
      label: `${result.host} is not in the blocklist snapshot`,
      value: 'This is not a clean bill of health. The snapshot is a point-in-time copy, and phishing domains are typically hours old.',
    };
  });
}

// ---------------------------------------------------------------------- input

/**
 * Take the header block out of whatever was handed over.
 *
 * A .eml file is a header block followed by a blank line and a body. The
 * parser stops at that line anyway, but cutting first keeps a quoted `Subject:`
 * inside a reply from ever being read as a field.
 */
function headerBlock(text) {
  const end = text.search(/\r?\n\r?\n/);
  return end === -1 ? text : text.slice(0, end);
}

// --------------------------------------------------------------------- report

async function report(text, renderer, out = process.stdout) {
  const headers = parseHeaders(headerBlock(text));
  if (!headers.length) {
    out.write(`${renderer.paint('\x1b[33m', 'Nothing here parsed as a header block.')}\n`);
    return false;
  }

  const findings = analyse(headers);
  if (!findings.length) {
    out.write(`Parsed ${headers.length} header fields, but found nothing noteworthy.\n`);
    return true;
  }

  for (const finding of findings) {
    let rendered = finding;
    if (finding.hostsToCheck?.length) {
      const extra = blocklistItems(await checkHosts(finding.hostsToCheck));
      rendered = { ...finding, items: [...finding.items, ...extra] };
    }
    out.write(`${renderer.renderFinding(rendered)}\n`);
  }

  out.write(`\n${renderer.paint('\x1b[2m', `${headers.length} header fields read. Nothing left this machine.`)}\n`);
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
async function interactive(renderer, { wipe }) {
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

    stdin.on('data', async (key) => {
      if (key === 'q' || key === '\u0003' || key === '\u0004') { // q, Ctrl-C, Ctrl-D
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
        stdout.write(`${renderer.paint('\x1b[33m', 'The clipboard is empty.')}\n`);
        busy = false;
        return;
      }

      // Leave raw mode while reporting so Ctrl-C works normally during output.
      stdin.setRawMode(false);
      const parsed = await report(text, renderer);

      // Only wipe once something was actually read. Emptying it after a failed
      // parse would take away the header the reader still needs.
      if (parsed && wipe) {
        const cleared = clearClipboard();
        stdout.write(renderer.paint('\x1b[2m', cleared
          ? '\nClipboard emptied. Note that clipboard history tools and device sync keep their own copies.\n'
          : '\nCould not empty the clipboard.\n'));
      }

      stdout.write(`${renderer.paint('\x1b[2m', '\nSpace to read another, q to quit.')}\n`);
      stdin.setRawMode(true);
      busy = false;
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
    return (await report(text, renderer)) ? 0 : 1;
  }

  if (!process.stdin.isTTY) {
    const text = await readStdin();
    if (!text.trim()) {
      process.stderr.write('Nothing on stdin.\n');
      return 1;
    }
    return (await report(text, renderer)) ? 0 : 1;
  }

  return interactive(renderer, { wipe });
}

main(process.argv).then(
  (code) => process.exit(code ?? 0),
  (error) => {
    process.stderr.write(`${error.stack ?? error}\n`);
    process.exit(1);
  },
);
