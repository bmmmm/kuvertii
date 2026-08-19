// Clipboard access for the terminal build, via the tools each platform ships.
//
// Reading the clipboard rather than accepting a paste is what makes the CLI
// workable at all: a header is multi-line, indentation-sensitive and routinely
// tens of kilobytes, which is exactly the input a line-reading prompt mangles.
// Taking it from the clipboard sidesteps bracketed-paste quirks, auto-indent
// and buffer limits in one step.

import { execFileSync } from 'node:child_process';

const READERS = {
  darwin: [['pbpaste', []]],
  win32: [['powershell', ['-NoProfile', '-Command', 'Get-Clipboard -Raw']]],
  linux: [
    ['wl-paste', ['--no-newline']],
    ['xclip', ['-selection', 'clipboard', '-o']],
    ['xsel', ['--clipboard', '--output']],
  ],
};

const CLEARERS = {
  darwin: [['pbcopy', []]],
  win32: [['powershell', ['-NoProfile', '-Command', 'Set-Clipboard -Value $null']]],
  linux: [
    ['wl-copy', ['--clear']],
    ['xclip', ['-selection', 'clipboard']],
    ['xsel', ['--clipboard', '--clear']],
  ],
};

function candidates(table) {
  return table[process.platform] ?? table.linux;
}

/**
 * A read failure that is about the content, not about the tool.
 *
 * Overflowing maxBuffer raises ENOBUFS, and reporting that as "no clipboard
 * tool worked" sends the reader to the wrong repair: the tool worked, the
 * clipboard held more than any header reaches. Two different causes must not
 * share one sentence — and trying the next tool would be dishonest too, since
 * the next tool reads the same clipboard.
 */
export function contentFailure(error) {
  if (error?.code !== 'ENOBUFS') return null;
  return {
    error: 'The clipboard holds more than 32 MB, which no header reaches. Copy just the header block and try again.',
  };
}

/**
 * Read the clipboard.
 *
 * Returns {text} on success, or {error} naming what to install — several Linux
 * setups have none of the three tools, and saying so beats an empty result
 * that looks like an empty clipboard.
 */
export function readClipboard() {
  const tried = [];
  for (const [command, args] of candidates(READERS)) {
    try {
      // maxBuffer raised well past any header: DKIM signatures and long
      // Received chains push real-world messages past the 1 MB default.
      return { text: execFileSync(command, args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }) };
    } catch (error) {
      const aboutContent = contentFailure(error);
      if (aboutContent) return aboutContent;
      tried.push(`${command} (${error.code ?? error.message})`);
    }
  }
  return { error: `no clipboard tool worked — tried ${tried.join(', ')}` };
}

/**
 * Empty the clipboard.
 *
 * Best-effort and deliberately quiet about failure: this is hygiene, not a
 * guarantee. Clipboard history managers and cross-device sync keep their own
 * copies, and this removes none of them — see the note in the README.
 */
export function clearClipboard() {
  for (const [command, args] of candidates(CLEARERS)) {
    try {
      execFileSync(command, args, { input: '', stdio: ['pipe', 'ignore', 'ignore'] });
      return true;
    } catch {
      /* try the next one */
    }
  }
  return false;
}
