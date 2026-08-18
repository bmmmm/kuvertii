#!/usr/bin/env node
// A development server for the page. `node tools/serve.mjs [port]`
//
// This replaces `python3 -m http.server`, which was the only Python in the
// project and was the wrong tool twice over.
//
// It binds to every interface by default — its own `--bind` help reads
// "(default: all interfaces)" — it generates directory listings, and it has no
// concept of a file it should not serve. Run in this repository it therefore
// publishes `.git/config`, `.github/` and `samples/` to whatever network the
// machine is on. That last one matters: README.md tells developers to keep real
// test headers in `samples/` precisely because a real header contains a real
// address, so the convenient dev command was serving exactly the material this
// project exists to protect.
//
// The rules here are the inverse. Loopback only, an explicit allowlist, no
// listings, and nothing whose path contains a dot-segment.

import { readFile, stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.argv[2] ?? 8000);

// What the published site consists of. Everything else in the repository —
// tests, tooling, package metadata, the git directory — is not part of the page
// and has no reason to be reachable from it.
const ALLOWED_DIRS = ['css', 'js', 'data'];
const ALLOWED_FILES = ['index.html', 'robots.txt', 'sitemap.xml'];

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.bin': 'application/octet-stream',
};

// The same policy index.html carries in a meta tag, sent as a real header.
//
// Delivered this way `frame-ancestors` is actually enforced, which it is not
// from a meta element — browsers ignore it there and say so in the console.
// GitHub Pages cannot set headers, so production keeps the meta version and
// lives without that one directive. Sending it properly here at least makes the
// difference deliberate rather than unnoticed.
export const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types 'none'",
].join('; ');

/**
 * Resolve a request path to a file, or null if it is not ours to serve.
 *
 * Three independent refusals rather than one clever check: anything carrying a
 * dot-segment, anything that escapes the root once normalised, and anything
 * outside the allowlist. A traversal has to defeat all three, and the allowlist
 * is the one that does not depend on getting path arithmetic right.
 */
export function resolve(urlPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath.split('?')[0]);
  } catch {
    return null; // malformed percent-encoding
  }

  const relative = decoded === '/' ? 'index.html' : decoded.replace(/^\/+/, '');
  if (!relative) return null;
  if (relative.split('/').some((segment) => segment.startsWith('.'))) return null;

  const normalised = normalize(relative);
  const absolute = join(ROOT, normalised);
  if (!absolute.startsWith(ROOT + sep)) return null;

  const [top] = normalised.split(sep);
  if (!ALLOWED_DIRS.includes(top) && !ALLOWED_FILES.includes(normalised)) return null;

  return absolute;
}

export function createDevServer() {
  return createServer(async (request, response) => {
    const send = (status, body, type = 'text/plain; charset=utf-8') => {
      response.writeHead(status, {
        'content-type': type,
        'content-security-policy': CSP,
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'cache-control': 'no-store',
      });
      response.end(body);
    };

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      send(405, 'Method not allowed\n');
      return;
    }

    const path = resolve(request.url ?? '/');
    if (!path) {
      send(404, 'Not found\n');
      return;
    }

    try {
      // Directories are refused rather than listed, and rather than quietly
      // resolving to an index file the allowlist never named.
      if ((await stat(path)).isDirectory()) {
        send(404, 'Not found\n');
        return;
      }
      send(200, await readFile(path), TYPES[extname(path)] ?? 'application/octet-stream');
    } catch {
      send(404, 'Not found\n');
    }
  });
}

// Only when run directly. The tests import this module so that they check the
// real path rules rather than a copy of them, and importing it must not open a
// socket.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  createDevServer().listen(PORT, '127.0.0.1', () => {
    process.stdout.write(`kuvertii on http://127.0.0.1:${PORT}/  (loopback only, ctrl-c to stop)\n`);
  });
}
