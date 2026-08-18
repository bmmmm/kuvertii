# kuvertii

Paste an email header, find out what it says about you.

**→ [bmmmm.github.io/kuvertii](https://bmmmm.github.io/kuvertii/)**

An email header is a shipping label with the interesting parts written in a
language nobody reads. Most of it is routine. Some of it is your own address,
encoded three or four times over, so that a reply, a bounce, a click or an
unsubscribe can be attributed back to you.

## What it finds

- **Whether the header is trying to control the program reading it.** A `List-ID`
  can carry the escape sequence that writes your clipboard, a `X-Mailer` the one
  that turns text into a clickable link, and a bidi override can make a hostname
  whose bytes read `evil` display as somebody else's. All of it is rendered
  inert and none of it is deleted — no sender writes these by accident, so the
  attempt is itself the finding.
- **Whether the header contradicts itself.** Fields that may appear once, appearing
  twice; and a line like `De:` — a valid optional header no client displays —
  placed above the real `From:` so that whichever program reads first sees a
  different sender.
- **Whether you pasted the whole header.** A fragment does not fail loudly — it
  analyses fine and quietly answers a narrower question than you asked. When the
  fields every delivered message carries are absent, that is said first, before
  anything it qualifies.
- **Who the message was really addressed to.** Your address is usually in `To:`
  once and encoded several more times — inside the unsubscribe token, in the
  bounce address, and in mailer fields stored *backwards* so they do not read as
  text at a glance. Addresses that appear only in encoded form are called out
  separately.
- **Who else was shown your address.** Everyone named in `To` and `Cc` can read
  every other name there. A message sent to a crowd hands each of them the whole
  list, which is the most ordinary privacy failure in email and the least
  remarked upon — `Bcc` was available and went unused.
- **That your copy is unique.** Bulk mail is not sent to a list, it is sent to
  you specifically. VERP bounce addresses, `Feedback-ID`, and per-message
  tracking ids all key back to your address. Platform-specific identifiers are
  named for what they are — a `X-MarketoID` is your lead record, a `X-HS-Cid`
  is your entry in someone's CRM.
- **Which list you are on.** `List-ID` carries an identifier the sender chose
  and never expected anyone to read, which makes it the most candid line in the
  header: segment names like `reactivation-90d` state how you have been filed.
- **What the message says about the machine that wrote it.** Client IP, mail
  program with version, and the timezone offset in `Date:` — the same fields
  your own client writes into every message you send.
- **Where the unsubscribe link actually goes.** ESP click-trackers pack the
  destination into base64 path segments; kuvertii unpacks them and reports the
  real target, plus the structural tells that separate an opt-out from a
  credential trap — punycode lookalikes, `user@host` disguises, bare IPs,
  login-shaped destination paths.
- **What the authentication results are worth.** SPF, DKIM and DMARC answer
  whether a server may send for a domain. They never ask whether the mail is
  honest. Spam passes all three every day — and a signature can pass while
  covering only the first few hundred bytes of the message, leaving the rest
  free to be rewritten by anyone. Every result word each mechanism can produce
  gets its own sentence, because `spf=neutral` is a domain declining to assert
  and `spf=permerror` is a fault in that domain's own published record; a single
  description per mechanism reads as the pass case and states the opposite on a
  message that failed.
- **What Microsoft actually decided,** which is no longer the spam score. On a
  cloud mailbox `SCL` decides nothing — the threat category does, and
  `compauth`/`reason` record the identity verdict. `reason=010` means someone
  outside wrote as though they were a colleague. Verdicts that mean *filtering
  was skipped* — a safe-senders entry, an IP allow list, a mail flow rule — are
  surfaced as such rather than read as a clean bill.
- **The route it took.** Read bottom-up, the first hop is the machine that
  generated the message — frequently an API injection from a datacentre rather
  than the brand on the envelope. Where that hop names itself with an encoded
  identifier rather than a hostname, it is decoded: sending platforms label the
  connection with the account they are billing, so the sender's customer number
  travels in the routing.
- **The verdicts filters already reached.** Spam flags from every major
  provider, including Microsoft 365's own vocabulary — `SCL`, `BCL`, `SFV` and
  `CAT` are translated into words, and "filtering was skipped" is reported as
  the finding it is rather than mistaken for a clean bill.

Localised header labels are understood, so a paste out of a German, French,
Spanish, Italian or Dutch mail client works as-is (`An:`, `Antwort an:`, …).

## Privacy

Nothing you paste leaves the page.

- No server, no analytics, no storage — not `localStorage`, not `sessionStorage`,
  no cookies. The header lives in one variable and is gone when the tab closes.
- A `Content-Security-Policy` in the page allows exactly one destination — this
  origin, for the blocklist asset — and denies everything else by default, so
  this is enforced by your browser rather than promised by the author. Every
  source in that policy is checked against a per-directive allowlist in the
  tests, because the previous check looked for wildcards and third-party hosts
  and would have accepted `connect-src 'self' https:`, which permits the web. It also sets
  `require-trusted-types-for`, which makes any assignment of header text to a
  markup sink throw rather than render — the no-innerHTML rule becomes the
  browser's to keep rather than ours. (One directive in that policy does
  nothing: `frame-ancestors` is ignored when delivered in a `<meta>` element,
  and GitHub Pages cannot send headers. It is kept for any host that can, and
  not counted on.)
- Text taken from the header is stripped of characters that are instructions
  rather than text — terminal escapes, and the bidi overrides that would let a
  hostname reading `evil` be displayed as somebody else's. Their presence is
  reported as a finding, because no sender writes them by accident.
- **Verify it yourself:** load the page, turn off your network, and analyse a
  header. It works. Or watch the network tab — the only request after load is
  the blocklist asset, from this same origin.

### The blocklist

Unsubscribe destinations are checked against a snapshot of
[Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) (MIT,
~390,000 domains), rebuilt daily by CI and served as a Bloom filter from this
origin. The domain you are checking is never sent anywhere — the filter comes to
your browser, not the other way round.

Read the results asymmetrically, because the data is asymmetric:

- **A hit is a strong warning** — but a false alarm is likelier than the
  headline figure suggests, and the tool now says so beside each hit. The
  designed rate, ~1 in 200, is the rate of a single Bloom probe; a lookup walks
  up the labels and makes one probe per boundary. Measured against the shipped
  filter with 200,000 clean hosts per depth: 1 in 193 for a two-label name, 1 in
  96 for three, **1 in 65 for four** — which is the shape of the ESP click
  trackers this check is usually pointed at. That is the price of shipping
  390,000 domains in 530 KB.
- The builder refuses any entry that would tar more than itself. A lookup walks
  up the labels, so one feed line reading `co.uk` or `google.com` would flag
  every domain beneath it; public suffixes are rejected against the Public
  Suffix List and a short list of major providers by name. It also refuses a
  build that has changed size by more than a factor of two, in either
  direction, against a committed baseline — and records the sha256 of the feed
  it read. The baseline is committed rather than carried over from the previous
  build because that build output is gitignored: the check compared against a
  file CI never has, so it was skipped on every scheduled run until this was
  noticed. A guard that cannot run is now a build failure rather than a pass.
- **A miss is not an all-clear.** The snapshot is a point-in-time copy and
  phishing domains are often only hours old. The dangerous ones are precisely
  those no list has caught yet.

A reputation *API* would answer better, and was deliberately not used: querying
one means telling a third party which link you are looking at, and that link
contains your recipient id.

## In the terminal

The same analysis, rendered for a terminal:

```sh
node bin/kuvertii.js         # press space to read the clipboard, q to quit
node bin/kuvertii.js mail.eml   # a header file or a whole .eml
pbpaste | node bin/kuvertii.js  # or anything else on stdin
```

There is nothing to install. `npm link` puts it on your PATH as `kuvertii` if
you would rather type that; the package declares no dependencies and has no
lockfile, so nothing is fetched either way.

### Running it sandboxed

For a header you actively distrust, Node will enforce the privacy claim rather
than leaving it to us:

```sh
node --permission --allow-fs-read=. --allow-fs-read=mail.eml bin/kuvertii.js mail.eml
```

Under `--permission` the runtime denies network access, filesystem writes and
subprocesses unless each is granted. Measured on Node 26: a `fetch()` from
inside the process fails with `ERR_ACCESS_DENIED`, which turns "nothing leaves
this machine" from a design claim into one the runtime enforces. The file and
stdin modes need nothing else.

The interactive clipboard mode is the exception: reading the clipboard means
running `pbpaste` or `wl-paste`, so it needs `--allow-child-process`, and an
allowed child inherits none of the parent's restrictions. That is a real
weakening and worth naming rather than papering over — use the file or stdin
mode when it matters.

Input never comes from a line prompt. A header is folded, indentation-sensitive
and routinely tens of kilobytes, which is precisely what a prompt mangles —
reading the clipboard on a keypress sidesteps bracketed-paste quirks, editor
auto-indent and buffer limits in one step.

**Links are printed defanged** — `hxxps://example[.]com` — and this is not
decoration. Ghostty, iTerm2, WezTerm, Kitty and VS Code all scan output for URL
patterns and turn what they find into a click target; that is the terminal's
doing and no program can switch it off. Printing a phishing destination as
plain text would hand you the one action this tool exists to prevent. Email
addresses stay readable, since their dots carry the meaning and a `mailto:` is
harmless.

Redirects are still resolved by decoding the link, never by requesting it. A
`HEAD` request would resolve them more reliably, and that is exactly why there
is a test walking both import graphs and asserting that no module either build
loads can reach the network: following the link
would report your click to the tracker and confirm your address to a phisher.

### About emptying the clipboard

After a successful read the clipboard is emptied, unless you pass `--keep`.
Treat this as hygiene, not as a guarantee: clipboard history managers (Raycast,
Alfred, Maccy, Paste) and cross-device sync will already hold a copy, and
nothing here removes those. It is also skipped when nothing parsed, so a failed
read never costs you the header.

The phishing blocklist is read from `data/`, which is built by CI rather than
committed. Without it the check reports itself unavailable — never as clean.

## Related work

Header analysis is a well-served field, but almost all of it is written from
the sending side of the question. The established tools ask *is this sender
authentic, and why was this message delayed or filtered* — a mail
administrator's question. kuvertii asks what the same header says about the
person who received it, which is why it decodes recipient identifiers rather
than delivery diagnostics.

- **[Microsoft MHA](https://github.com/microsoft/MHA)** (MIT) — the most mature
  tool in the field: an Outlook add-in and web app that decodes the Microsoft
  365 anti-spam headers and the per-hop delivery delays. For diagnosing why a
  message was late or filtered inside Exchange, use this instead. Note the
  trade-offs it accepts to reach the header: the add-in requires
  `ReadWriteMailbox` permission on the mailbox, and it reports telemetry to
  Application Insights.
- **[emlAnalyzer](https://github.com/wahlflo/eml_analyzer)** (MIT) — a local
  Python CLI for whole `.eml` files: MIME structure, attachments, embedded URLs
  and remote-content trackers. Complementary rather than competing, since
  kuvertii deliberately never looks past the header block.
- **The hosted header analyzers** (MXToolbox, PowerDMARC and a dozen others) —
  they cover authentication and routing well, and several now run client-side.
  Deliberately unlinked here: a header is not anonymous, and sending one to a
  form is a decision worth making on purpose rather than by following a link
  from this page.

## Development

No build step, no dependencies. Node is used only to run the tests and to bake
the blocklist.

```sh
node --test                          # 258 tests, stdlib only
node tools/mutate.mjs                # breaks each promise, checks the suite notices
node tools/build-blocklist.mjs       # writes data/ (gitignored, built in CI)
node tools/build-psl.mjs             # refreshes js/psl.js (committed)
node tools/serve.mjs                 # then open 127.0.0.1:8000
```

The dev server is twenty lines of `node:http` rather than `python3 -m
http.server`, which binds to every interface by default, lists directories, and
has no notion of a file it should not serve — in this repository that means it
hands out `.git/config` and `samples/` to the local network. This one is
loopback-only and serves an allowlist.

`tools/build-blocklist.mjs` also accepts a path to an already-downloaded feed,
so the build can be reproduced and inspected without network access.

Put local test headers in `samples/` — it is gitignored precisely because a real
header contains a real address.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

Bundled data: the phishing blocklist snapshot is derived from Phishing.Database,
MIT-licensed, fetched at build time and not redistributed in this repository.
