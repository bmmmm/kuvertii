# kuvertii

Paste an email header, find out what it says about you.

**→ [bmmmm.github.io/kuvertii](https://bmmmm.github.io/kuvertii/)**

An email header is a shipping label with the interesting parts written in a
language nobody reads. Most of it is routine. Some of it is your own address,
encoded three or four times over, so that a reply, a bounce, a click or an
unsubscribe can be attributed back to you.

## What it finds

- **Who the message was really addressed to.** Your address is usually in `To:`
  once and encoded several more times — inside the unsubscribe token, in the
  bounce address, and in mailer fields stored *backwards* so they do not read as
  text at a glance. Addresses that appear only in encoded form are called out
  separately.
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
  free to be rewritten by anyone.
- **The route it took.** Read bottom-up, the first hop is the machine that
  generated the message — frequently an API injection from a datacentre rather
  than the brand on the envelope.
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
- A `Content-Security-Policy` in the page blocks every outbound request, so this
  is enforced by your browser rather than promised by the author.
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

- **A hit is a strong warning.** (Though ~1 in 200 lookups is a false alarm, by
  design — that is the price of shipping 390,000 domains in 530 KB.)
- **A miss is not an all-clear.** The snapshot is a point-in-time copy and
  phishing domains are often only hours old. The dangerous ones are precisely
  those no list has caught yet.

A reputation *API* would answer better, and was deliberately not used: querying
one means telling a third party which link you are looking at, and that link
contains your recipient id.

## In the terminal

The same analysis, rendered for a terminal:

```sh
kuvertii                     # press space to read the clipboard, q to quit
kuvertii message.eml         # a header file or a whole .eml
pbpaste | kuvertii           # or anything else on stdin
```

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
is a test asserting no module here can reach the network: following the link
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
node --test                          # 107 tests, stdlib only
node tools/build-blocklist.mjs       # writes data/ (gitignored, built in CI)
python3 -m http.server 8000          # then open localhost:8000
```

`tools/build-blocklist.mjs` also accepts a path to an already-downloaded feed,
so the build can be reproduced and inspected without network access.

Put local test headers in `samples/` — it is gitignored precisely because a real
header contains a real address.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

Bundled data: the phishing blocklist snapshot is derived from Phishing.Database,
MIT-licensed, fetched at build time and not redistributed in this repository.
