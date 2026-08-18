import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  extractUrls, inspectUnsubscribeLink, registrableDomain, unwrapRedirect,
} from '../js/links.js';
import { CLICK_URL } from './fixtures.js';

const signal = (report, fragment) =>
  report.signals.find((s) => s.title.toLowerCase().includes(fragment.toLowerCase()));

test('registrable domain handles multi-part suffixes', () => {
  assert.equal(registrableDomain('news.example.org'), 'example.org');
  assert.equal(registrableDomain('a.b.shop.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('example.com'), 'example.com');
});

test('a click redirect gives up its real destination without being visited', () => {
  const { destination } = unwrapRedirect(CLICK_URL);
  assert.equal(
    destination,
    'https://news.example.org/subscription/directUnsubscribe?id=k7nzjxchawgg3ub7stnp65',
  );
});

test('urls are pulled out of angle-bracketed header values', () => {
  const urls = extractUrls('<https://a.example/unsub>, <mailto:off@a.example>');
  assert.deepEqual(urls, ['https://a.example/unsub', 'mailto:off@a.example']);
});

test('a plausible unsubscribe link reads as plausible', () => {
  const report = inspectUnsubscribeLink(CLICK_URL, {
    fromDomain: 'mail.example.email',
    hasOneClickHeader: true,
  });
  assert.equal(report.verdict, 'plausible');
  assert.ok(signal(report, 'unsubscribe endpoint'), 'recognises the opt-out path');
  assert.ok(signal(report, 'one-click'), 'points at the header-based alternative');
});

test('a login page behind an unsubscribe link is called out', () => {
  const report = inspectUnsubscribeLink('https://secure-example.test/account/login?u=1', {
    fromDomain: 'example.org',
  });
  assert.equal(report.verdict, 'suspicious');
  assert.ok(signal(report, 'asks for an account'));
});

test('userinfo disguise is detected', () => {
  const report = inspectUnsubscribeLink('https://newsletter.example.org@evil.test/unsub', {});
  assert.equal(report.verdict, 'suspicious');
  assert.ok(signal(report, 'credentials embedded'));
});

test('punycode lookalike hosts are flagged', () => {
  const report = inspectUnsubscribeLink('https://xn--exmple-cua.test/unsubscribe', {});
  assert.ok(signal(report, 'punycode'));
});

test('a bare IP host is flagged', () => {
  const report = inspectUnsubscribeLink('http://203.0.113.5/unsubscribe', {});
  assert.ok(signal(report, 'bare ip'));
  assert.ok(signal(report, 'unencrypted'));
});

test('a link shortener hiding an unsubscribe is treated as a caution', () => {
  const report = inspectUnsubscribeLink('https://bit.ly/3xYzAbc', { fromDomain: 'example.org' });
  const hit = signal(report, 'link shortener');
  assert.ok(hit);
  assert.equal(hit.level, 'caution');
});

test('a known bulk platform is explained rather than suspected', () => {
  const report = inspectUnsubscribeLink('https://example.list-manage.com/unsubscribe?u=9', {
    fromDomain: 'example.org',
  });
  const hit = signal(report, 'bulk mail platform');
  assert.ok(hit, 'Mailchimp recognised');
  assert.equal(hit.level, 'good');
});

test('mailto unsubscribes short-circuit as the harmless variant', () => {
  const report = inspectUnsubscribeLink('mailto:unsub@example.org?subject=off', {});
  assert.equal(report.verdict, 'plausible');
  assert.equal(report.signals.length, 1);
});

test('a malformed url does not throw', () => {
  const report = inspectUnsubscribeLink('not a url at all', {});
  assert.equal(report.verdict, 'suspicious');
});

// Domain boundaries come from the real Public Suffix List, baked in by
// tools/build-psl.mjs. What follows is the case that made it necessary: the
// hand-written approximation it replaced merged any two names sharing a
// multi-label suffix it had never heard of, and there were 5,487 of those.

test('a multi-label suffix is not itself a registrable domain', () => {
  assert.equal(registrableDomain('evil.com.sg'), 'evil.com.sg');
  assert.equal(registrableDomain('bank.com.sg'), 'bank.com.sg');
  assert.equal(registrableDomain('foo.bar.co.il'), 'bar.co.il');
  assert.equal(registrableDomain('a.b.c.pvt.k12.ma.us'), 'c.pvt.k12.ma.us');
});

test('the ordinary cases are unchanged', () => {
  assert.equal(registrableDomain('a.b.example.com'), 'example.com');
  assert.equal(registrableDomain('bbc.co.uk'), 'bbc.co.uk');
  assert.equal(registrableDomain('news.example.org'), 'example.org');
  // A TLD this list has never seen falls to the default rule, `*`.
  assert.equal(registrableDomain('host.invalidtld'), 'host.invalidtld');
});

test('a wildcard rule and its exception both apply', () => {
  // `*.ck` makes every `X.ck` a public suffix; `!www.ck` takes one back.
  assert.equal(registrableDomain('foo.bar.ck'), 'foo.bar.ck');
  assert.equal(registrableDomain('www.ck'), 'www.ck');
});

test('a hosting platform separates its tenants', () => {
  // The PRIVATE section. Without it these collapse to one domain, which is the
  // multi-label-suffix bug again on a suffix the registry did not sell.
  assert.equal(registrableDomain('alice.github.io'), 'alice.github.io');
  assert.equal(registrableDomain('evil.github.io'), 'evil.github.io');
  assert.equal(registrableDomain('a.blogspot.com'), 'a.blogspot.com');
});

test('a known bulk-mail platform still reduces to itself', () => {
  // js/senders.js is keyed by registrable domain, so widening the suffix list
  // must not split an ESP into per-customer domains it no longer recognises.
  for (const domain of ['sendgrid.net', 'list-manage.com', 'mailchimp.com', 't.co']) {
    assert.equal(registrableDomain(domain), domain);
  }
  assert.equal(registrableDomain('em1234.sendgrid.net'), 'sendgrid.net');
});

test('a name that is only a public suffix names no registrant', () => {
  assert.equal(registrableDomain('co.uk'), 'co.uk');
  assert.equal(registrableDomain('com.sg'), 'com.sg');
});

test('an unsubscribe on a different com.sg registrant is not "the sender domain"', () => {
  // End to end, because the reduction is what the verdict is built on: this
  // rendered as `✓ Unsubscribe stays on the sender domain — Both are com.sg`.
  const result = inspectUnsubscribeLink('https://evil.com.sg/unsubscribe?id=abc', {
    fromDomain: 'bank.com.sg',
  });
  const titles = result.signals.map((s) => s.title).join(' | ');
  assert.doesNotMatch(titles, /stays on the sender domain/);
  assert.match(titles, /unrelated domain/);
  assert.ok(!result.signals.some((s) => s.level === 'good' && /sender domain/.test(s.title)));
});
