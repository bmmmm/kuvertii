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
