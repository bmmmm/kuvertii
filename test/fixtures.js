// Synthetic header, structurally modelled on a real bulk-mail message.
//
// Every address, id and hostname here is invented. The encodings are genuine —
// they were produced by the same transforms real senders use, so the decoders
// are tested against the shape they will actually meet.

export const RECIPIENT = 'maja.beispiel@example.org';

// `X-Mailer-Info` segments: plaintext reversed, base64'd, whole string reversed.
export const MAILER_SEGMENT = 'QbhpWYuIWZpNHcpVGbAVGeh1GcsVmLvJ3Z';
export const CAMPAIGN_SEGMENT = 'uV2dzxWZ0RXZyBDMuV2dzJDMyYDM4EzN';

// `List-Unsubscribe` token: NUL-separated fields behind an opaque prefix.
// High entropy by construction — it is base64 of invented test data, not a
// credential, and decodes to the fictional address above.
export const UNSUB_TOKEN =
  '1a2b3c4dMQBtYWphLmJlaXNwaWVsQGV4YW1wbGUub3JnAG5ld3NsZXR0ZXIwMG5ld3MyMDI2MDgxNwBuZXdzbGV0dGVyAA'; // gitleaks:allow

export const CLICK_URL =
  'https://track.example.email/click?e2260281/VaHR0cHM6Ly9uZXdzLmV4YW1wbGUub3JnL3N1YnNjcmlwdGlvbi9kaXJlY3RVbnN1YnNjcmliZQ/qP2lkPWs3bnpqeGNoYXdnZzN1YjdzdG5wNjU/s9n4e04f304';

// Note the deliberate quirks: the X-Mailer-Info-Extra value is folded across
// lines, and the Message-ID has lost its field name — both happen constantly
// when a header is copied out of a mail client.
export const BULK_HEADER = `From: Beispiel Newsletter <noreply@mail.example.email>
Subject: Herzlich willkommen!
To: Maja Beispiel <${RECIPIENT}>
Reply-To: kontakt@unrelated-hotel.example
Return-Path: <return-b443a1b34703-ddad3f5708=10@mail.example.email>
Original-Recipient: rfc822;${RECIPIENT}
X-Mailer-Info: 10.${MAILER_SEGMENT}.${CAMPAIGN_SEGMENT}
X-Mailer-Info-Extra: ddad3f5708:${MAILER_SEGMENT}
 ${CAMPAIGN_SEGMENT}
List-Unsubscribe: <https://mail.example.email/unsub/${UNSUB_TOKEN}>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
List-Id: Beispiel Wochenpost <reaktivierung-90d.mail.example.email>
List-Owner: <mailto:redaktion@mail.example.email>
List-Archive: <https://news.example.org/archiv>
X-SG-EID: sIS7wRUZL8h9HxBAOmSkPHhr
X-MarketoID: 903-ABC-123:45678:0
X-Campaign-Id: sommer-2026
Feedback-Id: FB0D2036:151900::GASV
Authentication-Results: dmarc.example.com; dmarc=pass header.from=mail.example.email
Authentication-Results: dkim.example.com; dkim=pass header.d=mail.example.email
Authentication-Results: spf.example.com; spf=pass smtp.mailfrom=mail.example.email
X-Dmarc-Policy: v=DMARC1; p=reject
DKIM-Signature: a=rsa-sha256; d=mail.example.email; s=default; t=1786988915; b=AAAA
X-Spam-Flag: yes
X-Apple-Action: JUNK/Junk
Received: from mta-in-02 by mailgateway-99 (mailgateway) with SMTP id abc-123
 for <${RECIPIENT}>; Mon, 17 Aug 2026 17:48:42 GMT
Received: from o1288.example-mail.com (o1288.example-mail.com [198.51.100.40])
 by mta-in-02 (Postfix) with ESMTPS id 20D5C18000DE
 for <${RECIPIENT}>; Mon, 17 Aug 2026 17:48:39 +0000 (UTC)
Received: from 203.0.113.116 by 198.51.100.107 with https; 17 Aug 2026 17:48:35 +0000
MIME-Version: 1.0
<mid-0a8b4b4903f2c04d71238613c8e4c12d@mail.example.email>
`;

// A message that reached a Microsoft 365 mailbox and was judged on the way in.
// Modelled on credential phishing: the envelope is unauthorised, the filter
// caught it, and the verdict fields say so in Microsoft's own vocabulary.
// The client IP and the timezone offset are the fields that describe whoever
// composed it — the same ones a reply would carry back about the reader.
export const MICROSOFT_HEADER = `From: "IT Support" <helpdesk@contoso-secure.example>
To: ${RECIPIENT}
Subject: Action required: verify your mailbox
Date: Mon, 17 Aug 2026 09:12:04 +0300
User-Agent: Microsoft Outlook 16.0.17328
X-Priority: 1 (Highest)
X-Originating-IP: [198.51.100.77]
Received-SPF: Fail (protection.outlook.com: domain of contoso-secure.example does not designate 198.51.100.77 as permitted sender)
Authentication-Results: protection.outlook.com; spf=fail; dkim=none; dmarc=fail
X-Forefront-Antispam-Report: CIP:198.51.100.77;CTRY:RU;LANG:en;SCL:9;SRV:;IPV:NLI;SFV:SPM;H:mail.contoso-secure.example;PTR:unknown;CAT:PHSH;SFTY:9.19
X-Microsoft-Antispam: BCL:0;
X-MS-Exchange-Organization-SCL: 9
`;
