// Known bulk-sending platforms, keyed by registrable domain.
//
// This is not a reputation list. Its job is to turn "unknown domain" into
// "that is a mail platform, a redirect through it is ordinary" — context that
// stops an honest newsletter from looking like an attack, and stops a
// tracking hop from looking like a hack.

export const KIND_LABELS = {
  esp: 'bulk mail platform',
  shortener: 'link shortener',
};

const ESP = {
  // Infrastructure / delivery
  'greenarrowmail.com': 'GreenArrow',
  'sendgrid.net': 'Twilio SendGrid',
  'sendgrid.com': 'Twilio SendGrid',
  'amazonses.com': 'Amazon SES',
  'mailgun.org': 'Mailgun',
  'mailgun.net': 'Mailgun',
  'sparkpostmail.com': 'SparkPost',
  'mandrillapp.com': 'Mandrill',
  'postmarkapp.com': 'Postmark',
  'pstmrk.it': 'Postmark',
  'elasticemail.com': 'Elastic Email',
  'mailjet.com': 'Mailjet',
  'mjt.lu': 'Mailjet',
  'zcsend.net': 'Zoho Campaigns',
  'smtp2go.com': 'SMTP2GO',

  // Marketing / campaign suites
  'list-manage.com': 'Mailchimp',
  'mailchimp.com': 'Mailchimp',
  'mailchi.mp': 'Mailchimp',
  'mcsv.net': 'Mailchimp',
  'createsend.com': 'Campaign Monitor',
  'constantcontact.com': 'Constant Contact',
  'rs6.net': 'Constant Contact',
  'activehosted.com': 'ActiveCampaign',
  'sendinblue.com': 'Brevo',
  'brevo.com': 'Brevo',
  'sibautomation.com': 'Brevo',
  'getresponse.com': 'GetResponse',
  'aweber.com': 'AWeber',
  'awtrk.com': 'AWeber',
  'icptrack.com': 'iContact',
  'mailerlite.com': 'MailerLite',
  'klaviyomail.com': 'Klaviyo',
  'klaviyo.com': 'Klaviyo',
  'hubspotemail.net': 'HubSpot',
  'hubspot.com': 'HubSpot',
  'mktomail.com': 'Marketo',
  'marketo.com': 'Marketo',
  'eloqua.com': 'Oracle Eloqua',
  'en25.com': 'Oracle Eloqua',
  'rsys.net': 'Oracle Responsys',
  'responsys.net': 'Oracle Responsys',
  'exacttarget.com': 'Salesforce Marketing Cloud',
  'pardot.com': 'Salesforce Pardot',
  'braze.com': 'Braze',
  'iterable.com': 'Iterable',
  'customeriomail.com': 'Customer.io',
  'convertkit-mail.com': 'Kit (ConvertKit)',
  'getdrip.com': 'Drip',
  'emarsys.net': 'Emarsys',
  'dotdigital.com': 'Dotdigital',
  'dotmailer.com': 'Dotdigital',
  'infusionsoft.com': 'Keap',
  'keap.com': 'Keap',
  'omnisend.com': 'Omnisend',
  'moosend.com': 'Moosend',

  // Newsletter platforms
  'substack.com': 'Substack',
  'beehiiv.com': 'beehiiv',
  'ghost.io': 'Ghost',
  'buttondown.email': 'Buttondown',

  // Support / product messaging
  'intercom-mail.com': 'Intercom',
  'intercom.io': 'Intercom',
  'zendesk.com': 'Zendesk',
};

const SHORTENERS = {
  'bit.ly': 'Bitly',
  'tinyurl.com': 'TinyURL',
  't.co': 'X / Twitter',
  'ow.ly': 'Hootsuite',
  'buff.ly': 'Buffer',
  'rebrand.ly': 'Rebrandly',
  'is.gd': 'is.gd',
  'cutt.ly': 'Cutt.ly',
  'shorturl.at': 'ShortURL',
  'lnkd.in': 'LinkedIn',
};

/** Identify a registrable domain, or null when it is not a known platform. */
export function identifySender(registrableDomain) {
  const domain = String(registrableDomain ?? '').toLowerCase();
  if (ESP[domain]) return { name: ESP[domain], kind: 'esp' };
  if (SHORTENERS[domain]) return { name: SHORTENERS[domain], kind: 'shortener' };
  return null;
}

/**
 * Headers by which a sending platform keys a message back to one recipient.
 *
 * The domain tables above answer "who sent this". These answer the question the
 * recipient actually has: *which system holds a record about me, and what is in
 * it*. That turns an opaque hex string into something readable — the id itself
 * is meaningless, but knowing it is Marketo's lead id, and that the lead record
 * is what it points at, is not.
 *
 * Only headers whose meaning is documented or unambiguous in the wild are
 * listed. A wrong explanation is worse than a missing one, so anything guessed
 * from a plausible-looking name was left out; the generic patterns below catch
 * the rest without claiming to know the platform.
 */
const PLATFORM_HEADERS = [
  [/^x-sg-e?id$/i, 'Twilio SendGrid',
    'An encrypted blob holding the recipient address and message id. SendGrid decodes it to attribute every open, click and bounce.'],
  [/^x-mailgun-variables$/i, 'Mailgun',
    'Custom variables the sender attached to your copy, usually as JSON. Whatever they store about you travels in the message itself.'],
  [/^x-mailgun-tag$/i, 'Mailgun',
    'The campaign segment your address was filed under.'],
  [/^x-mandrill-user$/i, 'Mandrill',
    'The sending account this message was billed to.'],
  [/^x-mc-user$/i, 'Mailchimp',
    'The Mailchimp account whose audience list contains your address.'],
  [/^x-msfbl$/i, 'SparkPost',
    'A feedback-loop payload, base64 encoded. It carries the customer id and your recipient key so that a spam complaint can be traced back to you.'],
  [/^x-ses-(outgoing|configuration-set|message-tags)$/i, 'Amazon SES',
    'The sending configuration and any tags attached to your copy, used to route delivery events.'],
  [/^x-marketoid$/i, 'Marketo',
    'Your lead id in the sender\'s Marketo instance — the primary key of a record about you, not a random number.'],
  [/^x-hs-cid$/i, 'HubSpot',
    'Your contact id in the sender\'s HubSpot CRM.'],
  [/^x-roving-(id|campaignid)$/i, 'Constant Contact',
    'Constant Contact\'s identifier for your subscription to this list.'],
  [/^x-pm-message-id$/i, 'Postmark',
    'The send record for this individual message.'],
  [/^x-sfmc-stack$/i, 'Salesforce Marketing Cloud',
    'The Marketing Cloud instance holding the subscriber record for your address.'],
  [/^x-klaviyo/i, 'Klaviyo',
    'Klaviyo\'s profile and campaign keys for your address.'],
  [/^x-braze/i, 'Braze',
    'Braze\'s user and campaign keys for your address.'],
];

// Generic identifier headers, for platforms not named above. The word in the
// header name is the whole finding: something is counting subscribers, and you
// are one of them.
const GENERIC_ID_HEADER =
  /^x-(?:campaign|subscriber|recipient|contact|customer|member|list|job)[-_]?id$/i;

/**
 * Explain a header that identifies the recipient to a sending platform.
 *
 * Returns {platform, meaning} — platform is null when only the generic shape
 * was recognised, which is reported as an unattributed id rather than guessed.
 */
export function identifyPlatformHeader(headerName) {
  const name = String(headerName ?? '').trim();
  if (!name) return null;

  for (const [pattern, platform, meaning] of PLATFORM_HEADERS) {
    if (pattern.test(name)) return { platform, meaning };
  }

  if (GENERIC_ID_HEADER.test(name)) {
    return {
      platform: null,
      meaning: 'An identifier the sending system uses to tell your copy apart from everyone else\'s.',
    };
  }

  return null;
}
