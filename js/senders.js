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
