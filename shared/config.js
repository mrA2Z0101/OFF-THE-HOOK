/*
 * Off the Hook shared configuration.
 *
 * Every scoring weight, verdict threshold and built-in list lives here so it can be
 * tuned in one place. Loaded as a classic script (content/background/options pages)
 * and as a CommonJS module (Node unit tests).
 */
(function (root, factory) {
  const mod = factory();
  if (typeof module === 'object' && module.exports) module.exports = mod;
  else (root.PhishGuard = root.PhishGuard || {}).config = mod;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Points each rule adds to the 0-100 risk score, and the severity shown to the user.
  // Scores are summed and capped at 100. Content rules add a few extra points per
  // additional distinct phrase (see keywordExtraPerMatch / keywordMaxExtra).
  const RULES = {
    // Sender
    display_name_mismatch:  { weight: 30, severity: 'high' },
    brand_impersonation:    { weight: 35, severity: 'high' },
    brand_in_subject:       { weight: 12, severity: 'medium' },
    sender_lookalike:       { weight: 40, severity: 'high' },
    sender_suspicious_tld:  { weight: 8,  severity: 'low' },
    freemail_impersonation: { weight: 25, severity: 'high' },
    reply_to_mismatch:      { weight: 15, severity: 'medium' },
    reply_to_freemail:      { weight: 25, severity: 'high' },
    display_name_lure:      { weight: 15, severity: 'medium' },
    no_subject_request:     { weight: 10, severity: 'medium' },
    unverified_request:     { weight: 15, severity: 'medium' }, // also floors the verdict at Suspicious
    // Your company (Settings > Your company)
    internal_compromised:   { weight: 30, severity: 'high' },
    company_impersonation:  { weight: 15, severity: 'medium' }, // high + 30 when sent from free mail
    // Learned from your reports (Settings > Your reports)
    reported_sender:        { weight: 60, severity: 'high' },
    reported_domain:        { weight: 40, severity: 'high' },
    reported_link:          { weight: 40, severity: 'high' },
    kw_learned:             { weight: 15, severity: 'medium' },
    freemail_request:       { weight: 20, severity: 'high' },
    freemail_disclaimer:    { weight: 10, severity: 'medium' },

    // Links
    link_text_mismatch:     { weight: 30, severity: 'high' },
    link_text_tracked:      { weight: 4,  severity: 'low' },
    link_script_scheme:     { weight: 35, severity: 'high' },
    link_ip:                { weight: 25, severity: 'high' },
    link_at_trick:          { weight: 30, severity: 'high' },
    link_lookalike:         { weight: 40, severity: 'high' },
    link_punycode:          { weight: 20, severity: 'medium' },
    link_shortener:         { weight: 10, severity: 'medium' },
    link_many_subdomains:   { weight: 10, severity: 'medium' },
    link_suspicious_tld:    { weight: 8,  severity: 'low' },
    link_insecure:          { weight: 4,  severity: 'low' },

    // Content (phrase lists live in data/keywords.json)
    kw_urgency:             { weight: 10, severity: 'medium' },
    kw_credential:          { weight: 20, severity: 'high' },
    kw_money:               { weight: 15, severity: 'medium' },
    kw_authority:           { weight: 12, severity: 'medium' },
    kw_prize:               { weight: 15, severity: 'medium' },
    kw_generic_greeting:    { weight: 5,  severity: 'low' },
    kw_ai_manipulation:     { weight: 30, severity: 'high' },
    kw_contact_request:     { weight: 15, severity: 'medium' },
    kw_custom:              { weight: 10, severity: 'medium' },

    // Attachments
    attachment_double_ext:  { weight: 40, severity: 'high' },
    attachment_risky:       { weight: 25, severity: 'high' },
    attachment_archive:     { weight: 10, severity: 'medium' },

    // Headers / other
    auth_fail:              { weight: 30, severity: 'high' },
    auth_weak:              { weight: 10, severity: 'medium' },
    // From raw header lines (Outlook "View message details" / Gmail "Show original").
    spoofed_internal:       { weight: 45, severity: 'high' },   // company address sent from outside; floors at phishing
    provider_verdict:       { weight: 35, severity: 'high' },   // Microsoft CAT:PHSH / impersonation / spoof / malware
    provider_spam:          { weight: 10, severity: 'medium' },
    return_path_mismatch:   { weight: 10, severity: 'medium' },
    // Warnings shown by Gmail/Outlook themselves (read from the page, never fetched).
    webmail_warning:        { weight: 25, severity: 'high' },
    webmail_first_contact:  { weight: 8,  severity: 'low' },
    image_only:             { weight: 8,  severity: 'low' },
    qr_link:                { weight: 12, severity: 'medium' }, // a QR code in the email opens a website
    // On a public list of active phishing / malware sites (BLOCKLIST_SOURCES). Floors the verdict at phishing.
    link_blocklisted:       { weight: 60, severity: 'high' },
    sender_blocklisted:     { weight: 60, severity: 'high' },
    // Contact memory: who you've had normal email from (stored as fingerprints on this computer).
    history_new_address:    { weight: 25, severity: 'medium' }, // known name, never-seen address/domain
    first_contact_request:  { weight: 12, severity: 'medium' }, // first email from a sender, and it asks for something
    first_contact:          { weight: 3,  severity: 'low' }
  };

  // score >= suspicious -> "Suspicious"; score >= phishing -> "Likely Phishing".
  const THRESHOLDS = {
    low:    { suspicious: 40, phishing: 70 },
    medium: { suspicious: 25, phishing: 55 },
    high:   { suspicious: 15, phishing: 40 }
  };

  const VERDICT_LABELS = {
    safe: 'Likely Safe',
    suspicious: 'Suspicious',
    phishing: 'Likely Phishing'
  };

  const SCORING = {
    keywordExtraPerMatch: 3,     // extra points per additional distinct phrase in one category
    keywordMaxExtra: 10,         // cap on those extra points per category
    trustedSenderMultiplier: 0.35, // score multiplier when the sender is on the allowlist
    maxMatchesPerFinding: 25
  };

  // AI blend: final = (1 - blendWeight) * ruleScore + blendWeight * aiScore
  const AI = {
    defaultBlendWeight: 0.5,
    truncatedBodyChars: 3000,
    fullBodyMaxChars: 20000,
    maxLinksSent: 30,
    maxHighlights: 10
  };

  const FREEMAIL_DOMAINS = [
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.ca', 'yahoo.fr', 'yahoo.de',
    'ymail.com', 'rocketmail.com', 'outlook.com', 'hotmail.com', 'hotmail.co.uk', 'hotmail.fr',
    'live.com', 'msn.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com', 'proton.me',
    'protonmail.com', 'pm.me', 'gmx.com', 'gmx.net', 'gmx.de', 'mail.com', 'yandex.com',
    'yandex.ru', 'zoho.com', 'zohomail.com', 'tutanota.com', 'tuta.io', 'mail.ru', 'inbox.com',
    'fastmail.com', 'hushmail.com', 'qq.com', '163.com', '126.com', 'web.de', 'comcast.net',
    'att.net', 'sbcglobal.net', 'verizon.net', 'cox.net', 'bellsouth.net', 'earthlink.net'
  ];

  const URL_SHORTENERS = [
    'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 's.id', 't.ly', 'v.gd',
    'bl.ink', 'short.io', 'lnkd.in', 'qrco.de', 'tiny.one', 'x.gd', 'shorte.st', 'adf.ly',
    'soo.gd', 'clck.ru', 'urlz.fr', 'surl.li', 'u.to'
  ];

  // Public lists of active phishing / malware sites, downloaded once a day (only the lists are
  // downloaded; nothing about your email is sent). Each can be switched off in Settings.
  const BLOCKLIST_SOURCES = [
    { id: 'phishdb', name: 'Phishing.Database', format: 'domains', home: 'https://github.com/mitchellkrogza/Phishing.Database',
      about: 'Active phishing domains',
      url: 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt' },
    { id: 'urlhaus', name: 'URLhaus (abuse.ch)', format: 'hosts', home: 'https://urlhaus.abuse.ch/',
      about: 'Sites spreading malware', url: 'https://urlhaus.abuse.ch/downloads/hostfile/' },
    { id: 'phisharmy', name: 'Phishing Army', format: 'domains', home: 'https://phishing.army/',
      about: 'Phishing domains gathered from PhishTank, OpenPhish, CERT.PL, urlscan.io and others',
      url: 'https://phishing.army/download/phishing_army_blocklist.txt' },
    { id: 'openphish', name: 'OpenPhish', format: 'urls', home: 'https://openphish.com/',
      about: 'The newest phishing links, refreshed every 12 hours', terms: 'Free for non-commercial use only',
      url: 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt' }
  ];

  // Big sites and shared services. The lists sometimes name one bad page on them
  // (s3.us-east-2.amazonaws.com/a-bucket/login.html, docs.google.com/forms/...), and because only
  // the site name is kept, that would flag every link to the whole service. These are never
  // added (along with SHARED_PLATFORMS and URL_SHORTENERS). "*." covers every subdomain;
  // "*" in the middle covers any run of letters, digits, dots or dashes.
  const BLOCKLIST_NEVER = [
    'google.com', '*.google.com', 'forms.gle', 'youtube.com', '*.youtube.com', 'googleapis.com', '*.googleapis.com', 'gstatic.com',
    'microsoft.com', '*.microsoft.com', 'microsoftonline.com', '*.microsoftonline.com', 'office.com', '*.office.com',
    'office365.com', '*.office365.com', 'live.com', '*.live.com', 'outlook.com', '*.outlook.com', 'sharepoint.com', '1drv.ms',
    'apple.com', '*.apple.com', 'icloud.com', '*.icloud.com',
    'amazon.com', '*.amazon.com', 's3.amazonaws.com', 's3*.amazonaws.com', 'amazonaws.com',
    'facebook.com', '*.facebook.com', 'instagram.com', '*.instagram.com', 'whatsapp.com', 'wa.me',
    'linkedin.com', '*.linkedin.com', 'x.com', 'twitter.com', 't.me', 'telegram.org', '*.telegram.org',
    'github.com', '*.github.com', 'githubusercontent.com', 'raw.githubusercontent.com', 'gitlab.com',
    'dropbox.com', '*.dropbox.com', 'dropboxusercontent.com', '*.dropboxusercontent.com', 'box.com', 'app.box.com',
    'wetransfer.com', 'we.tl', 'docusign.com', '*.docusign.com', 'docusign.net', '*.docusign.net', 'adobe.com', '*.adobe.com',
    'zoom.us', '*.zoom.us', 'webex.com', 'paypal.com', '*.paypal.com', 'yahoo.com', '*.yahoo.com',
    'wikipedia.org', '*.wikipedia.org', 'cloudflare.com', 'ipfs.io', 'dweb.link',
    'form.typeform.com', 'form.jotform.com', 'surveymonkey.com', '*.surveymonkey.com', 'canva.com', 'www.canva.com',
    'notion.so', 'linktr.ee', 'discord.com', 'discord.gg', 'cdn.discordapp.com'
  ];

  // Hosting platforms shared by millions of unrelated sites. A list naming one site on them
  // (x.weeblysite.com) must never flag the whole platform (weeblysite.com).
  const SHARED_PLATFORMS = [
    '000webhostapp.com', 'weeblysite.com', 'weebly.com', 'wixsite.com', 'wix.com', 'github.io', 'pages.dev', 'workers.dev',
    'r2.dev', 'vercel.app', 'netlify.app', 'web.app', 'firebaseapp.com', 'appspot.com', 'herokuapp.com', 'glitch.me',
    'blogspot.com', 'wordpress.com', 'godaddysites.com', 'squarespace.com', 'notion.site', 'sharepoint.com',
    'onmicrosoft.com', 'azurewebsites.net', 'windows.net', 'amazonaws.com', 'cloudfront.net', 'googleusercontent.com',
    'ipfs.io', 'myshopify.com', 'square.site', 'webflow.io', 'framer.app', 'carrd.co', 'jimdosite.com',
    'mystrikingly.com', 'typeform.com', 'jotform.com', 'surveymonkey.com', 'canva.site', 'dropbox.com', 'box.com',
    'wetransfer.com', 'docusign.net', 'adobe.com', 'google.com', 'microsoft.com', 'office.com', 'live.com', 'yolasite.com',
    'webnode.page', 'site123.me', 'replit.app', 'repl.co', 'ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'duckdns.org'
  ];

  // Email-service-provider click trackers and security link wrappers. A text/href
  // mismatch through one of these is common in legitimate marketing mail, so it is
  // reported as low severity instead of high.
  const TRACKER_DOMAINS = [
    'list-manage.com', 'mailchimp.com', 'mcusercontent.com', 'sendgrid.net', 'sendgrid.com',
    'mandrillapp.com', 'hubspotlinks.com', 'hubspot.com', 'hs-sites.com', 'mailgun.org',
    'sparkpostmail.com', 'exct.net', 'exacttarget.com', 'rs6.net', 'constantcontact.com',
    'klaviyo.com', 'klclick.com', 'klclick1.com', 'klclick3.com', 'mlsend.com', 'createsend.com',
    'awstrack.me', 'mimecast.com', 'mimecastprotect.com', 'urldefense.com', 'urldefense.proofpoint.com',
    'safelinks.protection.outlook.com', 'pardot.com', 'marketo.com', 'mktoweb.com', 'eloqua.com',
    'en25.com', 'sailthru.com', 'braze.com', 'customeriomail.com', 'ct.sendgrid.net', 'substack.com',
    'beehiiv.com', 'convertkit-mail.com', 'ck.page', 'mailerlite.com', 'brevo.com', 'sendinblue.com'
  ];

  const SUSPICIOUS_TLDS = [
    'zip', 'mov', 'xyz', 'top', 'click', 'link', 'country', 'gq', 'tk', 'ml', 'cf', 'ga', 'work',
    'support', 'rest', 'icu', 'cam', 'buzz', 'fit', 'cyou', 'sbs', 'monster', 'quest', 'bond',
    'cfd', 'lol', 'win', 'bid', 'loan', 'men', 'date', 'review', 'stream', 'download', 'racing',
    'kim', 'party', 'science', 'accountant', 'cricket', 'mom', 'beauty', 'hair', 'autos', 'boats'
  ];

  // Words attackers bolt onto brand names (paypal-security.com, amazonverify.net).
  const LOOKALIKE_WORDS = [
    'security', 'secure', 'support', 'verify', 'verification', 'login', 'logon', 'signin',
    'account', 'accounts', 'update', 'service', 'services', 'help', 'helpdesk', 'team', 'alert',
    'alerts', 'notice', 'billing', 'payment', 'pay', 'online', 'center', 'centre', 'id', 'auth',
    'confirm', 'recovery', 'unlock', 'bank', 'mail', 'web', 'portal', 'customer', 'care', 'info',
    'official', 'app', 'refund', 'claim', 'delivery', 'tracking', 'track', 'parcel', 'shipping'
  ];

  // Display-name words that suggest an organization's department or role account.
  // Used for free-mail checks and to confirm ambiguous brand names ("Chase Support").
  // Deliberately excludes "LLC", "Inc", "Office"... because many small businesses use Gmail.
  const ORG_WORDS = [
    'support', 'security', 'team', 'billing', 'account', 'accounts', 'admin', 'administrator',
    'helpdesk', 'help desk', 'it department', 'it support', 'customer service', 'customer care',
    'customer support', 'payroll', 'hr', 'human resources', 'accounting', 'finance department',
    'department', 'notification', 'notifications', 'alert', 'alerts', 'verification', 'bank',
    'card', 'card services', 'online', 'official', 'no-reply', 'noreply', 'webmaster',
    'postmaster', 'mail delivery', 'service center', 'fraud', 'fraud department', 'id'
  ];

  const EXEC_TITLES = [
    'ceo', 'cfo', 'coo', 'cto', 'cio', 'president', 'vice president', 'vp', 'chairman',
    'chairwoman', 'chair', 'managing director', 'executive director', 'director', 'founder',
    'owner', 'principal', 'superintendent', 'pastor', 'treasurer'
  ];

  // Executable / script / container types commonly abused for malware delivery.
  const RISKY_EXTENSIONS = [
    'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'msi', 'msix', 'msp', 'appx', 'appxbundle', 'cpl',
    'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'ps1', 'psm1', 'jar', 'reg', 'lnk', 'url',
    'iso', 'img', 'vhd', 'vhdx', 'html', 'htm', 'shtml', 'xhtml', 'svg', 'one', 'chm', 'scf',
    'docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm', 'iqy', 'slk'
  ];
  const ARCHIVE_EXTENSIONS = ['zip', 'rar', '7z', 'gz', 'tgz', 'tar', 'cab', 'arj', 'ace', 'z', 'xz', 'bz2', 'lzh'];
  // Extensions people expect to be harmless; used to spot "invoice.pdf.exe".
  const DECOY_EXTENSIONS = [
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'csv', 'jpg', 'jpeg',
    'png', 'gif', 'bmp', 'mp3', 'mp4', 'wav', 'mov', 'avi', 'odt', 'ods'
  ];

  // Default user settings. API keys are NOT here; they live in a separate "secrets"
  // object in chrome.storage.local (never storage.sync).
  const DEFAULT_SETTINGS = {
    sensitivity: 'medium',
    companyDomains: [],
    trustedDomains: [],
    customKeywords: [],
    highlight: {
      enabled: true,
      linkBadges: true,
      linkHover: true, // show the link check card when hovering a link in the email
      qr: true,        // read QR codes in the email's pictures and check where they go
      colors: { high: '#e53935', medium: '#fb8c00', low: '#fdd835', ai: '#ff2e88' }
    },
    ui: { showBadge: true, inboxTags: true }, // inboxTags: flag risky rows in the message list
    // Reply Guard: warn when a reply to a risky email contains a phone number, password, card or
    // bank details, codes; pauseSend stops the first Send so you can double-check.
    replyGuard: { enabled: true, pauseSend: true },
    // Download public scam-site lists daily and check links against them; each list can be turned off.
    blocklists: { enabled: true, sources: { phishdb: true, urlhaus: true, phisharmy: true, openphish: true } },
    history: { enabled: true },     // remember who you've had normal email from (fingerprints only)
    feedback: { saveText: false }, // store the email body with reports (for future learning)
    ai: {
      enabled: false,
      privacyAccepted: false,
      provider: 'ollama', // 'openai' | 'anthropic' | 'ollama'
      openai: { baseUrl: 'https://api.openai.com/v1', model: '' },
      anthropic: { model: 'claude-sonnet-5-5' },
      ollama: { baseUrl: 'http://localhost:11434', model: '' },
      sendFullBody: false,
      redact: true,
      maxTokens: 800,
      timeoutSec: 30,
      blendWeight: AI.defaultBlendWeight
    }
  };

  // Saved settings layered over the defaults (arrays replace, objects merge).
  function deepMerge(base, over) {
    if (Array.isArray(base)) return Array.isArray(over) ? over.slice() : base.slice();
    if (base && typeof base === 'object') {
      const out = {};
      for (const k of Object.keys(base)) out[k] = deepMerge(base[k], over && typeof over === 'object' ? over[k] : undefined);
      return out; // unknown keys from storage are dropped
    }
    return over === undefined || (over !== null && typeof over !== typeof base) ? base : over;
  }
  function mergeSettings(saved) { return deepMerge(DEFAULT_SETTINGS, saved || {}); }

  return {
    mergeSettings,
    RULES, THRESHOLDS, VERDICT_LABELS, SCORING, AI,
    FREEMAIL_DOMAINS, URL_SHORTENERS, TRACKER_DOMAINS, SUSPICIOUS_TLDS, LOOKALIKE_WORDS,
    ORG_WORDS, EXEC_TITLES, RISKY_EXTENSIONS, ARCHIVE_EXTENSIONS, DECOY_EXTENSIONS,
    BLOCKLIST_SOURCES, BLOCKLIST_NEVER, SHARED_PLATFORMS, DEFAULT_SETTINGS
  };
});
