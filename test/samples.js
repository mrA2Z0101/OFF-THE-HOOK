/* Sample emails used by the unit tests and the dev demo page. All names and domains are fictional. */
(function (root, factory) {
  const mod = factory();
  if (typeof module === 'object' && module.exports) module.exports = mod;
  else root.PhishGuardSamples = mod;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const phishing = {
    paypalLookalike: {
      from: { name: 'PayPal Security', address: 'service@paypa1-security.com' },
      replyTo: ['help.paypal.desk@gmail.com'],
      subject: 'Your account has been suspended',
      body: 'Dear customer,\n\nWe noticed unusual activity on your account. Your account has been suspended.\n' +
        'To restore access, verify your account within 24 hours or it will be permanently deleted.\n\n' +
        'https://www.paypal.com/signin\n\nThank you,\nPayPal Security Team',
      links: [{ text: 'https://www.paypal.com/signin', href: 'http://paypa1-security.com/login.php?id=88231' }],
      attachments: [],
      imageCount: 1
    },

    ceoGiftCards: {
      from: { name: 'Michael Torres CEO', address: 'm.torres.office@gmail.com' },
      subject: 'Quick favor',
      body: "Hi,\n\nAre you at your desk? I need a quick favor. I'm in a meeting and can't talk right now.\n" +
        'I need you to purchase 5 Apple gift cards ($200 each) for a client today. Keep this confidential, ' +
        "I'll explain later. Scratch the back and send me photos of the codes.\n\nMichael\nSent from my iPhone",
      links: [],
      attachments: []
    },

    malwareAttachment: {
      from: { name: 'Accounts Payable', address: 'ap@northwind-billing.xyz' },
      subject: 'Overdue invoice #44721',
      body: 'Hello,\n\nPlease see the attached overdue invoice and remit payment today to avoid a late fee.\n\nRegards,\nAccounts',
      links: [],
      attachments: ['Invoice_44721.pdf.exe', 'supporting-docs.zip']
    },

    homoglyphApple: {
      from: { name: 'Apple', address: 'no-reply@apple-id-verify.com' },
      subject: 'Your Apple ID has been locked',
      body: 'Your Apple ID has been locked for security reasons. Click the link below to verify your identity.\n\nVerify Apple ID',
      links: [{ text: 'Verify Apple ID', href: 'https://xn--80ak6aa92e.com/verify' }],
      attachments: []
    },

    microsoftLinks: {
      from: { name: 'Microsoft 365 Admin', address: 'admin@m365-alerts.net' },
      subject: 'Action required: mailbox storage is full',
      body: 'Your mailbox storage is full. Messages will be deleted.\nSign in to Office 365 to upgrade your storage.\n' +
        'Or use the backup portal. Short link: bit.ly/3xYz',
      links: [
        { text: 'Sign in to Office 365', href: 'https://www.microsoft.com@evil-host.ru/office365' },
        { text: 'backup portal', href: 'http://192.168.10.5/login' },
        { text: 'bit.ly/3xYz', href: 'https://bit.ly/3xYz' }
      ],
      attachments: []
    },

    // Real-world sample (Oct 2026) that v1.0 scored "Likely Safe". Recipient removed.
    contactInfoScam: {
      from: { name: 'CONTACT INFO UPDATE -- Awaiting your response now !!!', address: 'companygroupfile843@gmail.com' },
      subject: '',
      body: '--\nHi\nI’m on my alternative phone - what’s your main mobile number?"\nGratitude. Get Outlook for iOS\n\n' +
        '• This message, sent by e-mail or fax, and any documents transmitted with it are property of PFCU. It may contain ' +
        'confidential, proprietary and/or legally privileged information, and is intended solely for the use of the individual ' +
        'or entity to whom this message is addressed. If you are not one of the named recipient(s) or otherwise have reason to ' +
        'believe that you have received this message in error, please notify the sender and delete this message immediately. ' +
        'Please note that even in the most secure environments, e-mails are susceptible to tampering and unauthorized access. ' +
        'Therefore, we shall not be responsible or liable for the accuracy or the proper and complete transmission of the ' +
        'information contained in this e-mail.',
      links: [],
      attachments: [],
      providerWarnings: [{ level: 'low', text: "You don't often get email from companygroupfile843@gmail.com" }]
    },

    qrOnly: {
      from: { name: 'HR Department', address: 'hr-benefits@benefits-update.top' },
      subject: 'Benefits enrollment',
      body: 'Scan the QR code to update your benefits.',
      links: [],
      attachments: [],
      imageCount: 1,
      imageAlts: ['QR code']
    },

    authFail: {
      from: { name: 'Chase', address: 'alerts@chase.com' },
      subject: 'Unusual sign-in activity',
      body: 'We detected unusual sign-in activity. Confirm your identity to keep using online banking.',
      links: [{ text: 'Confirm now', href: 'https://chase-secure-verify.com/id' }],
      attachments: [],
      authResults: 'mx.google.com; spf=fail (google.com: domain of alerts@chase.com does not designate 203.0.113.9 as permitted sender) smtp.mailfrom=alerts@chase.com; dkim=none; dmarc=fail (p=REJECT) header.from=chase.com'
    }
  };

  const legitimate = {
    amazonShipping: {
      from: { name: 'Amazon.com', address: 'shipment-tracking@amazon.com' },
      subject: 'Your Amazon.com order of "USB-C Cable" has shipped!',
      body: 'Hello Alex,\n\nYour package is on the way and will arrive Thursday, October 9.\n\nTrack package\n\n' +
        'Order #112-4471925-1182633\nWe hope to see you again soon.\namazon.com',
      links: [
        { text: 'Track package', href: 'https://www.amazon.com/progress-tracker/package/ref=pe_123?orderId=112-4471925' },
        { text: 'amazon.com', href: 'https://www.amazon.com/' }
      ],
      attachments: [],
      imageCount: 4
    },

    googleSecurity: {
      from: { name: 'Google', address: 'no-reply@accounts.google.com' },
      subject: 'Security alert',
      body: "A new sign-in on Windows\n\nalex@example.com\n\nWe noticed a new sign-in to your Google Account on a Windows device. " +
        "If this was you, you don't need to do anything. If not, we'll help you secure your account.\n\nCheck activity",
      links: [
        { text: 'Check activity', href: 'https://accounts.google.com/AccountChooser?Email=alex@example.com&continue=https://myaccount.google.com/alert/nt/1' },
        { text: 'https://myaccount.google.com/notifications', href: 'https://myaccount.google.com/notifications' }
      ],
      attachments: [],
      imageCount: 1
    },

    newsletter: {
      from: { name: 'The Weekly Digest', address: 'news@digest.example.org' },
      subject: 'This week: five ideas for your garden',
      body: 'Welcome to this week\'s issue. We look at raised beds, drip irrigation, native plants, composting and ' +
        'fall bulbs. Each article includes step-by-step photos and a shopping list. Read more on our website ' +
        'www.example.org. You are receiving this because you subscribed. Unsubscribe at any time.',
      links: [
        { text: 'Read more', href: 'https://example.us21.list-manage.com/track/click?u=abc&id=def' },
        { text: 'www.example.org', href: 'https://example.us21.list-manage.com/track/click?u=abc&id=xyz' },
        { text: 'Unsubscribe', href: 'https://example.us21.list-manage.com/unsubscribe?u=abc' }
      ],
      attachments: [],
      imageCount: 3
    },

    coworker: {
      from: { name: 'Jane Doe', address: 'jane.doe@acmesteel.example' },
      subject: 'Q3 shop drawings',
      body: 'Hi Alex,\n\nAttached are the Q3 shop drawings and the updated schedule. Let me know if the connection ' +
        'details on sheet E-4 look right to you.\n\nThanks,\nJane',
      links: [],
      attachments: ['Q3 schedule.xlsx', 'Shop drawings rev B.pdf']
    }
  };

  return { phishing, legitimate };
});
