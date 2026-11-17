/*
 * Scoreboard tests: reading .eml files (MIME parts, encodings, attachments, headers) and
 * counting catches, misses and false alarms.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory;
  else root.PhishGuardScoreCases = factory;
})(typeof globalThis !== 'undefined' ? globalThis : this, function defineScoreCases(env) {
  'use strict';
  const { test, assert, PG, lists, samples } = env;
  const b64 = s => { const bytes = new TextEncoder().encode(s); let bin = ''; for (const b of bytes) bin += String.fromCharCode(b); return btoa(bin); };

  const html = '<html><head><style>p{color:red}</style></head><body><p>Dear customer,</p><p>Your account has been suspended. ' +
    'To restore access, <a href="http://paypa1-security.com/login.php?id=1">https://www.paypal.com/signin</a> within 24 hours.</p>' +
    '<img src="cid:logo" width="120" height="40" alt="PayPal"><img src="https://t.example/p.gif" width="1" height="1">' +
    '<p>Caf&eacute; &amp; more &#8212; thanks</p></body></html>';
  const phishEml = [
    'Return-Path: <bounce@paypa1-security.com>',
    'From: =?UTF-8?B?' + b64('PayPal Sécurité') + '?= <service@paypa1-security.com>',
    'To: alex@example.com',
    'Subject: =?utf-8?Q?Your_account_has_been_suspended_=E2=9A=A0?=',
    'Authentication-Results: spf=fail smtp.mailfrom=paypa1-security.com; dkim=none; dmarc=fail header.from=paypa1-security.com',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="outer"',
    '',
    'This is a multi-part message.',
    '--outer',
    'Content-Type: multipart/alternative; boundary="alt"',
    '',
    '--alt',
    'Content-Type: text/plain; charset="utf-8"',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    'Dear customer, your account has been suspended. Visit https://paypa1-security.com/l=',
    'ogin today.',
    '--alt',
    'Content-Type: text/html; charset="utf-8"',
    'Content-Transfer-Encoding: base64',
    '',
    b64(html).replace(/(.{76})/g, '$1\r\n'),
    '--alt--',
    '--outer',
    'Content-Type: application/octet-stream; name="invoice.pdf.exe"',
    "Content-Disposition: attachment; filename*=utf-8''Rechnung%20%C3%BCber.pdf.exe",
    'Content-Transfer-Encoding: base64',
    '',
    b64('MZ fake'),
    '--outer--',
    'epilogue text that is not part of the email',
    ''
  ].join('\r\n');

  test('Email files: multipart, base64, quoted-printable, encoded headers and attachments', () => {
    const e = PG.eml.parse(phishEml);
    assert.deepEqual(e.from, { name: 'PayPal Sécurité', address: 'service@paypa1-security.com' });
    assert.equal(e.subject, 'Your account has been suspended ⚠');
    assert.ok(/Dear customer,\nYour account has been suspended/.test(e.body), e.body);
    assert.ok(/Café & more — thanks/.test(e.body), 'entities decoded');
    assert.ok(!/color:red|epilogue/.test(e.body), 'no styles or epilogue');
    assert.deepEqual(e.links, [{ text: 'https://www.paypal.com/signin', href: 'http://paypa1-security.com/login.php?id=1' }]);
    assert.equal(e.imageCount, 1, 'tracking pixel ignored');
    assert.deepEqual(e.imageAlts, ['PayPal']);
    assert.deepEqual(e.attachments, ['Rechnung über.pdf.exe']);
    assert.ok(/dmarc=fail/.test(e.authResults));
    assert.ok(e.headers['return-path']);
    const r = PG.analyzer.analyze(e, { sensitivity: 'medium' }, lists);
    assert.equal(r.verdict, 'phishing');
  });

  test('Email files: plain-text emails get their links from the text', () => {
    const e = PG.eml.parse('From: Jane Doe <jane@acmesteel.example>\nSubject: Drawings\nContent-Type: text/plain; charset=us-ascii\n\nHi Alex,\nThe drawings are at https://share.acmesteel.example/q3 now.\nJane\n');
    assert.equal(e.from.address, 'jane@acmesteel.example');
    assert.deepEqual(e.links.map(l => l.href), ['https://share.acmesteel.example/q3']);
    assert.ok(/^Hi Alex,/.test(e.body));
  });

  test('Scoreboard: counts catches, misses and false alarms, problems first', () => {
    const items = [
      { label: 'phish', name: 'paypal.eml', email: samples.phishing.paypalLookalike },
      { label: 'phish', name: 'quiet.eml', email: { from: { name: 'Pat', address: 'pat@vendor.example' }, subject: 'Hello', body: 'Lunch?', links: [] } },
      { label: 'legit', name: 'amazon.eml', email: samples.legitimate.amazonShipping },
      { label: 'legit', name: 'alarm.eml', email: samples.phishing.ceoGiftCards }
    ];
    const { rows, stats } = PG.scoreboard.run(items, { analyzer: PG.analyzer, settings: {}, lists });
    assert.deepEqual([stats.phish, stats.caught, stats.legit, stats.falseAlarms], [2, 1, 2, 1]);
    assert.equal(stats.catchRate, 50);
    assert.equal(rows[0].outcome, 'missed');
    assert.equal(rows[1].outcome, 'false_alarm');
    assert.ok(/caught: 1 of 2 \(50%\)/.test(PG.scoreboard.summary(stats)));
  });
});
