/*
 * Known scam-site lists and contact memory: the list format, lookups, and how the analyzer
 * uses them (including what must never be flagged).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory;
  else root.PhishGuardIntelCases = factory;
})(typeof globalThis !== 'undefined' ? globalThis : this, function defineIntelCases(env) {
  'use strict';
  const { test, assert, PG, lists } = env;
  const BL = PG.blocklist;
  const ids = r => r.findings.map(f => f.id);
  const has = (r, id) => assert.ok(ids(r).includes(id), `expected "${id}", got [${ids(r).join(', ')}]`);
  const hasNot = (r, id) => assert.ok(!ids(r).includes(id), `did not expect "${id}" (${ids(r).join(', ')})`);

  const listText = '# comment\nevil-login.top\npaypa1-verify.com\nsites.google.com\nweeblysite.com\nphish-1.weeblysite.com\nWWW.Shouty-Case.NET\n\nbad host!\n';
  const hostsText = '# URLhaus\n127.0.0.1\tmalware-drop.example\n127.0.0.1\tevil-login.top\n0.0.0.0 203.0.113.9\n';
  const set = BL.build([{ name: 'Phish list', hosts: BL.parse(listText, 'domains') }, { name: 'Malware list', hosts: BL.parse(hostsText, 'hosts') }]);
  const blocklist = BL.create(BL.deserialize(BL.serialize(set)));
  const analyze = (email, settings, extra) => PG.analyzer.analyze(email, Object.assign({ sensitivity: 'medium' }, settings), Object.assign({ blocklist }, lists, extra));
  const mail = (href, from) => ({ from: from || { name: 'Billing', address: 'billing@vendor-mail.example' }, subject: 'Invoice', body: 'Please see your invoice.', links: [{ text: 'View invoice', href }] });

  test('Lists: both formats parse, junk lines are skipped, duplicates keep the first list', () => {
    assert.deepEqual(BL.parse(listText, 'domains'), ['evil-login.top', 'paypa1-verify.com', 'sites.google.com', 'weeblysite.com', 'phish-1.weeblysite.com', 'www.shouty-case.net']);
    assert.deepEqual(BL.parse(hostsText, 'hosts'), ['malware-drop.example', 'evil-login.top', '203.0.113.9']);
    assert.equal(set.n, 8, 'evil-login.top is in both lists but stored once');
    assert.equal(blocklist.has('evil-login.top'), 'Phish list');
    assert.equal(blocklist.has('malware-drop.example'), 'Malware list');
    assert.equal(blocklist.has('www.paypa1-verify.com'), 'Phish list', 'www. is ignored');
    assert.equal(blocklist.has('shouty-case.net'), null, 'only the listed host');
    assert.equal(blocklist.has('example.com'), null);
  });

  test('Lists: link lists (OpenPhish) keep the site name; big shared services never go in', () => {
    const CONFIG = PG.config;
    const skip = BL.neverMatcher([].concat(CONFIG.BLOCKLIST_NEVER, CONFIG.SHARED_PLATFORMS, CONFIG.URL_SHORTENERS));
    const urls = [
      'https://kukoinjlogn.webflow.io/', 'http://user:pw@Evil-Login.TOP:8080/a?b=1', 'https://sundram786.github.io/Spotify-Clone/',
      'https://s3.us-east-2.amazonaws.com/a-bucket/login.html', 'https://contract-quote.s3.us-east-2.amazonaws.com/x.html',
      'https://docs.google.com/forms/d/e/1FAIpQ/viewform', 'https://www.dropbox.com/scl/fi/abc', 'https://bit.ly/3xyz',
      'https://www.facebook.com/some-page', 'https://github.io/', 'https://weebly.com/', 'not a url', 'ftp://files.bad-host.example/x'
    ].join('\n');
    assert.deepEqual(BL.parse(urls, 'urls', skip),
      ['kukoinjlogn.webflow.io', 'evil-login.top', 'sundram786.github.io', 'contract-quote.s3.us-east-2.amazonaws.com', 'files.bad-host.example']);
    assert.ok(!skip('google.com.secure-login.top') && !skip('microsoft-support.top') && !skip('www.paypa1.com'), 'look-alikes are not protected');
    assert.ok(skip('www.paypal.com') && skip('login.microsoftonline.com') && skip('s3-website-us-east-1.amazonaws.com'));
    assert.deepEqual(BL.parse('sites.google.com\nevil-login.top\n', 'domains', skip), ['evil-login.top'], 'filter applies to every list');
  });

  test('Lists: a link to a listed site makes the email Likely Phishing', () => {
    const r = analyze(mail('https://evil-login.top/o365'));
    has(r, 'link_blocklisted');
    assert.equal(r.verdict, 'phishing');
    assert.ok(r.links[0].checks.some(c => c.ok === false && /active phishing/.test(c.text)));
    const sub = analyze(mail('https://secure.paypa1-verify.com/x'));
    has(sub, 'link_blocklisted');
  });

  test('Lists: official brands, shared platforms, trusted and company sites are never flagged', () => {
    hasNot(analyze(mail('https://sites.google.com/view/our-team')), 'link_blocklisted');          // listed, but official Google
    hasNot(analyze(mail('https://our-bakery.weeblysite.com/')), 'link_blocklisted');               // platform listed as a whole
    has(analyze(mail('https://phish-1.weeblysite.com/login')), 'link_blocklisted');                 // the one listed site on it
    hasNot(analyze(mail('https://evil-login.top/x'), { trustedDomains: ['evil-login.top'] }), 'link_blocklisted');
    hasNot(analyze(mail('https://paypa1-verify.com/'), { companyDomains: ['paypa1-verify.com'] }), 'link_blocklisted');
  });

  test('Lists: a sender on a list is flagged; free-mail domains are not', () => {
    const r = analyze({ from: { name: 'IT', address: 'it@malware-drop.example' }, subject: 'Update', body: 'Install the update.', links: [] });
    has(r, 'sender_blocklisted');
    assert.equal(r.verdict, 'phishing');
    const freemail = BL.create(BL.build([{ name: 'x', hosts: ['gmail.com'] }]));
    hasNot(PG.analyzer.analyze({ from: { name: 'Jo', address: 'jo@gmail.com' }, subject: 'Hi', body: 'Hi', links: [] }, {}, Object.assign({ blocklist: freemail }, lists)), 'sender_blocklisted');
  });

  // ---- contact memory ----
  const known = { learned: 120, addrSeen: 0, addrEstablished: false, nameCount: 14, nameAddrKnown: false, nameDomains: { 'acmesteel.example': 14 } };
  const ask = (from, extra) => analyze({ from, subject: 'Quick favor', body: 'Are you at your desk? I need you to buy gift cards for a client today.', links: [] }, {}, Object.assign({ history: known }, extra));

  test('Contacts: a familiar name on a free-mail address is a high warning', () => {
    const r = ask({ name: 'Kevin Smith', address: 'kevin.smith.office@gmail.com' });
    has(r, 'history_new_address');
    const f = r.findings.find(x => x.id === 'history_new_address');
    assert.equal(f.severity, 'high');
    assert.ok(/acmesteel\.example/.test(f.explanation) && /14 normal emails/.test(f.explanation), f.explanation);
    assert.ok(r.verdict !== 'safe');
  });

  test('Contacts: a familiar name on another business domain is a medium warning; the usual domain is fine', () => {
    const other = analyze({ from: { name: 'Kevin Smith', address: 'kevin@ks-consulting.example' }, subject: 'Lunch', body: 'Lunch at noon?', links: [] }, {}, { history: known });
    assert.equal(other.findings.find(x => x.id === 'history_new_address').severity, 'medium');
    assert.equal(other.verdict, 'suspicious', 'floored at Suspicious');
    const usual = analyze({ from: { name: 'Kevin Smith', address: 'k.smith@acmesteel.example' }, subject: 'Lunch', body: 'Lunch at noon?', links: [] }, {}, { history: known });
    hasNot(usual, 'history_new_address');
    const est = analyze({ from: { name: 'Kevin Smith', address: 'kevin@ks-consulting.example' }, subject: 'Lunch', body: 'Lunch at noon?', links: [] }, {},
      { history: Object.assign({}, known, { addrSeen: 5, addrEstablished: true, nameAddrKnown: true }) });
    hasNot(est, 'history_new_address');
    assert.ok(est.notes.some(n => /5 earlier emails/.test(n)));
  });

  test('Contacts: first-time sender asking for something, only after enough mail is learned', () => {
    const fresh = { learned: 120, addrSeen: 0, addrEstablished: false, nameCount: 0, nameAddrKnown: false, nameDomains: {} };
    has(ask({ name: 'Pat Doe', address: 'pat@unknown-vendor.example' }, { history: fresh }), 'first_contact_request');
    const early = ask({ name: 'Pat Doe', address: 'pat@unknown-vendor.example' }, { history: Object.assign({}, fresh, { learned: 12 }) });
    hasNot(early, 'first_contact_request');
    hasNot(early, 'first_contact');
    const plain = analyze({ from: { name: 'Pat Doe', address: 'pat@unknown-vendor.example' }, subject: 'Hello', body: 'Nice to meet you at the expo.', links: [] }, {}, { history: fresh });
    assert.equal(plain.findings.find(x => x.id === 'first_contact').severity, 'low');
    assert.equal(plain.verdict, 'safe');
  });

  test('Contacts: an inbox row from a familiar name on a new free-mail address gets a tag', () => {
    const r = PG.analyzer.analyzePreview({ from: { name: 'Kevin Smith', address: 'kevin.smith.office@gmail.com' }, subject: 'Quick favor', body: 'Are you at your desk?' },
      { sensitivity: 'medium' }, Object.assign({ history: known }, lists));
    assert.ok(r.verdict !== 'safe');
    assert.ok(r.reasons.some(x => x.id === 'history_new_address'));
  });
});
