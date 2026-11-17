/*
 * Scoreboard page: label emails as phishing / normal (.eml files or your saved reports), run
 * the current checks over them, and show catch rate, false alarms, and every miss.
 * Files are read on this computer only and nothing is stored.
 */
'use strict';
(function () {
  const PG = window.PhishGuard;
  const D = PG.domain;
  const $ = id => document.getElementById(id);
  const ext = !!(globalThis.chrome && chrome.runtime && chrome.runtime.id);
  const items = [];
  const seenReports = new Set();
  let filter = 'problems';
  let last = null;

  const word = document.querySelector('.ot-wordmark');
  word.addEventListener('error', () => word.closest('.ot-title').classList.add('no-img'));

  const load = f => fetch('../data/' + f).then(r => r.json());
  const depsPromise = (async () => {
    const [keywords, brands] = await Promise.all([load('keywords.json'), load('brands.json')]);
    let saved;
    try { if (ext) saved = (await chrome.storage.local.get('settings')).settings; } catch (e) { saved = undefined; }
    return { settings: PG.config.mergeSettings(saved), lists: { keywords, brands } };
  })();

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v; else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v); else el.setAttribute(k, v);
    }
    for (const c of children.flat()) if (c != null && c !== false) el.append(c);
    return el;
  }
  const status = t => { $('addStatus').textContent = t; };
  function counts() {
    $('phishCount').textContent = items.filter(i => i.label === 'phish').length;
    $('legitCount').textContent = items.filter(i => i.label === 'legit').length;
  }

  // Folder names decide the label when a whole folder is added.
  function labelFromPath(path) {
    const parts = String(path || '').toLowerCase().split('/').slice(0, -1);
    for (let i = parts.length - 1; i >= 0; i--) {
      if (/^(phish|phishing|scam|scams|spam|junk|bad|malicious)/.test(parts[i])) return 'phish';
      if (/^(normal|legit|legitimate|safe|good|ham|clean|real)/.test(parts[i])) return 'legit';
    }
    return null;
  }

  // QR codes in the email's pictures become links (like the live check in Gmail/Outlook).
  async function readQr(email) {
    for (const pic of email.pictures || []) {
      try {
        const bmp = await createImageBitmap(new Blob([pic.bytes], { type: pic.mime }));
        const k = Math.min(1, 1600 / Math.max(bmp.width, bmp.height));
        const c = document.createElement('canvas');
        c.width = Math.max(1, Math.round(bmp.width * k)); c.height = Math.max(1, Math.round(bmp.height * k));
        const ctx = c.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(bmp, 0, 0, c.width, c.height);
        const r = PG.qr.decode(ctx.getImageData(0, 0, c.width, c.height));
        const link = r && PG.qr.toLink(r.text);
        if (link) email.links.push({ text: '', href: link, qr: true });
      } catch (e) { /* not a picture the browser can read */ }
    }
    delete email.pictures;
    return email;
  }

  async function addFiles(files, label) {
    let added = 0, skipped = 0, unsorted = 0;
    for (const f of Array.from(files || [])) {
      if (!/\.eml$/i.test(f.name)) { skipped++; continue; }
      const lab = label || labelFromPath(f.webkitRelativePath);
      if (!lab) { unsorted++; continue; }
      try {
        const email = await readQr(PG.eml.parse(new Uint8Array(await f.arrayBuffer())));
        items.push({ label: lab, name: f.webkitRelativePath || f.name, source: 'file', email });
        added++;
      } catch (e) { skipped++; }
    }
    counts();
    status(`Added ${added} email${added === 1 ? '' : 's'}.` + (skipped ? ` Skipped ${skipped} file(s) that aren't .eml emails.` : '') +
      (unsorted ? ` ${unsorted} file(s) weren't in a "phish" or "normal" folder, so they were left out.` : ''));
    rerun();
  }

  async function addReports() {
    if (!ext) { status('Reports are only available when this page is opened from the extension.'); return; }
    const { feedback } = await chrome.storage.local.get('feedback');
    const reports = (feedback && Array.isArray(feedback.reports)) ? feedback.reports : [];
    let added = 0, noText = 0;
    for (const r of reports) {
      if (seenReports.has(r.id)) continue;
      if (!r.text) { noText++; continue; }
      seenReports.add(r.id);
      items.push({
        label: r.type === 'phish' ? 'phish' : 'legit', name: 'Report: ' + (r.subject || '(no subject)'), source: 'report',
        email: { from: r.sender, subject: r.subject, body: r.text, links: r.links || [], attachments: r.attachments || [] }
      });
      added++;
    }
    counts();
    status(reports.length
      ? `Added ${added} report${added === 1 ? '' : 's'}.` + (noText ? ` ${noText} report(s) don't include the email text, so they can't be re-checked (turn on "Also save the email text" in Settings → Your reports for future ones).` : '')
      : 'You have no reports yet. Use "It\'s phishing" / "It\'s safe" in the panel on an email.');
    rerun();
  }

  // Ask the background worker which sites in these emails are on the scam-site lists.
  async function blocklistFor(list) {
    if (!ext) return null;
    const hosts = new Set();
    const addHost = host => { if (!host) return; hosts.add(host); const reg = D.registrableDomain(host); if (reg) hosts.add(reg); };
    for (const it of list) {
      addHost(D.domainOfEmail(it.email.from && it.email.from.address));
      for (const l of it.email.links || []) {
        const p = D.parseUrl(l.href);
        if (p && /^https?:$/.test(p.protocol)) addHost(D.lower(D.unwrapRedirect(p).url.hostname));
      }
    }
    const hits = {};
    let enabled = false;
    const all = Array.from(hosts);
    for (let i = 0; i < all.length; i += 200) {
      const r = await chrome.runtime.sendMessage({ type: 'checkHosts', hosts: all.slice(i, i + 200) }).catch(() => null);
      if (r && r.ok) { enabled = r.enabled; Object.assign(hits, r.hits); }
    }
    return enabled ? { has: host => hits[String(host || '').toLowerCase()] || null } : null;
  }

  async function rerun() {
    if (!items.length) { $('results').replaceChildren(); last = null; return; }
    const deps = await depsPromise;
    const blocklist = await blocklistFor(items);
    const res = PG.scoreboard.run(items, { analyzer: PG.analyzer, settings: deps.settings, lists: Object.assign({}, deps.lists, blocklist ? { blocklist } : {}) });
    last = Object.assign(res, { blocklist: !!blocklist });
    render();
  }

  const OUTCOME = { caught: 'Caught', missed: 'Missed', ok: 'Correct', false_alarm: 'False alarm' };
  function render() {
    const { rows, stats, blocklist } = last;
    const cards = h('div', { class: 'stats-grid' },
      stats.phish ? h('div', { class: 'stat ' + (stats.catchRate >= 90 ? 'v-safe' : stats.catchRate >= 70 ? 'v-suspicious' : 'v-phishing') },
        h('div', { class: 'big', text: stats.catchRate + '%' }),
        h('div', { class: 'what', text: `Phishing caught: ${stats.caught} of ${stats.phish}` }),
        h('div', { class: 'more', text: `${stats.strict} rated Likely Phishing, ${stats.caught - stats.strict} Suspicious` })) : null,
      stats.legit ? h('div', { class: 'stat ' + (stats.falseRate <= 2 ? 'v-safe' : stats.falseRate <= 10 ? 'v-suspicious' : 'v-phishing') },
        h('div', { class: 'big', text: stats.falseRate + '%' }),
        h('div', { class: 'what', text: `False alarms: ${stats.falseAlarms} of ${stats.legit} normal emails` }),
        h('div', { class: 'more', text: `${stats.strictFalse} wrongly rated Likely Phishing` })) : null);

    const shown = rows.filter(r => filter === 'all' || (filter === 'problems' ? (r.outcome === 'missed' || r.outcome === 'false_alarm') : r.outcome === filter));
    const fbtn = (key, label) => h('button', { type: 'button', class: 'small', 'aria-pressed': String(filter === key), text: label, onclick: () => { filter = key; render(); } });
    const copy = h('button', { type: 'button', class: 'small', text: 'Copy summary' });
    copy.addEventListener('click', () => navigator.clipboard.writeText(PG.scoreboard.summary(stats, new Date().toLocaleDateString())).then(() => { copy.textContent = 'Copied'; }, () => {}));

    const table = h('table', {},
      h('thead', {}, h('tr', {}, ['Result', 'Verdict', 'Email', 'Main reasons'].map(t => h('th', { scope: 'col', text: t })))),
      h('tbody', {}, shown.slice(0, 500).map(r => h('tr', {},
        h('td', {}, h('span', { class: 'outcome ' + r.outcome, text: OUTCOME[r.outcome] }), h('span', { class: 'meta', text: r.label === 'phish' ? 'phishing' : 'normal' })),
        h('td', { class: 'verdict-cell ' + r.verdict, text: `${r.verdictLabel} · ${r.score}` }),
        h('td', { class: 'sub' }, h('strong', { text: r.subject || '(no subject)' }),
          h('span', { class: 'meta', text: ((r.from && (r.from.name ? r.from.name + ' <' + (r.from.address || '?') + '>' : r.from.address)) || 'unknown sender') }),
          h('span', { class: 'meta', text: r.name })),
        h('td', {}, r.reasons.length ? h('ul', { class: 'reasons' }, r.reasons.map(x => h('li', { text: x.title }))) : h('span', { class: 'meta', text: 'No warning signs found' }))))));

    $('results').replaceChildren(h('section', { 'aria-labelledby': 'res-h' },
      h('h2', { id: 'res-h', text: 'Results' }),
      cards,
      h('p', { class: 'help', text: 'Checked with your current settings' + (blocklist ? ' and the scam-site lists' : '') +
        ', but without what your reports taught it or your contact memory, so this shows what the checks catch on their own. Change a setting and the numbers update.' }),
      h('div', { class: 'filters' }, fbtn('problems', 'Misses & false alarms'), fbtn('missed', 'Missed'), fbtn('false_alarm', 'False alarms'), fbtn('all', 'All'), copy),
      shown.length ? h('div', { class: 'tablewrap' }, table) : h('p', { class: 'empty', text: filter === 'problems' ? 'No misses and no false alarms. 🎯' : 'Nothing here.' })
    ));
  }

  // ---- wiring ----
  let pickLabel = null;
  document.querySelectorAll('[data-pick]').forEach(b => b.addEventListener('click', () => { pickLabel = b.dataset.pick; $('files').click(); }));
  $('files').addEventListener('change', e => { addFiles(e.target.files, pickLabel); e.target.value = ''; });
  $('pickFolder').addEventListener('click', () => $('folder').click());
  $('folder').addEventListener('change', e => { addFiles(e.target.files, null); e.target.value = ''; });
  $('useReports').addEventListener('click', addReports);
  $('clearAll').addEventListener('click', () => { items.length = 0; seenReports.clear(); counts(); status(''); rerun(); });
  for (const zone of [$('phishDrop'), $('legitDrop')]) {
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('over'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('over'));
    zone.addEventListener('drop', e => { e.preventDefault(); zone.classList.remove('over'); addFiles(e.dataTransfer.files, zone.dataset.label); });
  }
  window.addEventListener('dragover', e => e.preventDefault());
  window.addEventListener('drop', e => e.preventDefault());

  // For dev/testing pages: add emails without a file picker.
  window.__offTheHookScore = { add: async (label, name, emlText) => { items.push({ label, name, source: 'file', email: await readQr(PG.eml.parse(emlText)) }); counts(); return rerun(); } };
})();
