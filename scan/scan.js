/*
 * File checker page. Reads dropped/chosen files on this computer, runs shared/filecheck.js,
 * reads QR codes in any pictures, and shows a verdict card per file. Nothing is uploaded or
 * stored, and the file is never opened or run.
 */
'use strict';
(function () {
  const PG = window.PhishGuard;
  const FC = PG.filecheck;
  const $ = id => document.getElementById(id);
  const MAX_READ = 100 * 1024 * 1024;

  const VERDICT = {
    danger: { cls: 'v-phishing', icon: '✕', label: 'Dangerous file', advice: "Don't open this file. Delete it, and if it came by email, report the email to IT." },
    caution: { cls: 'v-suspicious', icon: '!', label: 'Be careful', advice: 'Only open it if you were expecting it from someone you trust. Never click "Enable content" or sign in to anything it opens.' },
    ok: { cls: 'v-safe', icon: '✓', label: 'No warning signs found', advice: "Off the Hook didn't find any of the tricks it checks for. That doesn't prove the file is safe: if you weren't expecting it, check with the sender first." }
  };
  const LINK_VERDICT = {
    danger: { cls: 'v-phishing', icon: '✕', label: 'Dangerous link inside', advice: "Opening the file itself is unlikely to harm your computer, but a link or QR code in it goes to a dangerous site. Don't visit it, don't scan it, and report the email to IT." },
    caution: { cls: 'v-suspicious', icon: '!', label: 'Check the links', advice: "The file looks harmless, but its links need care. Only follow them if you were expecting this file, and never sign in from them." }
  };
  const RISK_LABEL = { danger: 'Dangerous', caution: 'Check', ok: 'Looks normal' };
  const SOURCE_LABEL = { qr: 'QR code', link: 'Link', text: 'Written on the page', form: 'Form sends to', remote: 'Loaded when opened', redirect: 'Redirects to' };

  const word = document.querySelector('.ot-wordmark');
  word.addEventListener('error', () => word.closest('.ot-title').classList.add('no-img'));

  // Link checks use the same brand list, company domains and trusted senders as email checks.
  const load = f => fetch('../data/' + f).then(r => r.json());
  const depsPromise = (async () => {
    const [keywords, brands] = await Promise.all([load('keywords.json'), load('brands.json')]);
    let saved;
    try { if (globalThis.chrome && chrome.storage && chrome.storage.local) saved = (await chrome.storage.local.get('settings')).settings; } catch (e) { saved = undefined; }
    return { analyzer: PG.analyzer, settings: PG.config.mergeSettings(saved), lists: { keywords, brands } };
  })();

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v; else if (k === 'text') el.textContent = v; else el.setAttribute(k, v);
    }
    for (const c of children.flat()) if (c != null && c !== false) el.append(c);
    return el;
  }
  const size = n => n < 1024 ? n + ' bytes' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
  const hex = buf => Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');

  // Pixels for QR reading: decoded pictures (PNG, JPEG...) or raw PDF image samples.
  async function pixelsOf(img) {
    if (img.pixels) return img.pixels;
    try {
      const bmp = await createImageBitmap(new Blob([img.bytes], { type: img.mime }));
      const k = Math.min(1, 1600 / Math.max(bmp.width, bmp.height));
      const w = Math.max(1, Math.round(bmp.width * k)), hgt = Math.max(1, Math.round(bmp.height * k));
      const canvas = document.createElement('canvas');
      canvas.width = w; canvas.height = hgt;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.drawImage(bmp, 0, 0, w, hgt);
      if (bmp.close) bmp.close();
      return ctx.getImageData(0, 0, w, hgt);
    } catch (e) { return null; }
  }

  // Ask the background worker which of these sites are on the scam-site lists (null if off).
  async function blocklistFor(urls) {
    if (!(globalThis.chrome && chrome.runtime && chrome.runtime.id) || !urls.length) return null;
    const D = PG.domain, hosts = new Set();
    for (const u of urls) {
      const p = D.parseUrl(u);
      if (!p || !/^https?:$/.test(p.protocol)) continue;
      const host = D.lower(D.unwrapRedirect(p).url.hostname);
      hosts.add(host);
      hosts.add(D.registrableDomain(host));
    }
    const r = await chrome.runtime.sendMessage({ type: 'checkHosts', hosts: Array.from(hosts).filter(Boolean).slice(0, 200) }).catch(() => null);
    return r && r.ok && r.enabled ? { has: h => r.hits[String(h || '').toLowerCase()] || null } : null;
  }

  function card(name) {
    const el = h('section', { class: 'result pending', 'aria-busy': 'true' },
      h('div', { class: 'verdict v-pending' }, h('span', { class: 'vicon', 'aria-hidden': 'true' }, h('span', { class: 'spin' })),
        h('div', {}, h('div', { class: 'vlabel', text: 'Checking…' }), h('div', { class: 'vscore fname', text: name }))));
    $('results').prepend(el);
    return el;
  }

  function render(el, rep, sha) {
    // When the only problems are links / QR codes, the file itself isn't the danger.
    const v = rep.linkOnly && rep.verdict !== 'ok' ? LINK_VERDICT[rep.verdict] : VERDICT[rep.verdict] || VERDICT.ok;
    el.className = 'result ' + v.cls;
    el.removeAttribute('aria-busy');
    const findings = h('ul', { class: 'checks', 'aria-label': 'What Off the Hook found' });
    for (const f of rep.findings) {
      findings.append(h('li', { class: 'fail ' + f.severity },
        h('span', { class: 'm', 'aria-hidden': 'true', text: f.severity === 'low' ? 'i' : '✗' }),
        h('span', {}, f.title, f.detail ? h('span', { class: 'detail', text: f.detail }) : null)));
    }
    if (!rep.findings.length) findings.append(h('li', { class: 'pass' }, h('span', { class: 'm', 'aria-hidden': 'true', text: '✓' }), h('span', { text: 'None of the dangerous features Off the Hook looks for' })));

    const links = rep.links.slice().sort((a, b) => ({ danger: 0, caution: 1, ok: 2 }[a.risk] - { danger: 0, caution: 1, ok: 2 }[b.risk]));
    const linkList = links.length ? [
      h('h3', { text: `Web addresses in the file (${links.length})` }),
      h('ul', { class: 'links' }, links.slice(0, 25).map(l => h('li', {},
        h('span', { class: 'risk ' + l.risk, text: RISK_LABEL[l.risk] }),
        h('span', { class: 'src', text: SOURCE_LABEL[l.source] || 'Link' }),
        h('span', { class: 'dom', text: l.domain || l.display }),
        l.flags.length ? h('span', { class: 'why', text: l.flags.join(' · ') }) : null))),
      links.length > 25 ? h('p', { class: 'k', text: `…and ${links.length - 25} more.` }) : null
    ] : [];

    const copy = h('button', { type: 'button', class: 'small', text: 'Copy' });
    copy.addEventListener('click', () => navigator.clipboard.writeText(sha).then(() => { copy.textContent = 'Copied'; }, () => {}));

    el.replaceChildren(...[
      h('div', { class: 'verdict ' + v.cls },
        h('span', { class: 'vicon', 'aria-hidden': 'true', text: v.icon }),
        h('div', {}, h('div', { class: 'vlabel', text: v.label }),
          h('div', { class: 'vscore' }, h('span', { class: 'fname', text: rep.name }), ` · ${rep.type.label} · ${size(rep.size)}`))),
      h('p', { class: 'note verdict-color', text: v.advice }),
      findings,
      ...linkList,
      rep.notes.length ? h('ul', { class: 'more-notes' }, rep.notes.map(n => h('li', { text: n }))) : null,
      sha ? h('div', { class: 'hash' }, 'SHA-256 fingerprint (to look the file up in a malware database):', h('code', { text: sha }), copy) : null
    ].filter(Boolean));
  }

  let queue = Promise.resolve();
  function handle(files) {
    for (const f of Array.from(files || [])) {
      const el = card(f.name);
      queue = queue.then(() => checkOne(f, el)).catch(err => {
        el.className = 'result v-suspicious';
        el.replaceChildren(h('p', { class: 'note warn', text: `Couldn't check ${f.name}: ${err && err.message ? err.message : err}` }));
      });
    }
  }

  async function checkOne(f, el) {
    const deps = await depsPromise;
    const tooBig = f.size > MAX_READ;
    const bytes = new Uint8Array(await (tooBig ? f.slice(0, 1024 * 1024) : f).arrayBuffer());
    const rep = await FC.inspect({ name: f.name, bytes }, deps);
    if (tooBig) { rep.size = f.size; rep.notes.unshift('Larger than 100 MB, so only its name and type were checked.'); }
    // QR codes in pictures (the file itself, or pictures inside a PDF).
    const qrUrls = [];
    for (const img of rep.images.slice(0, 20)) {
      const px = await pixelsOf(img);
      const r = px && PG.qr.decode(px);
      if (!r) continue;
      const link = PG.qr.toLink(r.text);
      if (link) qrUrls.push({ href: link, source: 'qr' });
      else rep.notes.push(`Contains a QR code that says: "${r.text.slice(0, 120)}"`);
    }
    if (qrUrls.length) FC.applyLinks(rep, qrUrls, deps);
    // Links (and QR codes) found in the file against the downloaded scam-site lists.
    const blocklist = await blocklistFor(rep.urls.map(u => u.href));
    if (blocklist) FC.applyLinks(rep, [], Object.assign({}, deps, { lists: Object.assign({}, deps.lists, { blocklist }) }));
    const sha = tooBig ? '' : hex(await crypto.subtle.digest('SHA-256', bytes));
    render(el, rep, sha);
  }

  $('pick').addEventListener('click', () => $('file').click());
  $('file').addEventListener('change', e => { handle(e.target.files); e.target.value = ''; });

  // Drop anywhere on the page.
  let depth = 0;
  const hasFiles = e => e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');
  window.addEventListener('dragenter', e => { if (!hasFiles(e)) return; e.preventDefault(); depth++; document.body.classList.add('dragging'); });
  window.addEventListener('dragover', e => { if (!hasFiles(e)) return; e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
  window.addEventListener('dragleave', () => { if (--depth <= 0) { depth = 0; document.body.classList.remove('dragging'); } });
  window.addEventListener('drop', e => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth = 0;
    document.body.classList.remove('dragging');
    handle(e.dataTransfer.files);
  });

  // For dev/testing pages: check bytes without a real file picker.
  window.__offTheHookCheck = (name, bytes) => handle([new File([bytes], name)]);
})();
