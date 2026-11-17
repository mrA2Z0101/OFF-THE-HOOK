/*
 * Hover card shown on the webmail page. Three uses, one look:
 *   - showLink(anchor, entry): hovering a link -> where it really goes + every check
 *   - showInfo(target, info):  hovering a highlighted phrase -> why it was flagged
 *   - showRow(tag, entry):     hovering an inbox row tag -> why the unopened email was flagged
 * Built from the shared design system (shared/brand.js) so it matches the panel, popup and
 * settings page exactly. Never opens or fetches the link. All text set with textContent.
 */
(function () {
  'use strict';

  const BRAND = globalThis.PhishGuard.brand;

  const LINK_RISK = {
    danger: { cls: 'v-phishing', icon: '✕', label: 'Dangerous link', advice: "Don't click. If you need this site, type its address into your browser yourself." },
    caution: { cls: 'v-suspicious', icon: '!', label: 'Use caution', advice: 'Only continue if you were expecting this link, and never sign in or pay from it without checking.' },
    ok: { cls: 'v-safe', icon: '✓', label: 'No warning signs', advice: "Nothing suspicious in the address, but Off the Hook can't see the site itself. Be careful where you sign in." }
  };
  // Same verdicts for a QR code, with advice about scanning instead of clicking.
  const QR_ADVICE = {
    danger: "Don't scan it. Your phone doesn't have your work computer's protections, and this address shows clear signs of a fake site.",
    caution: "Only scan it if you were expecting it, and never sign in or pay from a site a QR code opened.",
    ok: "The address looks normal, but only scan QR codes you were expecting. Typing the site's address yourself is always safer."
  };
  const PHRASE_RISK = {
    high: { cls: 'v-phishing', icon: '!', label: 'High-risk wording' },
    medium: { cls: 'v-suspicious', icon: '!', label: 'Medium-risk wording' },
    low: { cls: 'v-low', icon: '!', label: 'Low-risk wording' },
    ai: { cls: 'v-ai', icon: 'AI', label: 'Flagged by AI' }
  };
  const ROW_RISK = {
    phishing: {
      cls: 'v-phishing', icon: '✕', label: 'Likely phishing',
      advice: "Treat this as phishing. If you open it, don't click links, open attachments, or reply with any information."
    },
    suspicious: {
      cls: 'v-suspicious', icon: '!', label: 'Suspicious',
      advice: "Open it carefully: Off the Hook runs the full check when you do. Don't click links or attachments until you've read its verdict."
    }
  };
  const MAX_PASSED = 4;

  // Card-specific layout only; colors and components come from the shared design system.
  const CARD_CSS = `
  :host { all: initial; }
  * { box-sizing: border-box; }
  .card {
    position: fixed; z-index: 2147483647; width: min(360px, calc(100vw - 16px));
    font: 13px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: var(--fg);
    background: var(--bg); border: 2px solid var(--edge); border-radius: 12px; overflow: hidden;
    box-shadow: 4px 4px 0 var(--vc, var(--edge)), 0 10px 28px rgba(0,0,0,.32);
  }
  .card[hidden] { display: none; }
  .card .ot-logo { width: 24px; height: 24px; }
  .card .ot-wordmark { height: 24px; }
  .body { padding: 12px 12px 10px; }
  .card .verdict .vicon { width: 34px; height: 34px; font-size: 18px; }
  .card .v-suspicious .vicon, .card .v-low .vicon { padding-top: 9px; font-size: 14px; }
  .card .vlabel { font-size: 18px; }
  .k { margin-top: 10px; }
  .dest { font-size: 16px; font-weight: 800; overflow-wrap: anywhere; }
  .site { color: var(--muted); font-weight: 400; font-size: 12px; }
  .code.url { display: block; margin-top: 3px; color: var(--muted); }
  .quote { font-size: 15px; font-weight: 800; overflow-wrap: anywhere; margin-top: 10px; }
  .more { color: var(--muted); font-size: 12px; margin: 2px 0 0 20px; }
  .card .note { margin-top: 10px; }
  .card .disclaimer { margin-top: 8px; padding-top: 6px; font-size: 11px; }
  `;

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v; else if (k === 'text') el.textContent = v; else el.setAttribute(k, v);
    }
    for (const c of children.flat()) if (c != null && c !== false) el.append(c);
    return el;
  }

  function verdictBlock(risk, sub) {
    return h('div', { class: 'verdict ' + risk.cls },
      h('span', { class: 'vicon', 'aria-hidden': 'true', text: risk.icon }),
      h('div', {}, h('div', { class: 'vlabel', text: risk.label }), sub ? h('div', { class: 'vscore', text: sub }) : null)
    );
  }

  function create(handlers) {
    const host = document.createElement('div');
    host.id = 'phishguard-linkcard';
    const shadow = host.attachShadow({ mode: 'open' });
    BRAND.adopt(shadow, CARD_CSS);
    const card = h('div', { class: 'card', role: 'tooltip', hidden: true });
    shadow.append(card);
    card.addEventListener('mouseenter', () => handlers && handlers.onEnter && handlers.onEnter());
    card.addEventListener('mouseleave', () => handlers && handlers.onLeave && handlers.onLeave());
    let current = null;

    function frame(chip, risk, sub) {
      card.className = 'card ' + risk.cls;
      card.replaceChildren(BRAND.header({ chip }));
      const body = h('div', { class: 'body' }, verdictBlock(risk, sub));
      card.append(body);
      return body;
    }

    function checksList(checks) {
      const failed = checks.filter(c => c.ok === false);
      const infos = checks.filter(c => c.ok === null);
      const passed = checks.filter(c => c.ok === true);
      const list = h('ul', { class: 'checks', 'aria-label': 'Checks' });
      for (const c of failed) list.append(h('li', { class: 'fail ' + (c.severity || '') }, h('span', { class: 'm', 'aria-hidden': 'true', text: '✗' }), h('span', { text: c.text })));
      for (const c of infos) list.append(h('li', { class: 'info' }, h('span', { class: 'm', 'aria-hidden': 'true', text: 'i' }), h('span', { text: c.text })));
      for (const c of passed.slice(0, MAX_PASSED)) list.append(h('li', { class: 'pass' }, h('span', { class: 'm', 'aria-hidden': 'true', text: '✓' }), h('span', { text: c.text })));
      const out = [];
      if (list.childNodes.length) out.push(list);
      if (passed.length > MAX_PASSED) out.push(h('div', { class: 'more', text: `+${passed.length - MAX_PASSED} more checks passed` }));
      return out;
    }

    function renderLink(entry) {
      const risk = LINK_RISK[entry.risk] || LINK_RISK.ok;
      const isEmail = entry.kind === 'email';
      const isQr = !!entry.qr;
      const body = frame(isQr ? 'QR check' : 'Link check', risk,
        isQr ? 'Where this QR code goes' : isEmail ? 'Email address link' : 'Where this link really goes');
      body.append(h('div', { class: 'k', text: isEmail ? 'Opens an email to' : isQr ? 'The QR code opens' : 'Really goes to' }));
      const dest = h('div', { class: 'dest', text: entry.domain || entry.display });
      if (!isEmail && entry.registrable && entry.registrable !== entry.domain) dest.append(' ', h('span', { class: 'site', text: '(site: ' + entry.registrable + ')' }));
      body.append(dest);
      if (!isEmail && entry.display) body.append(h('span', { class: 'code url', text: entry.display.length > 180 ? entry.display.slice(0, 180) + '…' : entry.display }));
      if (entry.text && entry.text !== entry.display && entry.text !== entry.domain) {
        body.append(h('div', { class: 'k' }, 'Link text: ', h('span', { text: '“' + entry.text.slice(0, 120) + '”' })));
      }
      body.append(...checksList(entry.checks || []));
      body.append(h('p', { class: 'note verdict-color', text: isQr ? QR_ADVICE[entry.risk] || QR_ADVICE.caution : risk.advice }));
      body.append(h('p', { class: 'disclaimer', text: isQr
        ? 'Read from the picture on your computer. Off the Hook did not open the address.'
        : 'Checked on your computer. Off the Hook did not open the link.' }));
    }

    // info: { text: matched phrase, items: [{ source: 'rule'|'ai', severity, title, reason }] }
    function renderInfo(info) {
      const rank = { high: 3, medium: 2, low: 1 };
      const rules = (info.items || []).filter(i => i.source !== 'ai');
      const top = rules.reduce((a, b) => (!a || rank[b.severity] > rank[a.severity] ? b : a), null);
      const risk = top ? PHRASE_RISK[top.severity] || PHRASE_RISK.medium : PHRASE_RISK.ai;
      const body = frame('Warning sign', risk, 'Why this wording was flagged');
      body.append(h('div', { class: 'quote', text: '“' + String(info.text || '').slice(0, 160) + '”' }));
      const checks = (info.items || []).map(i => ({
        ok: false,
        severity: i.source === 'ai' ? 'medium' : i.severity,
        text: (i.source === 'ai' ? 'AI: ' : (i.title ? i.title + ': ' : '')) + i.reason
      }));
      body.append(...checksList(checks));
      body.append(h('p', { class: 'note verdict-color', text: "Don't act on this request until you've confirmed it with the sender through a channel you already trust." }));
    }

    // entry: { result: { verdict, score, reasons: [{ severity, title }] }, data: { from, subject } }
    function renderRow(entry) {
      const res = entry.result || {};
      const d = entry.data || {};
      const risk = ROW_RISK[res.verdict] || ROW_RISK.suspicious;
      const body = frame('Inbox check', risk, `Risk score ${res.score} / 100 · from the preview`);
      body.append(h('div', { class: 'quote', text: '“' + (String(d.subject || '').slice(0, 160) || '(no subject)') + '”' }));
      const from = d.from || {};
      const who = from.name && from.address ? `${from.name} <${from.address}>` : (from.name || from.address || 'unknown sender');
      body.append(h('div', { class: 'k' }, 'From: ', h('span', { text: who.slice(0, 200) })));
      body.append(...checksList((res.reasons || []).map(r => ({ ok: false, severity: r.severity, text: r.title }))));
      body.append(h('p', { class: 'note verdict-color', text: risk.advice }));
      body.append(h('p', { class: 'disclaimer', text: 'Checked from the sender, subject and preview line only. The email has not been opened.' }));
    }

    // Below the target if it fits, else above; if neither fits, use the roomier side and let
    // the card scroll, so it never covers the thing it describes.
    function position(anchor) {
      const r = anchor.getBoundingClientRect();
      card.style.maxHeight = 'none'; card.style.overflowY = 'hidden';
      card.style.left = '0px'; card.style.top = '0px';
      const height = card.getBoundingClientRect().height;
      const width = card.getBoundingClientRect().width;
      const below = window.innerHeight - r.bottom - 16;
      const above = r.top - 16;
      let top;
      if (height <= below) top = r.bottom + 8;
      else if (height <= above) top = r.top - height - 8;
      else if (below >= above) { top = r.bottom + 8; limit(below); }
      else { const lim = limit(above); top = r.top - lim - 8; }
      const left = Math.max(8, Math.min(r.left, window.innerWidth - width - 8));
      card.style.top = Math.max(8, top) + 'px';
      card.style.left = left + 'px';
    }
    function limit(space) {
      const lim = Math.max(120, space);
      card.style.maxHeight = lim + 'px';
      card.style.overflowY = 'auto';
      return lim;
    }

    function open(target, draw) {
      if (!host.isConnected) document.documentElement.appendChild(host);
      current = target;
      draw();
      card.hidden = false;
      position(target);
    }

    return {
      show(anchor, entry) { open(anchor, () => renderLink(entry)); },
      showLink(anchor, entry) { open(anchor, () => renderLink(entry)); },
      showInfo(target, info) { open(target, () => renderInfo(info)); },
      showRow(target, entry) { open(target, () => renderRow(entry)); },
      hide() { card.hidden = true; current = null; },
      showingFor() { return card.hidden ? null : current; },
      contains(node) { return node === host || host.contains(node); }
    };
  }

  globalThis.PhishGuardLinkCard = { create };
})();
