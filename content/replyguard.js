/*
 * Reply Guard: when you reply to an email Off the Hook rated Suspicious or Likely Phishing (or
 * write to a sender it flagged earlier in this tab), it watches what you type. If your reply
 * contains a phone number, password, card or bank details, a sign-in code or gift card codes,
 * a warning card appears next to the reply box, and Send is paused once so you can double-check.
 *
 * It never edits your reply, never sends anything, and never stores what you type. Only your
 * own words are checked: the quoted original email and your signature are skipped.
 */
(function () {
  'use strict';

  const BRAND = globalThis.PhishGuard.brand;
  const S = globalThis.PhishGuard.sensitive;

  const EDITOR_SEL = '[contenteditable="true"], [contenteditable=""], [contenteditable="plaintext-only"], textarea';
  // Parts of a reply that aren't your new words: quoted email, forwarded header, signature.
  const SKIP_SEL = '.gmail_quote, .gmail_extra, blockquote, #divRplyFwdMsg, [id^="divRplyFwdMsg"], #mail-editor-reference-message-container, ' +
    '.gmail_signature, [data-smartmail="gmail_signature"], #Signature, [id^="Signature"], #signature, [id^="ms-outlook-mobile-signature"]';
  const STOP_SEL = '#appendonsend, #divRplyFwdMsg, [id^="divRplyFwdMsg"], .gmail_quote';
  const OUR_UI = '#phishguard-root, #phishguard-linkcard, #phishguard-replyguard';

  const CARD_CSS = `
  :host { all: initial; }
  * { box-sizing: border-box; }
  .card { position: fixed; z-index: 2147483647; width: min(380px, calc(100vw - 16px));
    font: 13px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: var(--fg);
    background: var(--bg); border: 2px solid var(--edge); border-radius: 12px; overflow: hidden;
    box-shadow: 4px 4px 0 var(--vc, var(--edge)), 0 10px 28px rgba(0,0,0,.32); }
  .card[hidden] { display: none; }
  .card .ot-logo { width: 24px; height: 24px; }
  .card .ot-wordmark { height: 24px; }
  .body { padding: 12px; }
  .card .verdict .vicon { width: 34px; height: 34px; font-size: 18px; }
  .card .v-suspicious .vicon { padding-top: 9px; font-size: 14px; }
  .card .vlabel { font-size: 18px; }
  .card .checks { margin-top: 8px; }
  .card .note { margin: 10px 0; }
  .masked { font: 12px ui-monospace, SFMono-Regular, Consolas, monospace; color: var(--muted); margin-left: 4px; }
  .k { margin-top: 10px; }
  `;

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v);
    }
    for (const c of children.flat()) if (c != null && c !== false) el.append(c);
    return el;
  }

  const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g;

  /**
   * @param {{ getContext: () => object|null, riskySenders: () => Map, settings: () => object }} opts
   *   getContext: the open email if it is risky: { verdict, label, sender: { name, address }, internal, bodyEl }
   *   riskySenders: risky senders seen in this tab, keyed by address and by "name:<lowercase name>"
   *   pendingReply: the risky email you just clicked Reply on (or null)
   *   refresh: optional, returns a promise after merging senders flagged in other windows
   */
  function create(opts) {
    const state = new WeakMap(); // editor -> { ack, findings, ctx }
    let host = null, card = null, shownFor = null, timer = null, hideTimer = null;

    const cfg = () => Object.assign({ enabled: true, pauseSend: true }, opts.settings() || {});

    // ---------- which box is a reply box, and whose reply is it ----------
    function editorOf(node) {
      const el = node && (node.nodeType === 1 ? node : node.parentElement);
      if (!el || !el.closest || el.closest(OUR_UI)) return null;
      let ed = el.closest(EDITOR_SEL);
      if (!ed) return null;
      for (let up = ed.parentElement && ed.parentElement.closest(EDITOR_SEL); up; up = up.parentElement && up.parentElement.closest(EDITOR_SEL)) ed = up;
      const label = (ed.getAttribute('aria-label') || '') + ' ' + (ed.getAttribute('placeholder') || '');
      if (/search|subject|find|filter/i.test(label)) return null;
      const r = ed.getBoundingClientRect();
      if (r.height < 30 || r.width < 120) return null; // one-line boxes and chat bubbles
      return ed;
    }

    function composeRoot(ed) {
      let el = ed.parentElement;
      for (let i = 0; i < 14 && el && el !== document.body; i++, el = el.parentElement) {
        if (sendButtonIn(el)) return el;
      }
      return ed.parentElement || ed;
    }
    function sendButtonIn(root) {
      for (const b of root.querySelectorAll('button, [role="button"]')) if (isSend(b)) return b;
      return null;
    }
    function isSend(b) {
      const label = (b.getAttribute('aria-label') || b.getAttribute('data-tooltip') || b.getAttribute('title') || b.textContent || '').replace(/\s+/g, ' ').trim();
      return /^send\b/i.test(label) && !/^send (later|feedback|to\b|a copy|options)|schedul/i.test(label);
    }

    function addressesNear(root, ed) {
      const found = new Set();
      const names = new Set();
      for (const el of root.querySelectorAll('*')) {
        if (ed.contains(el) || el.closest(OUR_UI)) continue;
        for (const a of ['email', 'title', 'aria-label', 'data-hovercard-id']) {
          const v = el.getAttribute && el.getAttribute(a);
          if (v && v.includes('@')) (v.match(EMAIL_RE) || []).forEach(x => found.add(x.toLowerCase()));
        }
        // Recipient chips: the name may sit in a leaf element or next to icons inside a wrapper.
        const t = (el.textContent || '').replace(/\s+/g, ' ').trim();
        if (t && t.length < 80 && el.children.length <= 3) names.add(t.toLowerCase());
      }
      return { found, names };
    }

    // People named in the quoted original inside the reply box: Outlook's "From: Name <address>"
    // block and Gmail's "On ..., Name <address> wrote:" line.
    function quotedPeople(ed) {
      const text = ed.tagName === 'TEXTAREA' ? ed.value : (ed.innerText || ed.textContent || '');
      const found = new Set((text.match(EMAIL_RE) || []).map(a => a.toLowerCase()));
      const names = new Set();
      const add = n => { const t = String(n || '').replace(/["“”]/g, '').replace(/\s+/g, ' ').trim().toLowerCase(); if (t.length >= 3 && t.length <= 80) names.add(t); };
      let m;
      const fromRe = /(?:^|\n)\s*(?:From|De|Von|Van)\s*:\s*([^<\n\[]{2,80}?)\s*(?:<|\[mailto:|\n|$)/gi;
      while ((m = fromRe.exec(text))) add(m[1]);
      const wroteRe = /On .{3,90}?,\s*([^<,\n]{2,80}?)\s*(?:<[^>\n]+>)?\s*wrote:/gi;
      while ((m = wroteRe.exec(text))) add(m[1]);
      return { found, names };
    }

    // Is this reply going to a risky sender? Checked in order:
    //   1. the box sits next to the open risky email (inline reply)
    //   2. a flagged sender (this tab or another webmail window) is in the To line or quoted original
    //   3. you just clicked Reply on a flagged email (Outlook may swap the email out for the reply box)
    function contextFor(ed) {
      const ctx = opts.getContext();
      if (ctx && ctx.bodyEl && ctx.bodyEl.isConnected) {
        const region = ctx.bodyEl.closest('[role="main"], #ConversationReadingPaneContainer, #ReadingPaneContainerId');
        if (region && region.contains(ed)) return ctx;
      }
      const risky = opts.riskySenders();
      if (risky && risky.size) {
        const near = addressesNear(composeRoot(ed), ed);
        const quoted = quotedPeople(ed);
        for (const a of [...near.found, ...quoted.found]) if (risky.has(a)) return risky.get(a);
        for (const n of [...near.names, ...quoted.names]) if (risky.has('name:' + n)) return risky.get('name:' + n);
      }
      const pending = opts.pendingReply && opts.pendingReply();
      return pending || null;
    }

    // Only the words you typed: stop at the quoted original, skip signatures.
    function typedText(ed) {
      if (ed.tagName === 'TEXTAREA') return ed.value.split(/\n-{2,}\s*Original Message|\nOn .{5,80}wrote:\n|\n>/)[0];
      const stop = ed.querySelector(STOP_SEL);
      const walker = document.createTreeWalker(ed, NodeFilter.SHOW_TEXT);
      let out = '', prev = null;
      for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        if (stop && (stop === n || (stop.compareDocumentPosition(n) & Node.DOCUMENT_POSITION_FOLLOWING))) break;
        const p = n.parentElement;
        if (p && p.closest(SKIP_SEL)) continue;
        if (prev && p !== prev) out += ' ';
        out += n.nodeValue;
        prev = p;
        if (out.length > 20000) break;
      }
      return out;
    }

    function evaluate(ed) {
      const st = state.get(ed) || { ack: false, findings: [], ctx: null };
      state.set(ed, st);
      st.ctx = cfg().enabled ? contextFor(ed) : null;
      st.findings = st.ctx ? S.findSensitive(typedText(ed)) : [];
      return st;
    }

    // ---------- the warning card ----------
    function ensureCard() {
      if (host) return;
      host = document.createElement('div');
      host.id = 'phishguard-replyguard';
      const shadow = host.attachShadow({ mode: 'open' });
      BRAND.adopt(shadow, CARD_CSS);
      card = h('div', { class: 'card', role: 'alertdialog', 'aria-live': 'assertive', hidden: true });
      shadow.append(card);
    }

    function show(ed, st, mode) {
      ensureCard();
      if (!host.isConnected) document.documentElement.appendChild(host);
      clearTimeout(hideTimer);
      const phish = st.ctx.verdict === 'phishing';
      const cls = phish ? 'v-phishing' : 'v-suspicious';
      const who = st.ctx.sender && (st.ctx.sender.name || st.ctx.sender.address) || 'the sender';
      card.className = 'card ' + cls;
      const list = h('ul', { class: 'checks', 'aria-label': 'Found in your reply' },
        st.findings.slice(0, 6).map(f => h('li', { class: 'fail high' },
          h('span', { class: 'm', 'aria-hidden': 'true', text: '✗' }),
          h('span', {}, f.label, h('span', { class: 'masked', text: f.masked })))));
      const advice = st.ctx.internal
        ? `If ${who} really needs this, ask them in person or call a number you already know before sending. Their account may be hacked.`
        : 'Scammers ask for exactly this. Check the request another way (a phone number or address you already know) before you send anything.';
      const paused = mode === 'paused';
      const close = () => hide();
      card.replaceChildren(
        BRAND.header({ chip: 'Reply guard', onClose: close, closeLabel: 'Close warning' }),
        h('div', { class: 'body verdict-wrap ' + cls },
          h('div', { class: 'verdict ' + cls },
            h('span', { class: 'vicon', 'aria-hidden': 'true', text: '!' }),
            h('div', {}, h('div', { class: 'vlabel', text: paused ? 'Send paused' : 'Careful what you send' }),
              h('div', { class: 'vscore', text: `Replying to an email rated ${st.ctx.label || (phish ? 'Likely Phishing' : 'Suspicious')}` }))),
          h('div', { class: 'k', text: 'Your reply includes:' }),
          list,
          h('p', { class: 'note verdict-color', text: advice }),
          h('div', { class: 'actions' },
            paused ? h('button', { type: 'button', class: 'primary', text: 'Keep editing', onclick: () => { hide(); try { ed.focus(); } catch (e) { /* ignore */ } } }) : null,
            h('button', { type: 'button', text: paused ? 'Send anyway' : "I checked, it's OK", onclick: () => acknowledge(ed, st, paused) }),
            !paused ? h('button', { type: 'button', text: 'Hide', onclick: close }) : null)
        )
      );
      card.hidden = false;
      shownFor = ed;
      position();
    }

    function acknowledge(ed, st, paused) {
      st.ack = true;
      if (!paused) { hide(); return; }
      card.replaceChildren(
        BRAND.header({ chip: 'Reply guard', onClose: () => hide() }),
        h('div', { class: 'body' }, h('p', { class: 'note lime', text: 'OK. Click Send again to send it.' })));
      position();
      hideTimer = setTimeout(hide, 5000);
    }

    function hide() {
      if (card) card.hidden = true;
      shownFor = null;
    }

    function position() {
      if (!card || card.hidden || !shownFor || !shownFor.isConnected) return;
      const r = shownFor.getBoundingClientRect();
      card.style.left = '0px'; card.style.top = '0px';
      const cw = card.offsetWidth, ch = card.offsetHeight;
      let top = r.top - ch - 10;
      if (top < 8) top = r.bottom + 10 + ch <= window.innerHeight ? r.bottom + 10 : Math.max(8, window.innerHeight - ch - 8);
      const left = Math.max(8, Math.min(r.right - cw, window.innerWidth - cw - 8));
      card.style.top = top + 'px';
      card.style.left = left + 'px';
    }

    // ---------- events ----------
    function check(ed) {
      const st = evaluate(ed);
      if (st.findings.length && !st.ack) show(ed, st, 'warn');
      else if (shownFor === ed) hide();
    }

    document.addEventListener('input', e => {
      const ed = editorOf(e.target);
      if (!ed) return;
      clearTimeout(timer);
      timer = setTimeout(() => {
        Promise.resolve(opts.refresh && opts.refresh()).catch(() => {}).then(() => check(ed));
      }, 300);
    }, true);
    document.addEventListener('focusin', e => {
      const ed = editorOf(e.target);
      if (!ed) return;
      // Pick up senders flagged in other webmail windows (e.g. a reply popped out to its own window).
      Promise.resolve(opts.refresh && opts.refresh()).catch(() => {}).then(() => check(ed));
    }, true);
    let raf = 0;
    const reposition = () => { if (!raf) raf = requestAnimationFrame(() => { raf = 0; position(); }); };
    window.addEventListener('scroll', reposition, true);
    window.addEventListener('resize', reposition);

    // Pause Send once when the reply still contains something risky.
    function gate(e, ed) {
      if (!ed || !cfg().enabled || !cfg().pauseSend) return;
      const st = evaluate(ed);
      if (!st.findings.length || st.ack) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      show(ed, st, 'paused');
    }
    const editorForButton = b => {
      const root = composeRoot(b);
      let el = b.parentElement;
      for (let i = 0; i < 14 && el; i++, el = el.parentElement) {
        for (const cand of el.querySelectorAll(EDITOR_SEL)) { const ed = editorOf(cand); if (ed) return ed; }
        if (el === root) break;
      }
      return null;
    };
    for (const type of ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'click']) {
      window.addEventListener(type, e => {
        const t = e.target && e.target.closest ? e.target.closest('button, [role="button"]') : null;
        if (!t || t.closest(OUR_UI) || !isSend(t)) return;
        gate(e, editorForButton(t));
      }, true);
    }
    window.addEventListener('keydown', e => {
      const sendKey = (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) || (e.altKey && (e.key === 's' || e.key === 'S'));
      if (sendKey) gate(e, editorOf(e.target));
    }, true);

    return { hide, _test: { typedText, editorOf, contextFor, quotedPeople } };
  }

  globalThis.PhishGuardReplyGuard = { create };
})();
