/*
 * Off the Hook content script entry point.
 *
 * Watches the webmail page (MutationObserver), extracts the currently open email via
 * the site adapter, asks the background worker to analyze it, then shows the badge,
 * panel, and highlights. Read-only: it never clicks, sends, deletes or edits mail.
 */
(function () {
  'use strict';
  if (globalThis.__phishguardContentLoaded) return;
  globalThis.__phishguardContentLoaded = true;

  const adapter = globalThis.PhishGuardAdapters.pick(location);
  if (!adapter) return;

  const HL = globalThis.PhishGuardHighlighter;
  let settings = { highlight: { enabled: true, linkBadges: true, colors: {} }, ui: { showBadge: true }, ai: { enabled: false } };
  let cur = null;     // state for the email currently shown
  let runId = 0;      // increments per new email so stale async replies are ignored
  let timer = null;
  let dead = false;   // extension was reloaded/removed; stop working on this page

  const ui = globalThis.PhishGuardUI.create({
    onToggleHighlights: () => toggleHighlights(),
    onRescan: () => { if (cur) cur.key = null; schedule(0); },
    onOpenSettings: () => send({ type: 'openOptions' }).catch(() => {}),
    onOpenFileChecker: () => send({ type: 'openFileChecker' }).catch(() => {}),
    // Reports are stored only on this computer by the background worker.
    onReport: async (kind, phrases, note) => {
      if (!cur) return { ok: false, error: 'No email is open.' };
      const resp = await send({ type: 'report', kind, email: cur.data, site: adapter.id, phrases, note });
      if (resp && resp.ok) { cur.key = null; schedule(0); }
      return resp;
    },
    onUndoReport: async id => {
      const resp = await send({ type: 'undoReport', id });
      if (resp && resp.ok && cur) { cur.key = null; schedule(0); }
      return resp;
    },
    // Prefer what is selected right now; fall back to the last selection if the click cleared it.
    getSelectedText: () => selectedEmailText() || lastSelection
  });

  // ---- link check card (hover or keyboard focus on a link in the email) ----
  let linkMap = new Map(); // anchor element -> link entry from the analysis
  let showTimer = null, hideTimer = null;
  const linkCard = globalThis.PhishGuardLinkCard.create({
    onEnter: () => clearTimeout(hideTimer),
    onLeave: () => scheduleHideCard(150)
  });
  function rebuildLinkMap() {
    linkMap = new Map();
    if (!cur || !cur.result) return;
    for (const entry of cur.result.links || []) {
      const a = cur.linkEls && cur.linkEls[entry.index];
      if (a) linkMap.set(a, entry);
    }
  }
  const hoverEnabled = () => !(settings.highlight && settings.highlight.linkHover === false);
  // What the pointer is over: an analyzed link, a highlighted phrase, or a "real destination" badge.
  // All three open the same card, so every hover tip in the email looks the same.
  const linkFromEvent = e => {
    const t = e.target && e.target.closest ? e.target : null;
    if (!t) return null;
    if (listScan.isTag(t)) return t; // inbox row tag
    if (linkMap.has(t)) return t;     // a QR code picture
    const a = t.closest('a[href]');
    if (a && linkMap.has(a)) return a;
    const mark = t.closest('mark.phishguard-mark[data-pg-info]');
    if (mark) return mark;
    const badge = t.closest('.phishguard-link-badge[data-pg-index]');
    return badge || null;
  };
  function entryForIndex(i) {
    return cur && cur.result && (cur.result.links || []).find(l => String(l.index) === String(i));
  }
  function showCard(el) {
    clearTimeout(hideTimer);
    if (!el.isConnected) return;
    if (listScan.isTag(el)) {
      const entry = listScan.infoFor(el);
      if (entry) linkCard.showRow(el, entry);
      return;
    }
    if (linkMap.has(el)) return linkCard.showLink(el, linkMap.get(el));
    if (el.dataset.pgIndex != null) {
      const entry = entryForIndex(el.dataset.pgIndex);
      if (entry) linkCard.showLink(el, entry);
      return;
    }
    if (el.dataset.pgInfo) {
      let items = [];
      try { items = JSON.parse(el.dataset.pgInfo); } catch (e) { return; }
      if (Array.isArray(items) && items.length) linkCard.showInfo(el, { text: el.textContent, items });
    }
  }
  function scheduleHideCard(ms) {
    clearTimeout(showTimer);
    clearTimeout(hideTimer);
    hideTimer = setTimeout(() => linkCard.hide(), ms);
  }
  // The link card can be turned off in Settings; phrase tips (the old tooltips) always show.
  const allowed = el => !linkMap.has(el) || hoverEnabled();
  document.addEventListener('mouseover', e => {
    const a = linkFromEvent(e);
    if (!a || !allowed(a)) return;
    clearTimeout(hideTimer);
    if (linkCard.showingFor() === a) return;
    clearTimeout(showTimer);
    showTimer = setTimeout(() => showCard(a), 300); // short pause so passing over links doesn't flash cards
  }, true);
  document.addEventListener('mouseout', e => {
    const a = linkFromEvent(e);
    if (!a) return;
    const to = e.relatedTarget;
    if (to && (a.contains(to) || linkCard.contains(to))) return;
    scheduleHideCard(250);
  }, true);
  document.addEventListener('focusin', e => {
    const a = linkFromEvent(e);
    if (a && allowed(a)) showCard(a);
  }, true);
  document.addEventListener('focusout', e => { if (linkFromEvent(e)) scheduleHideCard(100); }, true);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') scheduleHideCard(0); }, true);
  window.addEventListener('scroll', () => { if (linkCard.showingFor()) scheduleHideCard(0); }, true);

  // Text the user selects in the email (for "What gave it away?").
  // Triple-clicking or dragging past the last word makes the selection spill just outside the
  // email body, so the selection is clamped to the body instead of being rejected.
  function selectedEmailText() {
    const sel = document.getSelection();
    if (!sel || !sel.rangeCount || sel.isCollapsed) return '';
    const range = sel.getRangeAt(0);
    const node = range.commonAncestorContainer;
    const el = node && (node.nodeType === 1 ? node : node.parentElement);
    if (el && el.closest && el.closest('#phishguard-root, #phishguard-linkcard')) return ''; // our own panel
    let r = range;
    const body = cur && cur.bodyEl;
    if (body && body.isConnected && range.intersectsNode(body)) {
      r = range.cloneRange();
      if (!body.contains(r.startContainer)) r.setStart(body, 0);
      if (!body.contains(r.endContainer)) r.setEnd(body, body.childNodes.length);
    }
    return rangeText(r).replace(/\s+/g, ' ').trim().slice(0, 400);
  }
  // Text of a range with a space between paragraphs / line breaks (Range.toString() glues
  // "you.</p><p>Thanks" into "you.Thanks", which would never match the email again).
  function rangeText(r) {
    const c = r.commonAncestorContainer;
    if (c.nodeType === 3) return c.nodeValue.slice(r.startOffset, r.endOffset);
    const isInline = el => { const d = getComputedStyle(el).display; return d === 'inline' || d === 'contents'; };
    const blockOf = n => { let e = n.parentElement; while (e && e !== c && isInline(e)) e = e.parentElement; return e; };
    const walker = document.createTreeWalker(c, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
    let out = '', prevBlock = null, gap = false;
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      if (!r.intersectsNode(n)) continue;
      if (n.nodeType === 1) { if (n.tagName === 'BR') gap = true; continue; }
      let t = n.nodeValue;
      if (n === r.startContainer && n === r.endContainer) t = t.slice(r.startOffset, r.endOffset);
      else if (n === r.startContainer) t = t.slice(r.startOffset);
      else if (n === r.endContainer) t = t.slice(0, r.endOffset);
      const b = blockOf(n);
      if (out && (gap || (prevBlock && b !== prevBlock))) out += ' ';
      out += t; prevBlock = b; gap = false;
    }
    return out;
  }
  // Also remembered continuously, because clicking a button in the panel can clear the selection.
  let lastSelection = '';
  document.addEventListener('selectionchange', () => {
    if (!cur) return;
    const t = selectedEmailText();
    if (t) lastSelection = t;
  });

  async function send(msg) {
    if (!chrome.runtime || !chrome.runtime.id) { shutdown(); throw new Error('Off the Hook was updated or removed. Reload this page.'); }
    try {
      return await chrome.runtime.sendMessage(msg);
    } catch (e) {
      if (/context invalidated|receiving end does not exist/i.test(String(e && e.message))) {
        shutdown();
        throw new Error('Off the Hook was updated or removed. Reload this page to keep scanning.');
      }
      throw e;
    }
  }

  function signature(d) {
    return [d.from.address, d.from.name, d.subject, d.body.length, d.body.slice(0, 400), d.links.length,
      (d.attachments || []).join('|'), d.headersOnly ? 1 : 0, d.headers ? 'H' : ''].join('\u0001');
  }

  // ---- message header from Outlook's "View message details" window ----
  // When that window is open, read the raw header, check it belongs to the open email
  // (subject + sender), and remember it for the rest of this page session.
  const AH = globalThis.PhishGuardAdapters.helpers;
  const headerCache = new Map();
  const normSubject = s => String(s || '').replace(/\s+/g, ' ').trim().toLowerCase().replace(/^\(no subject\)$/, '');
  const identity = d => normSubject(d.subject) + '\u0001' + String(d.from.name || '').trim().toLowerCase();
  const KEEP_HEADERS = ['authentication-results', 'return-path', 'reply-to', 'from', 'received-spf',
    'x-ms-exchange-organization-authas', 'x-ms-exchange-crosstenant-authas', 'x-ms-exchange-organization-authsource',
    'x-ms-exchange-organization-scl', 'x-forefront-antispam-report', 'x-microsoft-antispam'];

  function captureHeaders(data) {
    if (!adapter.getHeaderText) return;
    let raw = '';
    try { raw = adapter.getHeaderText(); } catch (e) { return; }
    if (!raw) return;
    const h = AH.parseHeaderBlock(raw);
    const hSubject = normSubject(AH.decodeMimeWords((h.subject || h['thread-topic'] || [''])[0]));
    const hFrom = AH.parseAddress(AH.decodeMimeWords((h.from || [''])[0]));
    const sameAddr = hFrom.address && data.from.address && hFrom.address === data.from.address.toLowerCase();
    const sameName = hFrom.name && data.from.name && hFrom.name.trim().toLowerCase() === data.from.name.trim().toLowerCase();
    if (sameAddr || (hSubject === normSubject(data.subject) && (sameName || !data.from.name))) headerCache.set(identity(data), h);
  }

  function mergeHeaders(data) {
    const h = headerCache.get(identity(data));
    if (!h) return;
    data.headers = {};
    for (const k of KEEP_HEADERS) if (h[k]) data.headers[k] = h[k].map(v => String(v).slice(0, 2000));
    data.authResults = (h['authentication-results'] || []).join('\n');
    // Outlook often shows coworkers by name only; the header has the real address.
    const from = AH.parseAddress(AH.decodeMimeWords((h.from || [''])[0]));
    if (!data.from.address && from.address) data.from.address = from.address;
    if ((!data.replyTo || !data.replyTo.length) && h['reply-to']) data.replyTo = h['reply-to'].map(v => AH.parseAddress(v).address).filter(Boolean);
  }

  // ---- QR codes in the email's pictures ----
  // Links read from QR codes are added to the email's links (pointing at the picture), so they
  // get the same checks, highlight and hover card as any other link.
  const qrScan = globalThis.PhishGuardQrScan.create({ send, onFound: () => schedule(0) });
  function addQrLinks(open) {
    if (!open.bodyEl || settings.highlight && settings.highlight.qr === false) return;
    qrScan.scan(open.bodyEl);
    for (const { img, href } of qrScan.linksFor(open.bodyEl)) {
      open.data.links.push({ text: '', href, qr: true });
      open.linkEls.push(img);
    }
  }

  // ---- Reply Guard ----
  // Senders rated Suspicious / Likely Phishing in this tab (no email text kept), so a reply or
  // new message to them is watched even after the original email is closed.
  const VERDICT_WORDS = { suspicious: 'Suspicious', phishing: 'Likely Phishing' };
  const riskySenders = new Map();
  function riskOf(c) {
    const f = finalOf(c);
    return {
      verdict: f.verdict, label: VERDICT_WORDS[f.verdict] || f.verdict,
      sender: { name: c.data.from.name, address: c.data.from.address },
      internal: c.result.findings.some(x => x.id === 'internal_compromised' || x.id === 'unverified_request')
    };
  }
  function rememberRisk() {
    if (!cur || !cur.result || finalOf(cur).verdict === 'safe') return;
    const r = riskOf(cur);
    const keys = [cur.data.from.address].concat(cur.data.replyTo || []).filter(Boolean).map(a => a.toLowerCase());
    if (/\s/.test((cur.data.from.name || '').trim())) keys.push('name:' + cur.data.from.name.trim().toLowerCase());
    for (const k of keys) riskySenders.set(k, r);
    // Shared with other webmail windows (a reply popped out into its own window) until the browser closes.
    send({ type: 'rememberRisky', entries: keys.map(k => [k, r]) }).catch(() => {});
  }
  let riskyFetchedAt = 0;
  async function refreshRisky() {
    if (Date.now() - riskyFetchedAt < 5000) return; // at most every few seconds while typing
    riskyFetchedAt = Date.now();
    const resp = await send({ type: 'getRisky' });
    if (resp && resp.ok && resp.risky) for (const [k, v] of Object.entries(resp.risky)) if (!riskySenders.has(k)) riskySenders.set(k, v);
  }

  // Clicking Reply on a flagged email is remembered for a while: Outlook often swaps the email
  // out for the reply box, so the email is no longer "open" while you type.
  const emailId = d => [d.from.address, d.from.name, d.subject].join('\u0001').toLowerCase();
  const REPLY_RE = /^(reply( all)?|respond|répondre( à tous)?|antworten|responder)\b/i;
  const PENDING_MS = 10 * 60 * 1000;
  let pendingReply = null;
  function noteReply() {
    if (cur && cur.result && finalOf(cur).verdict !== 'safe') pendingReply = { ctx: riskOf(cur), at: Date.now(), id: emailId(cur.data) };
  }
  document.addEventListener('click', e => {
    const b = e.target && e.target.closest ? e.target.closest('button, [role="button"], [role="menuitem"]') : null;
    if (!b || b.closest('#phishguard-root, #phishguard-linkcard, #phishguard-replyguard')) return;
    const label = (b.getAttribute('aria-label') || b.getAttribute('title') || b.getAttribute('data-tooltip') || b.textContent || '').replace(/\s+/g, ' ').trim();
    if (REPLY_RE.test(label)) noteReply();
    else if (/^send\b/i.test(label)) setTimeout(() => { pendingReply = null; }, 0); // sent (or paused, then sent later)
  }, true);
  document.addEventListener('keydown', e => {
    // Reply shortcuts: R / Shift+R / A in Gmail, Ctrl+R / Ctrl+Shift+R in Outlook.
    const t = e.target;
    if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
    const k = (e.key || '').toLowerCase();
    if ((k === 'r' || (k === 'a' && !e.ctrlKey)) && !e.altKey && !e.metaKey) noteReply();
  }, true);

  globalThis.PhishGuardReplyGuard.create({
    getContext: () => (cur && cur.result && finalOf(cur).verdict !== 'safe' ? Object.assign(riskOf(cur), { bodyEl: cur.bodyEl }) : null),
    riskySenders: () => riskySenders,
    pendingReply: () => (pendingReply && Date.now() - pendingReply.at < PENDING_MS ? pendingReply.ctx : null),
    refresh: refreshRisky,
    settings: () => settings.replyGuard
  });

  function finalOf(c) {
    if (c.ai.status === 'done') return { score: c.ai.combined.score, verdict: c.ai.combined.verdict };
    return { score: c.result.score, verdict: c.result.verdict };
  }

  function render() {
    if (!cur || !cur.result) return;
    rememberRisk();
    ui.update({ result: cur.result, final: finalOf(cur), ai: cur.ai, highlightsOn: cur.highlightsOn, notice: cur.notice || '', site: adapter.id,
      attachments: (cur.data.attachments || []).length });
  }

  // ---- highlighting (observer paused so our own DOM edits don't trigger rescans) ----
  function withObserverPaused(fn) {
    observer.disconnect();
    try { fn(); } finally { observer.takeRecords(); startObserving(); }
  }

  function applyHighlights() {
    if (!cur || !cur.bodyEl || !cur.result) return;
    rebuildLinkMap(); // the hover card works even when highlights are turned off
    withObserverPaused(() => {
      HL.clear(cur.bodyEl);
      cur.marked = false;
      if (!cur.highlightsOn) return;
      const ruleItems = [];
      for (const f of cur.result.findings) {
        if (f.kind !== 'content') continue;
        for (const m of f.matches) ruleItems.push({ text: m, severity: f.severity, title: f.title, reason: f.explanation });
      }
      const aiItems = cur.ai.status === 'done' ? cur.ai.data.highlights.map(x => ({ text: x.text, reason: x.reason })) : [];
      const n = HL.highlightAll(cur.bodyEl, ruleItems, aiItems) + HL.markLinks(cur.linkEls, cur.result.links, settings.highlight.linkBadges !== false);
      cur.marked = n > 0;
    });
  }

  function clearHighlights() {
    if (cur && cur.bodyEl && cur.bodyEl.isConnected) withObserverPaused(() => HL.clear(cur.bodyEl));
    linkMap = new Map();
    scheduleHideCard(0);
  }

  function toggleHighlights() {
    if (!cur) return;
    cur.highlightsOn = !cur.highlightsOn;
    applyHighlights();
    render();
  }

  // ---- inbox list tags (checked before the email is opened) ----
  const listScan = globalThis.PhishGuardListScan.create({ adapter, send, pause: fn => withObserverPaused(fn) });

  // ---- main check ----
  async function check() {
    if (dead) return;
    listScan.run(!(settings.ui && settings.ui.inboxTags === false));
    let open;
    try { open = adapter.getOpenEmail(); } catch (e) { open = null; }

    if (open && (open.data.from.address || open.data.body)) {
      captureHeaders(open.data);
      mergeHeaders(open.data);
      addQrLinks(open);
    }

    if (!open || (!open.data.from.address && !open.data.body)) {
      if (cur) {
        clearHighlights();
        cur = null;
        runId++;
        ui.setVisible(false);
        send({ type: 'noEmail' }).catch(() => {});
      }
      return;
    }

    const sig = signature(open.data);
    if (cur && sig === cur.key) {
      // Same email. Webmail may have re-rendered the body and dropped our highlights.
      const bodyChanged = open.bodyEl !== cur.bodyEl;
      const marksGone = cur.marked && open.bodyEl && !open.bodyEl.querySelector('.phishguard-mark, .phishguard-link-flag');
      if (bodyChanged || marksGone) {
        cur.bodyEl = open.bodyEl;
        cur.linkEls = open.linkEls;
        applyHighlights();
      }
      return;
    }

    // A different email is open (or a rescan was requested).
    if (!cur || cur.data.from.address !== open.data.from.address || cur.data.subject !== open.data.subject) lastSelection = '';
    if (pendingReply && pendingReply.id !== emailId(open.data)) pendingReply = null; // moved on to another email
    clearHighlights();
    const id = ++runId;
    cur = {
      key: sig, data: open.data, bodyEl: open.bodyEl, linkEls: open.linkEls,
      result: null, ai: { status: 'off' }, highlightsOn: settings.highlight.enabled !== false, marked: false, notice: ''
    };
    ui.mount();
    ui.setVisible(settings.ui.showBadge !== false);
    ui.setLoading();

    let resp;
    try {
      resp = await send({ type: 'analyze', email: open.data, site: adapter.id });
    } catch (e) {
      resp = { ok: false, error: e.message };
    }
    if (id !== runId) return;
    if (!resp || !resp.ok) {
      cur.result = { score: 0, verdict: 'safe', findings: [], links: [], notes: [], summary: 'Off the Hook could not analyze this email.' };
      cur.notice = (resp && resp.error) || 'Analysis failed.';
      render();
      return;
    }
    if (resp.settings) applySettings(resp.settings);
    cur.result = resp.result;
    cur.ai = { status: resp.aiEnabled ? 'pending' : 'off' };
    applyHighlights();
    render();

    if (resp.aiEnabled) {
      let aiResp;
      try {
        aiResp = await send({ type: 'analyzeAI', email: open.data, ruleResult: resp.result });
      } catch (e) {
        aiResp = { ok: false, error: e.message };
      }
      if (id !== runId) return;
      cur.ai = aiResp && aiResp.ok
        ? { status: 'done', data: aiResp.ai, combined: aiResp.combined, providerLabel: aiResp.providerLabel }
        : { status: 'failed', error: (aiResp && aiResp.error) || 'Unknown error' };
      applyHighlights();
      render();
    }
  }

  function schedule(delay) {
    if (dead) return;
    clearTimeout(timer);
    timer = setTimeout(() => {
      check().catch(e => console.warn('[Off the Hook] check failed:', e && e.message));
    }, delay == null ? 450 : delay);
  }

  // ---- settings ----
  function applySettings(s) {
    settings = s;
    HL.setColors(s.highlight && s.highlight.colors);
    if (cur) ui.setVisible(s.ui.showBadge !== false);
  }

  async function refreshSettings(rescan) {
    try {
      const r = await send({ type: 'getPublicSettings' });
      if (r && r.ok) applySettings(r.settings);
    } catch (e) { return; }
    if (!rescan) return;
    listScan.reset(); // new settings or reports can change any row's tag
    if (cur) {
      cur.key = null;
      cur.highlightsOn = settings.highlight.enabled !== false;
    }
    schedule(0);
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && (changes.settings || changes.secrets || changes.feedback)) refreshSettings(true);
  });

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (sender.id !== chrome.runtime.id) return;
    if (msg && msg.type === 'toggleHighlights') { toggleHighlights(); sendResponse({ ok: true, on: !!(cur && cur.highlightsOn) }); }
    else if (msg && msg.type === 'rescan') { if (cur) cur.key = null; schedule(0); sendResponse({ ok: true }); }
  });

  // ---- observe the page ----
  const observer = new MutationObserver(records => {
    // Ignore mutations that only touch our own elements.
    for (const r of records) {
      const t = r.target;
      if (t.nodeType === 1 && (t.id === 'phishguard-root' || (t.className && String(t.className).includes('phishguard-')))) continue;
      schedule();
      return;
    }
  });
  function startObserving() {
    if (!dead) observer.observe(document.body || document.documentElement, { childList: true, subtree: true, characterData: true });
  }

  function shutdown() {
    if (dead) return;
    dead = true;
    observer.disconnect();
    clearTimeout(timer);
    if (cur) { cur.notice = 'Off the Hook was updated or removed. Reload this page to keep scanning.'; render(); }
  }

  // Inspection hook for dev/demo.html only (never set on real webmail pages).
  if (globalThis.PHISHGUARD_FORCE_ADAPTER) {
    globalThis.__phishguardDebug = { state: () => ({ cur, runId, dead, settings }), check };
  }

  window.addEventListener('hashchange', () => schedule(150));
  window.addEventListener('popstate', () => schedule(150));

  refreshSettings(false).finally(() => {
    startObserving();
    schedule(0);
  });
})();
