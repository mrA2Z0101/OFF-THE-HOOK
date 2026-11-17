/*
 * Adapter registry and DOM helpers shared by the per-site adapters.
 *
 * An adapter is { id, name, matches(location) -> bool, getOpenEmail() -> OpenEmail|null }
 * OpenEmail = {
 *   data:     emailData for the analyzer (plain values only, see shared/analyzer.js),
 *   bodyEl:   element containing the message body (for highlighting) or null,
 *   linkEls:  anchors in the same order as data.links,
 *   containerEl: the message element (used to detect when the open email changes)
 * }
 *
 * Optional: getListRows() -> [{ el, key, read() -> ListRow|null }] for the inbox message list.
 *   key:  cheap text fingerprint of the row (changes when the row's content changes)
 *   ListRow = { data: { from, subject, body (preview line), providerWarnings }, anchorEl }
 *   anchorEl: element the row tag is placed inside, at the start (usually the subject)
 */
(function () {
  'use strict';
  const registry = [];

  const helpers = {
    // Return the first element matching any selector in the list.
    first(rootEl, selectors) {
      for (const sel of selectors) {
        try {
          const el = rootEl.querySelector(sel);
          if (el) return el;
        } catch (e) { /* invalid selector in a list: skip */ }
      }
      return null;
    },
    all(rootEl, selectors) {
      for (const sel of selectors) {
        try {
          const list = Array.from(rootEl.querySelectorAll(sel));
          if (list.length) return list;
        } catch (e) { /* skip */ }
      }
      return [];
    },
    isVisible(el) {
      if (!el || !el.isConnected) return false;
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    },
    // Inside a box the user can type in (a reply or new message being written)?
    isEditable(el) {
      return !!(el && (el.isContentEditable || (el.closest && el.closest('[contenteditable="true"], [contenteditable=""], textarea'))));
    },
    text(el) {
      return el ? (el.innerText || el.textContent || '').trim() : '';
    },
    // "Name <addr@x.com>" / "addr@x.com" -> { name, address }
    parseAddress(s) {
      s = String(s || '').trim();
      const m = s.match(/^\s*"?([^"<]*?)"?\s*<\s*([^<>\s]+@[^<>\s]+)\s*>/);
      if (m) return { name: m[1].trim(), address: m[2].trim().toLowerCase() };
      const a = s.match(/[^\s<>"',;]+@[^\s<>"',;]+/);
      return { name: '', address: a ? a[0].toLowerCase() : '' };
    },
    // Links in the body, skipping our own badges.
    collectLinks(bodyEl) {
      const linkEls = Array.from(bodyEl.querySelectorAll('a[href]')).filter(a => !a.closest('.phishguard-link-badge'));
      const links = linkEls.map(a => ({ text: (a.innerText || a.textContent || '').trim().slice(0, 300), href: a.getAttribute('href') || '' }));
      return { linkEls, links };
    },
    // Images that are big enough to be content (ignores 1x1 tracking pixels).
    collectImages(bodyEl) {
      const imgs = Array.from(bodyEl.querySelectorAll('img')).filter(img => {
        const w = img.naturalWidth || img.width, h = img.naturalHeight || img.height;
        return !(w && h && w <= 3 && h <= 3);
      });
      return { imageCount: imgs.length, imageAlts: imgs.map(i => i.getAttribute('alt') || '').filter(Boolean).slice(0, 20) };
    },
    // Visible lines of text in an element (our row tags draw their text with CSS, so they never appear).
    lines(el) {
      return String((el && (el.innerText || el.textContent)) || '').split('\n').map(l => l.replace(/\s+/g, ' ').trim()).filter(Boolean);
    },
    // Deepest element inside root whose whole text is exactly `text` (e.g. the subject span).
    elementWithText(root, text) {
      if (!root || !text) return null;
      let hit = null;
      const els = root.querySelectorAll('span, div, p, h1, h2, h3, h4, a, strong, b');
      for (let i = 0; i < els.length && i < 400; i++) {
        if (els[i].closest('.phishguard-row-tag')) continue;
        if ((els[i].textContent || '').replace(/\s+/g, ' ').trim() === text) hit = els[i];
      }
      return hit;
    },
    // Visible text of the body. (Our badges render their text via CSS, so it never appears here.)
    bodyText(bodyEl) {
      return (bodyEl.innerText || bodyEl.textContent || '').slice(0, 100000);
    },
    // Parse raw RFC 5322 headers (for "show original" pages).
    parseRawHeaders(raw) {
      const headers = {};
      const lines = String(raw || '').split(/\r?\n/);
      let current = null;
      for (const line of lines) {
        if (line === '') break; // end of headers
        if (/^[ \t]/.test(line) && current) { current.value += ' ' + line.trim(); continue; }
        const m = line.match(/^([!-9;-~]+):\s?(.*)$/);
        if (!m) continue;
        current = { name: m[1].toLowerCase(), value: m[2] };
        (headers[current.name] = headers[current.name] || []).push(current);
      }
      const out = {};
      for (const k of Object.keys(headers)) out[k] = headers[k].map(h => h.value);
      return out;
    },
    // Header text shown inside a dialog (e.g. Outlook "Message details"): skips any title or
    // button text before the first real header line, then parses normally.
    parseHeaderBlock(text) {
      const lines = String(text || '').replace(/\r/g, '').split('\n');
      const start = lines.findIndex(l => /^(Received|Return-Path|Delivered-To|Authentication-Results|ARC-[A-Za-z-]+|X-[A-Za-z0-9-]+|DKIM-Signature|From|To|Subject|Date|Message-ID|MIME-Version|Content-Type|Thread-Topic):/i.test(l));
      if (start < 0) return {};
      return helpers.parseRawHeaders(lines.slice(start).join('\n'));
    },
    // Does this text look like a raw email header block?
    looksLikeHeaders(text) {
      const t = String(text || '');
      if (t.length < 80) return false;
      let hits = 0;
      for (const re of [/^Received:/im, /^Message-ID:/im, /^From:/im, /^Subject:/im, /^Authentication-Results:/im, /^Return-Path:/im, /^X-MS-Exchange-/im, /^MIME-Version:/im])
        if (re.test(t)) hits++;
      return hits >= 3;
    },
    // Decode RFC 2047 "encoded words" (=?utf-8?B?...?= / =?utf-8?Q?...?=) in Subject/From headers.
    decodeMimeWords(s) {
      return String(s || '').replace(/\?=\s+=\?/g, '?==?').replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (m, charset, enc, data) => {
        try {
          let bytes;
          if (enc.toUpperCase() === 'B') bytes = Uint8Array.from(atob(data), c => c.charCodeAt(0));
          else {
            const t = data.replace(/_/g, ' ');
            const arr = [];
            for (let i = 0; i < t.length; i++) {
              if (t[i] === '=' && /^[0-9A-Fa-f]{2}$/.test(t.slice(i + 1, i + 3))) { arr.push(parseInt(t.slice(i + 1, i + 3), 16)); i += 2; }
              else arr.push(t.charCodeAt(i));
            }
            bytes = Uint8Array.from(arr);
          }
          return new TextDecoder(charset.toLowerCase()).decode(bytes);
        } catch (e) { return m; }
      });
    }
  };

  globalThis.PhishGuardAdapters = {
    helpers,
    register(adapter) { registry.push(adapter); },
    pick(loc) {
      const forced = globalThis.PHISHGUARD_FORCE_ADAPTER; // used by dev/demo.html only
      if (forced) return registry.find(a => a.id === forced) || null;
      return registry.find(a => a.matches(loc)) || null;
    }
  };
})();
