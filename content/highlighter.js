/*
 * Highlights suspicious phrases and links inside the open email.
 *
 * Safety: email content is never parsed as HTML. We walk existing text nodes with a
 * TreeWalker, split them, and wrap matches in <mark> elements whose text is set with
 * textContent. Everything we add carries a "phishguard-" class so it can be removed.
 */
(function () {
  'use strict';

  const MARK = 'phishguard-mark';
  const BADGE = 'phishguard-link-badge';
  const LINK = 'phishguard-link-flag';
  const SKIP_BASE = 'script,style,noscript,textarea,input,select,option,.' + BADGE;
  const SKIP_ALL_MARKS = SKIP_BASE + ',mark.' + MARK;
  // Second pass may nest rule marks inside AI-only marks (longer AI phrases).
  const SKIP_RULE_MARKS = SKIP_BASE + ',mark.' + MARK + ':not(.phishguard-ai-only)';
  const MAX_MARKS = 400;
  const SEV_LABEL = { high: 'High risk', medium: 'Medium risk', low: 'Low risk' };

  const escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const keyOf = s => String(s).toLowerCase().replace(/[\u2018\u2019]/g, "'").replace(/[\u201C\u201D]/g, '"').replace(/\s+/g, ' ').trim();

  // Whole-word boundaries without /u property escapes (much cheaper to compile).
  const WORD = 'A-Za-z0-9_\\u00C0-\\u024F\\u0370-\\u052F';
  const WORD_CHAR_RE = new RegExp('[' + WORD + ']');
  function sourceFor(text) {
    const t = text.trim();
    let src = escapeRe(t).replace(/\s+/g, '\\s+').replace(/'/g, "['\u2018\u2019]").replace(/"/g, '["\u201C\u201D]');
    if (WORD_CHAR_RE.test(t[0])) src = '(?<![' + WORD + '])' + src;
    if (WORD_CHAR_RE.test(t[t.length - 1])) src += '(?![' + WORD + '])';
    return src;
  }

  /**
   * Highlight rule matches and AI phrases. AI-only phrases are wrapped first so that
   * rule matches inside a longer AI phrase still get their own severity mark.
   * @param {Element} root
   * @param {Array<{text, severity, reason, title}>} ruleItems
   * @param {Array<{text, reason}>} aiItems
   * @returns {number} marks created
   */
  function highlightAll(root, ruleItems, aiItems) {
    const ruleKeys = new Set((ruleItems || []).map(i => keyOf(i.text)));
    const ai = (aiItems || []).map(i => Object.assign({ source: 'ai' }, i));
    const aiOnly = ai.filter(i => !ruleKeys.has(keyOf(i.text)));
    const shared = ai.filter(i => ruleKeys.has(keyOf(i.text)));
    const rules = (ruleItems || []).map(i => Object.assign({ source: 'rule' }, i));
    return highlightText(root, aiOnly, SKIP_ALL_MARKS, true) + highlightText(root, rules.concat(shared), SKIP_RULE_MARKS, false);
  }

  function highlightText(root, items, skip, aiOnlyPass) {
    if (!root || !items || !items.length) return 0;
    const index = new Map();
    for (const it of items) {
      const text = String(it.text || '').trim();
      if (text.length < 2) continue;
      const k = keyOf(text);
      let e = index.get(k);
      if (!e) { e = { text, severity: null, ai: false, tips: [], items: [] }; index.set(k, e); }
      // items feed the hover card (content/linkcard.js); tips feed screen readers.
      if (it.source === 'ai') {
        e.ai = true;
        e.tips.push('AI: ' + it.reason);
        e.items.push({ source: 'ai', reason: String(it.reason || '') });
      } else {
        const rank = { high: 3, medium: 2, low: 1 };
        if (!e.severity || rank[it.severity] > rank[e.severity]) e.severity = it.severity;
        e.tips.push((SEV_LABEL[it.severity] || 'Warning') + ' · ' + (it.title ? it.title + ': ' : '') + it.reason);
        e.items.push({ source: 'rule', severity: it.severity, title: String(it.title || ''), reason: String(it.reason || '') });
      }
    }
    if (!index.size) return 0;

    const sources = Array.from(index.values()).map(e => e.text).sort((a, b) => b.length - a.length).map(sourceFor);
    let re;
    try { re = new RegExp(sources.join('|'), 'gi'); } catch (e) { return 0; }

    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(n) {
        if (!n.nodeValue || !n.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
        const p = n.parentElement;
        if (!p || p.closest(skip)) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);

    let count = 0;
    for (const node of nodes) {
      const text = node.nodeValue;
      re.lastIndex = 0;
      let m, last = 0, frag = null;
      while ((m = re.exec(text))) {
        if (!m[0]) { re.lastIndex++; continue; }
        const info = index.get(keyOf(m[0]));
        if (!info) continue;
        frag = frag || document.createDocumentFragment();
        if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
        const mark = document.createElement('mark');
        mark.className = MARK + ' phishguard-' + (info.severity || 'ai') + (info.ai ? ' phishguard-ai' : '') + (aiOnlyPass ? ' phishguard-ai-only' : '');
        mark.textContent = m[0];
        // Stored as an attribute string and only ever read back with JSON.parse + textContent.
        mark.dataset.pgInfo = JSON.stringify(info.items);
        mark.setAttribute('aria-description', 'Off the Hook: ' + info.tips.join('. '));
        frag.appendChild(mark);
        last = m.index + m[0].length;
        if (++count >= MAX_MARKS) break;
      }
      if (frag) {
        if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
        node.parentNode.replaceChild(frag, node);
      }
      if (count >= MAX_MARKS) break;
    }
    return count;
  }

  /** Outline flagged links and add a "real destination" badge next to risky ones. */
  function markLinks(linkEls, linkReport, showBadges) {
    let count = 0;
    for (const entry of linkReport || []) {
      // QR code pictures always get a label saying where the code goes, even when it looks fine.
      if (!entry.qr && (!entry.flags || !entry.flags.length)) continue;
      const a = linkEls[entry.index];
      if (!a || !a.isConnected) continue;
      const what = entry.qr ? 'QR code' : 'link';
      const tip = `${SEV_LABEL[entry.severity] || 'Checked'} ${what} · ${entry.flags.join(', ') || 'no warning signs'}\nReal destination: ${entry.display}`;
      a.classList.add(LINK, 'phishguard-' + (entry.severity || 'low'));
      a.setAttribute('aria-description', 'Off the Hook: ' + tip);
      if (showBadges && entry.domain && (entry.qr || entry.severity === 'high' || entry.severity === 'medium')) {
        const badge = document.createElement('span');
        badge.className = BADGE + ' phishguard-' + (entry.severity || 'low');
        badge.setAttribute('role', 'note');
        // Text is drawn by CSS (::before) so it never mixes into the email's own text.
        badge.dataset.pgLabel = entry.qr
          ? (entry.severity ? '⚠ QR code goes to: ' : 'QR code goes to: ') + entry.domain
          : '⚠ Real destination: ' + entry.domain;
        badge.setAttribute('aria-label', (entry.qr ? 'This QR code goes to ' : 'Warning: this link really goes to ') + entry.domain);
        badge.dataset.pgIndex = String(entry.index); // hovering the badge shows that link's card
        a.insertAdjacentElement('afterend', badge);
      }
      count++;
    }
    return count;
  }

  function clear(root) {
    if (!root) return;
    const parents = new Set();
    root.querySelectorAll('mark.' + MARK).forEach(m => {
      parents.add(m.parentNode);
      m.replaceWith(document.createTextNode(m.textContent));
    });
    parents.forEach(p => p && p.normalize && p.normalize());
    root.querySelectorAll('.' + BADGE).forEach(b => b.remove());
    root.querySelectorAll('.' + LINK).forEach(a => {
      a.classList.remove(LINK, 'phishguard-high', 'phishguard-medium', 'phishguard-low');
      a.removeAttribute('aria-description');
    });
  }

  function setColors(colors) {
    const s = document.documentElement.style;
    for (const k of ['high', 'medium', 'low', 'ai']) {
      if (colors && /^#[0-9a-f]{3,8}$/i.test(colors[k] || '')) s.setProperty('--phishguard-' + k, colors[k]);
    }
  }

  globalThis.PhishGuardHighlighter = { highlightAll, markLinks, clear, setColors };
})();
