/*
 * Outlook on the web adapter (outlook.live.com, outlook.office.com,
 * outlook.office365.com, outlook.cloud.microsoft).
 *
 * Outlook's markup is heavily generated and partly localized, so this adapter relies
 * on ARIA roles/labels plus text heuristics. Update SELECTORS when Outlook changes.
 */
(function () {
  'use strict';
  const { helpers: H } = globalThis.PhishGuardAdapters;

  const SELECTORS = {
    readingPane: [
      '#ConversationReadingPaneContainer', '[data-app-section="ConversationContainer"]',
      '#ReadingPaneContainerId', 'div[role="main"]'
    ],
    // Message body elements (one per expanded message).
    body: [
      'div[aria-label="Message body"]', 'div[aria-label="Corps du message"]', 'div[aria-label="Nachrichtentext"]',
      'div[aria-label="Cuerpo del mensaje"]', 'div[id^="UniqueMessageBody"]', 'div.allowTextSelection div[role="document"]',
      'div[role="document"]'
    ],
    subject: [
      '[role="heading"][aria-level="2"]', '#ConversationReadingPaneContainer [role="heading"]',
      'div[role="main"] span[title][id$="_SUBJECT"]', 'div[role="main"] h1'
    ],
    // Elements likely to carry the sender ("Name <address>") in the message header.
    senderCandidates: [
      'span[title*="@"]', 'div[title*="@"]', 'button[title*="@"]', '[aria-label^="From:"]',
      '[aria-label^="From "]', 'a[href^="mailto:"]', '[aria-label*="@"]', 'span.OZZZK', 'span.lDdSm'
    ],
    attachments: [
      'div[role="listbox"][aria-label*="ttach"] [role="option"]', '[data-testid="attachment-card"]',
      'div[aria-label*="ttachment"] [title]', 'div[role="attachment"]'
    ]
  };

  const FILE_RE = /([^\\/:*?"<>|\r\n]+\.[a-z0-9]{1,8})(?=\s|$|\s*\(|\s*\d)/i;

  // The message "card": the largest ancestor of the body that is still about this one
  // message (stops before reaching the message list or other conversation items).
  function messageContainerOf(bodyEl) {
    const bodyLen = (bodyEl.textContent || '').length;
    let best = bodyEl.parentElement || bodyEl;
    for (let el = best, i = 0; i < 12 && el && el !== document.body; i++, el = el.parentElement) {
      if ((el.textContent || '').length > bodyLen + 3000) break;
      best = el;
    }
    return best;
  }

  const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/;
  const RECIPIENT_LINE_RE = /^\s*(To|Cc|Bcc|À|An|Para|Para:)\s*:/i;

  // Outlook shows coworkers by name only; their address often still sits in an attribute
  // (title, aria-label, mailto href, data-*). Scan the header in page order, skipping the
  // To/Cc lines so the recipient (you) is never mistaken for the sender.
  function addressFromAttributes(container, bodyEl) {
    const els = container.querySelectorAll('*');
    for (let i = 0; i < els.length && i < 2000; i++) {
      const el = els[i];
      if (el === bodyEl || bodyEl.contains(el)) continue;
      if (inRecipientLine(el)) continue;
      for (const attr of el.attributes) {
        if (attr.name === 'class' || attr.name === 'style' || attr.name === 'src') continue;
        const v = attr.value || '';
        if (!v.includes('@')) continue;
        const m = v.replace(/^mailto:/i, '').match(EMAIL_RE);
        if (m) return { address: m[0].toLowerCase(), el };
      }
    }
    return null;
  }
  function inRecipientLine(el) {
    let p = el;
    for (let i = 0; i < 4 && p; i++, p = p.parentElement) {
      if (RECIPIENT_LINE_RE.test(p.textContent || '') || RECIPIENT_LINE_RE.test(p.getAttribute && (p.getAttribute('aria-label') || '') || '')) return true;
    }
    return false;
  }

  function findSender(container, bodyEl) {
    for (const el of H.all(container, SELECTORS.senderCandidates)) {
      if (bodyEl.contains(el) || inRecipientLine(el)) continue;
      const parts =[el.getAttribute('title'), el.getAttribute('aria-label'), el.textContent]
        .filter(Boolean).map(p => p.replace(/^From:?\s*/i, '').trim());
      let address = '', name = '';
      for (const p of parts) {
        const parsed = H.parseAddress(p);
        if (!address && parsed.address) address = parsed.address;
        // Name comes from "Name <addr>" text, or from text that has no address in it at all.
        if (!name && parsed.name) name = parsed.name;
        if (!name && p && !p.includes('@')) name = p;
      }
      if (address) {
        // Look one level up too: Outlook often splits name and address into sibling spans.
        if (!name && el.parentElement) {
          const parsed = H.parseAddress(el.parentElement.textContent || '');
          if (parsed.name) name = parsed.name;
        }
        return { name: name.slice(0, 200), address };
      }
    }
    // Fallback 1: scan header text before the body for "Name <addr>".
    const headerText = (container.innerText || '').split(H.text(bodyEl).slice(0, 40))[0] || '';
    const m = headerText.match(/([^\n<>]{1,80})<([^<>\s]+@[^<>\s]+)>/);
    if (m) return { name: m[1].trim(), address: m[2].toLowerCase() };

    // Fallback 2: an address hidden in an attribute of the header.
    const name = senderNameOnly(container, bodyEl, headerText);
    const hit = addressFromAttributes(container, bodyEl);
    if (hit) return { name, address: hit.address };

    // Name only: the analyzer will say it couldn't check the address.
    return { name, address: '' };
  }

  // Best guess at the visible sender name when no address is shown.
  function senderNameOnly(container, bodyEl, headerText) {
    for (const el of H.all(container, SELECTORS.senderCandidates)) {
      if (bodyEl.contains(el) || inRecipientLine(el)) continue;
      const t = (el.textContent || '').trim();
      if (t && t.length <= 120 && !t.includes('@')) return t;
    }
    // First non-empty header line that isn't a To/Cc line, date, or button label.
    for (const line of headerText.split('\n').map(l => l.trim())) {
      if (!line || line.length > 80 || RECIPIENT_LINE_RE.test(line) || /\d{1,2}:\d{2}|^(Reply|Forward|Reply all|Summarize)/i.test(line)) continue;
      if (/^[A-Za-z][A-Za-z .,'\-]{1,79}$/.test(line)) return line;
    }
    return '';
  }

  function attachments(container) {
    const names = new Set();
    for (const el of H.all(container, SELECTORS.attachments)) {
      for (const s of [el.getAttribute('title'), el.getAttribute('aria-label'), el.textContent]) {
        const m = s && s.trim().match(FILE_RE);
        if (m) { names.add(m[1].trim()); break; }
      }
    }
    return Array.from(names).slice(0, 30);
  }

  // Outlook's own safety banners (English UI; other languages are simply not detected).
  const WARNINGS = [
    { level: 'high', re: /failed our fraud detection checks|may not be who (they|it) appears? to be|This (message|sender) (might be|is|looks) (suspicious|dangerous|phishing)|identified (this|it) as (phishing|junk)/i },
    // Lazy domain match so "gmail.com.Learn why…" (no space between elements) stops at ".com".
    // Case-sensitive on purpose: a lowercase TLD stops before the capital "L" of "Learn".
    { level: 'low', re: /[Yy]ou don['’]t often get email from(\s+[\w.+-]+@[\w-]+?(\.[\w-]+?)*\.[a-z]{2,}(?![a-z]))?/ }
  ];
  function providerWarnings(bodyEl) {
    // Walk outward from the body through the message card only. The message list also shows
    // "You don't often get email from…" as preview text for other emails, so stop once an
    // ancestor holds much more text than this message. The body itself is excluded because
    // attackers can type anything there.
    const bodyText = bodyEl.textContent || '';
    const found = new Map();
    let el = bodyEl.parentElement;
    for (let i = 0; i < 8 && el && el !== document.body; i++, el = el.parentElement) {
      const all = el.textContent || '';
      if (all.length > bodyText.length + 4000) break;
      const text = all.replace(bodyText, ' ');
      for (const w of WARNINGS) {
        if (found.has(w.level)) continue;
        const m = text.match(w.re);
        if (m) found.set(w.level, { level: w.level, text: m[0].trim() });
      }
    }
    return Array.from(found.values());
  }

  // Outlook "… → View → View message details" opens a dialog with the raw message header.
  // We look for any open dialog (or text box inside one) whose text is a header block.
  const HEADER_DIALOG = ['[role="dialog"]', '[role="alertdialog"]', '.ms-Dialog', '.ms-Modal'];
  function headerText() {
    for (const dlg of H.all(document, HEADER_DIALOG)) {
      if (!H.isVisible(dlg) || dlg.closest('#phishguard-root, #phishguard-linkcard')) continue;
      const boxes = Array.from(dlg.querySelectorAll('textarea, pre, [contenteditable="true"]'));
      for (const b of boxes) {
        const t = b.value != null && b.tagName === 'TEXTAREA' ? b.value : (b.innerText || b.textContent || '');
        if (H.looksLikeHeaders(t)) return t;
      }
      const t = dlg.innerText || dlg.textContent || '';
      if (H.looksLikeHeaders(t)) return t;
    }
    return '';
  }

  // ---- inbox message list ----
  // Rows are read from their visible text: sender line, subject line, then the preview.
  // Times, dates, counts and tags like "External" are dropped first.
  const LIST = {
    row: ['div[data-convid]', '[role="listbox"] [role="option"]'],
    notMessageList: /attach|suggest|people|contact|folder|search|recipient|account/i
  };
  const MONTH = '(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\\.?';
  const DAY = '(Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*';
  const TIME = '\\d{1,2}:\\d{2}(\\s?[AaPp]\\.?[Mm]\\.?)?';
  const DATE = '\\d{1,2}[/.-]\\d{1,2}([/.-]\\d{2,4})?';
  const NOISE_RE = new RegExp(`^(${TIME}|${DAY}( ${TIME}| ${DATE})?|${DATE}|${MONTH} \\d{1,2}(, \\d{4})?|(Yesterday|Today)( ${TIME})?|\\(?\\d{1,4}\\)?|External|Unverified|Draft|\\[Draft\\])$`, 'i');
  // Outlook puts its first-contact banner at the start of the preview line.
  const FIRST_CONTACT_RE = /^[Yy]ou don['’]t often get email from\s+\S+?\.?(\s+Learn why this is important\.?)?(\s+|$)/;

  function listRows() {
    const found = new Set(LIST.row.flatMap(sel => Array.from(document.querySelectorAll(sel))));
    let rows = Array.from(found).filter(el => {
      if (el.closest('#phishguard-root, #phishguard-linkcard')) return false;
      if (el.querySelector(SELECTORS.body.join(','))) return false; // a reading-pane message, not a row
      const box = el.closest('[role="listbox"]');
      if (box && LIST.notMessageList.test(box.getAttribute('aria-label') || '')) return false;
      return H.isVisible(el);
    });
    rows = rows.filter(r => !rows.some(o => o !== r && o.contains(r))).slice(0, 100);
    return rows.map(el => ({ el, key: el.textContent + '\u0001' + titleAddresses(el), read: () => readRow(el) }));
  }
  function titleAddresses(el) {
    return Array.from(el.querySelectorAll('[title*="@"]'), t => t.getAttribute('title')).join(',');
  }
  // Only trust an address shown as the tooltip of the sender's name itself; the preview text
  // (which the sender controls) can contain any address.
  function senderTitleAddress(row, name) {
    for (const t of row.querySelectorAll('[title*="@"]')) {
      if ((t.textContent || '').replace(/\s+/g, ' ').trim() !== name) continue;
      const m = t.getAttribute('title').match(EMAIL_RE);
      if (m) return m[0].toLowerCase();
    }
    return '';
  }
  function readRow(el) {
    const lines = H.lines(el).filter(l => !NOISE_RE.test(l));
    if (lines.length < 2) return null;
    const [nameLine, subjectLine, ...rest] = lines;
    const parsed = H.parseAddress(nameLine);
    const name = parsed.address ? parsed.name : nameLine;
    const address = parsed.address || senderTitleAddress(el, nameLine);
    let body = rest.join(' ');
    const providerWarnings = [];
    const fc = body.match(FIRST_CONTACT_RE);
    if (fc) {
      providerWarnings.push({ level: 'low', text: "You don't often get email from this sender" });
      body = body.slice(fc[0].length);
    }
    return {
      data: { from: { name: name.slice(0, 200), address }, subject: /^\(no subject\)$/i.test(subjectLine) ? '' : subjectLine, body, providerWarnings },
      anchorEl: H.elementWithText(el, subjectLine) || H.elementWithText(el, nameLine)
    };
  }

  const adapter = {
    id: 'outlook',
    name: 'Outlook',
    matches: loc => /^outlook\.(live|office|office365)\.com$|^outlook\.cloud\.microsoft$/.test(loc.hostname),
    getHeaderText: headerText,
    getListRows: listRows,

    getOpenEmail() {
      const pane = H.first(document, SELECTORS.readingPane) || document;
      // Never the reply box you're typing in (it can carry similar labels).
      const bodies = H.all(pane, SELECTORS.body).filter(b => H.isVisible(b) && !H.isEditable(b));
      if (!bodies.length) return null;
      // Outlook lists the newest message first by default.
      const bodyEl = bodies[0];
      const container = messageContainerOf(bodyEl);
      const subjectEl = H.all(pane, SELECTORS.subject).find(H.isVisible);
      const { linkEls, links } = H.collectLinks(bodyEl);
      return {
        data: Object.assign({
          from: findSender(container, bodyEl),
          replyTo: [],
          subject: subjectEl ? (subjectEl.getAttribute('title') || H.text(subjectEl)) : '',
          body: H.bodyText(bodyEl),
          links,
          attachments: attachments(container),
          authResults: null,
          providerWarnings: providerWarnings(bodyEl)
        }, H.collectImages(bodyEl)),
        bodyEl,
        linkEls,
        containerEl: container
      };
    }
  };

  globalThis.PhishGuardAdapters.register(adapter);
})();
