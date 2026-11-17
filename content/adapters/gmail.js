/*
 * Gmail adapter (mail.google.com).
 *
 * Gmail's markup uses short generated class names that change occasionally. When
 * detection stops working, update the SELECTORS below; each entry is a list tried in order.
 */
(function () {
  'use strict';
  const { helpers: H } = globalThis.PhishGuardAdapters;

  const SELECTORS = {
    // An expanded message inside a conversation.
    message: ['div.adn.ads', 'div[role="listitem"] div.adn', 'div.h7 div.adn'],
    // Message body inside a message.
    body: ['div.a3s.aiL', 'div.a3s', 'div[data-message-id] div[dir="ltr"]'],
    // Sender element; Gmail puts the real address in an "email" attribute.
    sender: ['span.gD[email]', 'h3.iw span[email]', 'span[email][name]'],
    subject: ['h2.hP', 'h2[data-thread-perm-id]', 'div.ha h2'],
    // Attachment cards and their file-name labels.
    attachmentCard: ['span.aZo', 'div.aQH span[download_url]', 'div.aQH div.aZo'],
    attachmentName: ['span.aV3', 'div.aV3', '.aQA span'],
    // "Show original" page (view=om): raw message text.
    rawMessage: ['#raw_message_text', 'pre.raw_message_text', 'pre'],
    // Inbox list: one row per conversation, with sender, subject and preview ("snippet").
    listRow: ['tr.zA'],
    listSender: ['span.zF[email]', 'span.yP[email]', 'span[email]'],
    listSubject: ['span.bog', '.y6 span:not(.phishguard-row-tag)'],
    listSnippet: ['span.y2']
  };

  function listRows() {
    return H.all(document, SELECTORS.listRow).filter(H.isVisible).slice(0, 100).map(el => {
      const s = H.first(el, SELECTORS.listSender);
      return { el, key: (s ? s.getAttribute('email') : '') + '\u0001' + el.textContent, read: () => readRow(el) };
    });
  }
  function readRow(el) {
    const s = H.first(el, SELECTORS.listSender);
    const subj = H.first(el, SELECTORS.listSubject);
    const snip = H.first(el, SELECTORS.listSnippet);
    if (!subj && !snip) return null;
    return {
      data: {
        from: s ? { name: s.getAttribute('name') || H.text(s), address: (s.getAttribute('email') || '').toLowerCase() } : { name: '', address: '' },
        subject: subj ? H.text(subj) : '',
        body: snip ? H.text(snip).replace(/^[-–—\s]+/, '') : ''
      },
      anchorEl: subj || snip
    };
  }

  function findReplyTo(msgEl) {
    // Only available when the header details dropdown is open.
    const cells = Array.from(document.querySelectorAll('table td, table span'));
    for (const c of cells) {
      if (!/^\s*reply-to:\s*$/i.test(c.textContent || '')) continue;
      const row = c.closest('tr');
      const el = row && row.querySelector('span[email]');
      if (el) return [el.getAttribute('email')];
    }
    return [];
  }

  // Gmail's own red/yellow warning banners (English UI). Searched in the message element
  // with the body text removed, since attackers control the body.
  const WARNING_RE = /Be careful with this message|This message seems dangerous|Similar messages were used to steal people['’]s personal information|This message might be (suspicious|dangerous)|has been flagged as (phishing|dangerous)/i;
  function providerWarnings(msgEl, bodyEl) {
    const text = (msgEl.textContent || '').replace(bodyEl.textContent || '', ' ');
    const m = text.match(WARNING_RE);
    return m ? [{ level: 'high', text: m[0] }] : [];
  }

  function attachments(msgEl) {
    const names = new Set();
    for (const card of H.all(msgEl, SELECTORS.attachmentCard)) {
      const du = card.getAttribute('download_url');
      if (du) { const parts = du.split(':'); if (parts[1]) names.add(parts[1]); }
      const label = H.first(card, SELECTORS.attachmentName);
      if (label && H.text(label)) names.add(H.text(label));
    }
    return Array.from(names);
  }

  function showOriginal() {
    const pre = H.all(document, SELECTORS.rawMessage).sort((a, b) => (b.textContent || '').length - (a.textContent || '').length)[0];
    if (!pre) return null;
    const raw = pre.textContent || '';
    if (!/^(received|delivered-to|return-path|mime-version|from):/im.test(raw)) return null;
    const h = H.parseRawHeaders(raw);
    const from = H.parseAddress((h.from || [''])[0]);
    return {
      data: {
        from,
        replyTo: (h['reply-to'] || []).map(v => H.parseAddress(v).address).filter(Boolean),
        subject: (h.subject || [''])[0],
        body: '',
        links: [],
        attachments: [],
        authResults: (h['authentication-results'] || []).join('\n') + '\n' + (h['arc-authentication-results'] || []).join('\n'),
        headers: Object.fromEntries(['return-path', 'reply-to', 'from', 'received-spf'].filter(k => h[k]).map(k => [k, h[k]])),
        headersOnly: true
      },
      bodyEl: null,
      linkEls: [],
      containerEl: pre
    };
  }

  const adapter = {
    id: 'gmail',
    name: 'Gmail',
    matches: loc => loc.hostname === 'mail.google.com',
    getListRows: listRows,

    getOpenEmail() {
      if (/[?&]view=om\b/.test(location.search)) return showOriginal();

      const messages = H.all(document, SELECTORS.message).filter(H.isVisible);
      if (!messages.length) return null;
      // Gmail shows newest last; analyze the most recent expanded message.
      const msgEl = messages[messages.length - 1];
      const bodyEl = H.all(msgEl, SELECTORS.body).find(b => !H.isEditable(b));
      if (!bodyEl) return null;

      const senderEl = H.first(msgEl, SELECTORS.sender);
      const from = senderEl
        ? { name: senderEl.getAttribute('name') || H.text(senderEl), address: (senderEl.getAttribute('email') || '').toLowerCase() }
        : { name: '', address: '' };
      const subjectEl = Array.from(document.querySelectorAll(SELECTORS.subject.join(','))).find(H.isVisible);
      const { linkEls, links } = H.collectLinks(bodyEl);

      return {
        data: Object.assign({
          from,
          replyTo: findReplyTo(msgEl),
          subject: subjectEl ? H.text(subjectEl) : '',
          body: H.bodyText(bodyEl),
          links,
          attachments: attachments(msgEl),
          authResults: null,
          providerWarnings: providerWarnings(msgEl, bodyEl)
        }, H.collectImages(bodyEl)),
        bodyEl,
        linkEls,
        containerEl: msgEl
      };
    }
  };

  globalThis.PhishGuardAdapters.register(adapter);
})();
