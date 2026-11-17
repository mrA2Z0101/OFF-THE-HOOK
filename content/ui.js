/*
 * Floating verdict badge + details panel, rendered inside a Shadow DOM so webmail
 * styles cannot leak in (and ours cannot leak out). All text is set with textContent.
 */
(function () {
  'use strict';

  const VERDICT = {
    safe: { icon: '✓', label: 'Likely Safe' },
    suspicious: { icon: '!', label: 'Suspicious' },
    phishing: { icon: '✕', label: 'Likely Phishing' },
    pending: { icon: '…', label: 'Scanning…' }
  };
  const SEV = [
    { key: 'high', label: 'High risk', icon: '⚠' },
    { key: 'medium', label: 'Medium risk', icon: '◆' },
    { key: 'low', label: 'Low risk', icon: '●' }
  ];
  const CATEGORY_LABELS = {
    urgency: 'Urgency', credential_request: 'Credential request', impersonation: 'Impersonation',
    money_request: 'Money request', suspicious_link: 'Suspicious link', tone: 'Tone', other: 'Other'
  };

  // Panel-specific layout only. Colors and shared components come from shared/brand.js.
  const BRAND = globalThis.PhishGuard.brand;
  const PANEL_CSS = `
  :host { all: initial; }
  * { box-sizing: border-box; }
  .wrap {
    position: fixed; right: 20px; bottom: 20px; z-index: 2147483646;
    font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: var(--fg);
    display: flex; flex-direction: column; align-items: flex-end; gap: 10px;
  }
  button { font: inherit; color: inherit; cursor: pointer; }

  /* Floating badge: an ink sticker with a hard shadow in the verdict color. */
  .badge {
    display: inline-flex; align-items: center; gap: 8px; padding: 6px 14px 6px 7px;
    border-radius: 999px; border: 2px solid var(--vc, var(--muted)); background: var(--ink); color: var(--on-ink);
    box-shadow: 3px 3px 0 var(--vc, var(--muted)), 0 6px 16px rgba(0,0,0,.25); font-weight: 700; max-width: 320px;
    transition: transform .08s ease, box-shadow .08s ease;
  }
  .badge:hover { transform: translate(-1px, -1px); box-shadow: 4px 4px 0 var(--vc, var(--muted)), 0 8px 18px rgba(0,0,0,.28); }
  .badge .vicon { width: 24px; height: 24px; font-size: 14px; }
  .badge.v-suspicious .vicon { padding-top: 6px; font-size: 12px; }
  .badge .score { font-variant-numeric: tabular-nums; color: #c9cdd1; font-weight: 600; }
  .ai-dot { font-size: 11px; font-weight: 800; color: #fff; background: var(--pink); border-radius: 4px; padding: 0 4px; }

  .panel {
    width: min(400px, calc(100vw - 32px)); max-height: min(72vh, 680px); overflow: auto;
    background: var(--bg); border: 2px solid var(--edge); border-radius: 12px;
    box-shadow: 5px 5px 0 var(--edge), 0 12px 32px rgba(0,0,0,.3); padding: 0 0 10px;
  }
  .panel[hidden] { display: none; }
  .panel > .ot-bar { position: sticky; top: 0; z-index: 1; }
  .panel > .verdict { padding: 14px; }
  .section { padding: 10px 14px; }
  .panel-note { margin: 0 14px 8px; }
  .panel-note[hidden] { display: none; }
  .summary { margin: 0; padding: 0 14px 10px; }
  .panel > .actions { padding: 0 14px 12px; }
  .panel > .alertbox { margin: 0 14px 10px; }
  .panel > .disclaimer { margin: 10px 14px 0; }

  .report { margin: 10px 14px 0; padding: 10px 12px; border: 2px dashed var(--line); border-radius: 10px; background: var(--soft); }
  .report h3 { margin: 0 0 4px; }
  .report .actions { padding-top: 6px; }
  .report .actions button:not(.primary) { background: var(--bg); }
  .report textarea { width: 100%; margin-top: 6px; font: inherit; font-size: 13px; color: var(--fg); background: var(--bg);
    border: 2px solid var(--line); border-radius: 6px; padding: 5px 8px; resize: vertical; }
  .report .chips { margin-top: 6px; }
  .chip.removable { display: inline-flex; align-items: center; gap: 2px; }
  .chip .x { border: 0; background: transparent; color: inherit; padding: 0 2px; font-size: 14px; line-height: 1; cursor: pointer; }
  .rstatus { color: var(--pink-text); }

  .sender { margin: 0; padding: 0 14px 10px; font-size: 12px; color: var(--muted); overflow-wrap: anywhere; }
  .slabel { font-weight: 700; color: var(--fg); }

  ul { margin: 0; padding: 0; list-style: none; }
  .finding { padding: 8px 0; border-bottom: 1px dashed var(--line); }
  .finding:last-child { border-bottom: 0; }
  .ftitle { font-weight: 700; display: flex; gap: 6px; }
  .sev-high .sicon { color: var(--phishing-text); } .sev-medium .sicon { color: var(--suspicious-text); } .sev-low .sicon { color: var(--muted); }
  .fexp { margin: 2px 0 4px; color: var(--muted); font-size: 13px; }
  .ai-item .ftitle::before { content: "AI"; font-size: 10px; font-weight: 800; color: #fff; background: var(--ai); border-radius: 3px; padding: 1px 4px; height: fit-content; }
  .link { padding: 6px 0; border-bottom: 1px dashed var(--line); font-size: 13px; }
  .link:last-child { border-bottom: 0; }
  .ltext { color: var(--muted); overflow-wrap: anywhere; }
  .ldest { font-weight: 700; overflow-wrap: anywhere; }
  .lflags { display: block; color: var(--phishing-text); font-size: 12px; font-weight: 600; }
  .lfull { display: block; color: var(--muted); font: 11px/1.4 ui-monospace, Consolas, monospace; overflow-wrap: anywhere; }
  `;

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) {
      if (c == null || c === false) continue;
      el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return el;
  }

  function create(handlers) {
    const host = document.createElement('div');
    host.id = 'phishguard-root';
    const shadow = host.attachShadow({ mode: 'open' });
    BRAND.adopt(shadow, PANEL_CSS);
    const wrap = h('div', { class: 'wrap' });
    const panel = h('section', { class: 'panel', role: 'dialog', 'aria-modal': 'false', 'aria-labelledby': 'pg-title', id: 'pg-panel', hidden: true });
    const badge = h('button', { class: 'badge v-pending', type: 'button', 'aria-expanded': 'false', 'aria-controls': 'pg-panel' });
    wrap.append(panel, badge);
    shadow.appendChild(wrap);

    let state = null;
    let open = false;

    function setOpen(v, focusPanel) {
      open = v;
      panel.hidden = !v;
      badge.setAttribute('aria-expanded', String(v));
      if (v && focusPanel) { const t = panel.querySelector('h2'); if (t) t.focus(); }
    }
    badge.addEventListener('click', () => setOpen(!open, true));
    wrap.addEventListener('keydown', e => {
      if (e.key === 'Escape' && open) { e.stopPropagation(); setOpen(false); badge.focus(); }
    });

    function renderBadge() {
      badge.replaceChildren();
      if (!state || state.loading) {
        badge.className = 'badge v-pending';
        badge.append(h('span', { class: 'vicon', 'aria-hidden': 'true', text: '…' }), h('span', { text: 'Off the Hook: scanning…' }));
        badge.setAttribute('aria-label', 'Off the Hook is scanning this email');
        return;
      }
      const v = state.final.verdict;
      badge.className = 'badge v-' + v;
      const aiBit = state.ai.status === 'pending' ? h('span', { class: 'spin', 'aria-hidden': 'true' })
        : state.ai.status === 'done' ? h('span', { class: 'ai-dot', 'aria-hidden': 'true', text: 'AI' }) : null;
      badge.append(...[
        h('span', { class: 'vicon', 'aria-hidden': 'true', text: VERDICT[v].icon }),
        h('span', { text: VERDICT[v].label }),
        h('span', { class: 'score', text: String(state.final.score) }),
        aiBit
      ].filter(Boolean));
      badge.setAttribute('aria-label', `Off the Hook: ${VERDICT[v].label}, risk score ${state.final.score} out of 100. ${open ? 'Hide' : 'Show'} details.`);
    }

    function renderPanel() {
      panel.replaceChildren();
      const aiMode = !!(state && state.ai && state.ai.status !== 'off');
      panel.append(BRAND.header({
        headingTag: 'h2', headingId: 'pg-title', chip: aiMode ? 'AI-assisted' : 'Rule-based', ai: aiMode,
        closeLabel: 'Close Off the Hook panel', onClose: () => { setOpen(false); badge.focus(); }
      }));
      if (!state || state.loading) {
        panel.append(h('p', { class: 'section empty', text: 'Scanning this email…' }));
        return;
      }
      const { result, final, ai } = state;
      const v = final.verdict;

      panel.append(h('div', { class: 'verdict v-' + v },
        h('span', { class: 'vicon', 'aria-hidden': 'true', text: VERDICT[v].icon }),
        h('div', {},
          h('div', { class: 'vlabel', text: VERDICT[v].label }),
          h('div', { class: 'vscore', text: `Risk score ${final.score} / 100` }),
          h('div', { class: 'meter', role: 'presentation' }, (() => { const s = h('span'); s.style.width = final.score + '%'; return s; })())
        )
      ));

      const scores = h('div', { class: 'note panel-note', hidden: ai.status !== 'done' });
      if (ai.status === 'done') {
        scores.append(`Rule-based score: ${ai.combined.ruleScore} · AI score: ${ai.combined.aiScore} (AI says “${ai.data.verdict}”, ${ai.data.confidence}% confident${ai.providerLabel ? ', via ' + ai.providerLabel : ''})`);
      }
      panel.append(scores);

      let noticeText = '';
      if (ai.status === 'pending') noticeText = 'AI analysis in progress… showing the rule-based result for now.';
      else if (ai.status === 'failed') noticeText = 'AI analysis was unavailable, so this is the rule-based result. Reason: ' + ai.error;
      if (state.notice) noticeText = state.notice;
      const notice = h('p', { class: 'note warn panel-note', role: 'status', hidden: !noticeText });
      if (ai.status === 'pending' && !state.notice) notice.append(h('span', { class: 'spin', 'aria-hidden': 'true' }), ' ');
      notice.append(noticeText);
      panel.append(notice);

      // Coworker-account warning gets its own box so it can't be missed.
      const compromised = result.findings.find(f => f.id === 'internal_compromised');
      if (compromised) {
        panel.append(h('div', { class: 'alertbox', role: 'alert' },
          h('div', { class: 'alerttitle' }, h('span', { 'aria-hidden': 'true', text: '⚠ ' }), 'Possibly compromised coworker account'),
          h('p', { text: compromised.explanation })
        ));
      }

      // Header says "your company's address, but sent from outside": a faked coworker address.
      const spoofed = result.findings.find(f => f.id === 'spoofed_internal');
      if (spoofed) {
        panel.append(h('div', { class: 'alertbox', role: 'alert' },
          h('div', { class: 'alerttitle' }, h('span', { 'aria-hidden': 'true', text: '⚠ ' }), 'Fake coworker address'),
          h('p', { text: spoofed.explanation })
        ));
      }

      if (!compromised) {
        panel.append(h('p', { class: 'summary', text: ai.status === 'done' && ai.data.summary ? ai.data.summary : result.summary }));
      } else if (ai.status === 'done' && ai.data.summary) {
        panel.append(h('p', { class: 'summary', text: 'AI: ' + ai.data.summary }));
      }
      if (result.sender && result.sender.address) {
        const s = result.sender;
        panel.append(h('p', { class: 'sender' },
          h('span', { class: 'slabel', text: 'Sender read as: ' }),
          (s.name ? s.name + ' ' : '') + '<' + s.address + '>',
          s.freemail ? h('span', { class: 'stag', text: 'free email account' }) : null,
          s.trusted ? h('span', { class: 'stag', text: 'trusted' }) : null,
          s.internal ? h('span', { class: 'stag', text: 'your company' }) : null,
          result.headerChecked ? h('span', { class: 'stag', text: 'header checked' }) : null
        ));
      } else if (result.unreadSender) {
        panel.append(h('p', { class: 'sender' },
          h('span', { class: 'slabel', text: 'Sender read as: ' }),
          (result.unreadSender.name || '(no name)') + ' ',
          h('span', { class: 'stag', text: "address not visible to Off the Hook" })
        ));
      }

      // Outlook: suggest reading the message header when the email looks off or the sender is unclear.
      const wantsHeader = state.site === 'outlook' && !result.headerChecked &&
        (final.verdict !== 'safe' || result.unreadSender || (result.sender && result.sender.internal));
      if (wantsHeader) {
        panel.append(h('p', { class: 'note lime panel-note' },
          h('strong', { text: 'Want a deeper check? ' }),
          'In Outlook, click ', h('strong', { text: '… (More actions) → View → View message details' }),
          '. Off the Hook reads the message header automatically and updates this verdict, including whether a "coworker" email really came from inside your company.'
        ));
      }

      // Attachments: point to the file checker before anyone opens them.
      if (state.attachments > 0) {
        panel.append(h('div', { class: 'note panel-note' + (final.verdict === 'safe' ? ' lime' : ' warn') },
          h('strong', { text: state.attachments === 1 ? 'Has an attachment. ' : `Has ${state.attachments} attachments. ` }),
          state.attachments === 1
            ? 'Download it without opening it, then drop it into the file checker: it looks inside for macros, hidden programs and fake links.'
            : 'Download them without opening them, then drop them into the file checker: it looks inside for macros, hidden programs and fake links.',
          h('div', { class: 'actions', style: 'margin-top:6px' },
            h('button', { type: 'button', text: 'Open file checker', onclick: handlers.onOpenFileChecker }))
        ));
      }

      panel.append(h('div', { class: 'actions' },
        h('button', { type: 'button', 'aria-pressed': String(!state.highlightsOn), text: state.highlightsOn ? 'Hide highlights' : 'Show highlights', onclick: handlers.onToggleHighlights }),
        h('button', { type: 'button', text: 'Re-scan', onclick: handlers.onRescan }),
        h('button', { type: 'button', text: 'Settings', onclick: handlers.onOpenSettings })
      ));

      // Findings grouped by severity.
      const fWrap = h('div', { class: 'section' });
      if (!result.findings.length) fWrap.append(h('p', { class: 'empty', text: 'No rule-based warning signs found.' }));
      for (const sev of SEV) {
        const list = result.findings.filter(f => f.severity === sev.key);
        if (!list.length) continue;
        fWrap.append(h('h3', { text: `${sev.label} (${list.length})` }));
        fWrap.append(h('ul', {}, list.map(f => h('li', { class: 'finding sev-' + sev.key },
          h('div', { class: 'ftitle' }, h('span', { class: 'sicon', 'aria-hidden': 'true', text: sev.icon }), h('span', { text: f.title })),
          h('p', { class: 'fexp', text: f.explanation }),
          f.matches.length ? h('div', { class: 'chips', 'aria-label': 'Triggered by' }, f.matches.slice(0, 12).map(m => h('span', { class: 'chip', text: m }))) : null
        ))));
      }
      panel.append(h('details', { open: true }, h('summary', { text: `Findings (${result.findings.length})` }), fWrap));

      if (ai.status === 'done') {
        const hl = ai.data.highlights;
        const aiWrap = h('div', { class: 'section' });
        if (!hl.length) aiWrap.append(h('p', { class: 'empty', text: 'The AI did not flag specific phrases.' }));
        aiWrap.append(h('ul', {}, hl.map(x => h('li', { class: 'finding ai-item' },
          h('div', { class: 'ftitle' }, h('span', { text: `“${x.text}”` })),
          h('p', { class: 'fexp', text: `${CATEGORY_LABELS[x.category] || 'Other'}: ${x.reason}` })
        ))));
        panel.append(h('details', { open: true }, h('summary', { text: `AI highlights (${hl.length})` }), aiWrap));
      }

      const links = result.links || [];
      const lWrap = h('div', { class: 'section' });
      if (!links.length) lWrap.append(h('p', { class: 'empty', text: 'This email has no web links.' }));
      lWrap.append(h('ul', {}, links.slice(0, 40).map(l => h('li', { class: 'link' },
        h('span', { class: 'ltext', text: (l.text || '(no text)').slice(0, 80) }), ' → ',
        h('span', { class: 'ldest', text: l.domain || l.display }),
        l.flags.length ? h('span', { class: 'lflags', text: '⚠ ' + l.flags.join(' · ') }) : null,
        h('span', { class: 'lfull', text: l.display.slice(0, 200) })
      ))));
      if (links.length > 40) lWrap.append(h('p', { class: 'empty', text: `…and ${links.length - 40} more.` }));
      const flagged = links.filter(l => l.flags.length).length;
      panel.append(h('details', { open: flagged > 0 }, h('summary', { text: `Where the links really go (${links.length}${flagged ? ', ' + flagged + ' flagged' : ''})` }), lWrap));

      if (result.quieted && result.quieted.length) {
        panel.append(h('details', {}, h('summary', { text: `Quieted by your earlier "safe" report (${result.quieted.length})` }),
          h('ul', { class: 'section' }, result.quieted.map(f => h('li', { class: 'fexp', text: f.title })))));
      }
      if (result.notes && result.notes.length) {
        panel.append(h('div', { class: 'section' }, h('h3', { text: 'Notes' }), h('ul', {}, result.notes.map(n => h('li', { class: 'fexp', text: n })))));
      }
      if (handlers.onReport) panel.append(renderReport(result, final));
      panel.append(h('p', { class: 'disclaimer', text: 'Advisory only. Off the Hook can miss phishing and can flag safe email. Before clicking links, opening attachments, or sending money or information, confirm with the sender through a channel you already trust.' }));
    }

    // ---- "Was Off the Hook right?" reporting ----
    const NEVER_QUIET = ['internal_compromised', 'auth_fail', 'webmail_warning', 'attachment_double_ext', 'link_script_scheme',
      'kw_ai_manipulation', 'reported_sender', 'reported_domain', 'reported_link', 'spoofed_internal', 'provider_verdict',
      'link_blocklisted', 'sender_blocklisted'];
    let report = { mode: null, phrases: [], note: '', status: '', busy: false };
    const resetReport = () => { report = { mode: null, phrases: [], note: '', status: '', busy: false }; };

    async function saveReport() {
      report.busy = true; report.status = 'Saving…'; render();
      let resp;
      try { resp = await handlers.onReport(report.mode, report.phrases, report.note); } catch (e) { resp = { ok: false, error: e.message }; }
      if (resp && resp.ok) return; // the email is rescanned and shows "You reported this email…"
      report.busy = false; report.status = 'Could not save the report: ' + ((resp && resp.error) || 'unknown error'); render();
    }

    function renderReport(result, final) {
      const wrap = h('section', { class: 'report', 'aria-labelledby': 'pg-report-h' });
      wrap.append(h('h3', { id: 'pg-report-h', text: 'Was Off the Hook right?' }));
      const who = (result.sender && result.sender.address) || 'this sender';
      const btn = (text, onclick, cls) => h('button', { type: 'button', class: cls || null, text, disabled: report.busy, onclick });
      const noteBox = () => {
        const ta = h('textarea', { rows: '2', maxlength: '500', 'aria-label': 'Note (optional)', placeholder: 'Note (optional)' });
        ta.value = report.note;
        ta.addEventListener('input', () => { report.note = ta.value; });
        return ta;
      };

      if (result.reported) {
        const r = result.reported;
        wrap.append(h('p', { class: 'fexp', text: `You reported this email as ${r.type === 'phish' ? 'phishing' : 'safe'} on ${new Date(r.at).toLocaleDateString()}. Off the Hook remembers this on this computer only.` }));
        wrap.append(h('div', { class: 'actions' }, btn('Undo report', async () => {
          report.busy = true; render();
          try { await handlers.onUndoReport(r.id); } catch (e) { report.busy = false; report.status = 'Could not undo: ' + e.message; render(); }
        })));
      } else if (!report.mode) {
        const missed = final.verdict === 'safe';
        wrap.append(h('p', { class: 'fexp', text: missed
          ? 'If this is phishing Off the Hook missed, report it so similar emails get caught next time.'
          : 'If this email is actually fine, report it as safe so Off the Hook stops warning about it.' }));
        wrap.append(h('div', { class: 'actions' },
          btn("It's phishing", () => { report.mode = 'phish'; render(); }, missed ? 'primary' : null),
          btn("It's safe", () => { report.mode = 'safe'; render(); }, missed ? null : 'primary')
        ));
      } else if (report.mode === 'phish') {
        wrap.append(h('p', { class: 'fexp', text: `Off the Hook will flag email from ${who}, and the link sites in this email, from now on.` }));
        wrap.append(h('p', { class: 'fexp' }, h('strong', { text: 'What gave it away? ' }), '(optional) Select words in the email, then click "Add selected text". Off the Hook will watch for that wording.'));
        const chips = h('div', { class: 'chips' }, report.phrases.map((p, i) => h('span', { class: 'chip removable' }, p,
          h('button', { type: 'button', class: 'x', 'aria-label': 'Remove phrase ' + p, text: '×', onclick: () => { report.phrases.splice(i, 1); render(); } }))));
        wrap.append(h('div', { class: 'actions' }, btn('Add selected text', () => {
          const t = (handlers.getSelectedText && handlers.getSelectedText()) || '';
          if (!t) report.status = 'Select some words in the email first, then click Add selected text.';
          else if (t.length < 3) report.status = 'That selection is too short. Select at least a few letters.';
          else if (t.length > 120) report.status = `That selection is ${t.length} characters. Select just the giveaway words (up to 120 characters), like "send me your phone number".`;
          else if (report.phrases.some(p => p.toLowerCase() === t.toLowerCase())) report.status = `"${t}" is already in the list.`;
          else if (report.phrases.length >= 10) report.status = 'You can add up to 10 phrases.';
          else { report.phrases.push(t); report.status = `Added "${t}".`; }
          render();
        })));
        if (report.phrases.length) wrap.append(chips);
        wrap.append(noteBox());
        wrap.append(h('div', { class: 'actions' }, btn('Save report', saveReport, 'primary'), btn('Cancel', () => { resetReport(); render(); })));
      } else {
        const quiet = result.findings.filter(f => !NEVER_QUIET.includes(f.id));
        const kept = result.findings.filter(f => NEVER_QUIET.includes(f.id));
        wrap.append(h('p', { class: 'fexp', text: quiet.length
          ? `For email from ${who}, Off the Hook will stop showing: ${quiet.map(f => f.title).join('; ')}.`
          : 'Off the Hook will remember that this email is safe.' }));
        if (kept.length) {
          wrap.append(h('p', { class: 'fexp', text: `These warnings stay on, because they matter most if an account is hacked or a message is dangerous: ${kept.map(f => f.title).join('; ')}.` }));
        }
        wrap.append(noteBox());
        wrap.append(h('div', { class: 'actions' }, btn('Save as safe', saveReport, 'primary'), btn('Cancel', () => { resetReport(); render(); })));
      }
      if (report.status) wrap.append(h('p', { class: 'fexp rstatus', role: 'status', text: report.status }));
      return wrap;
    }

    function render() {
      // Keep keyboard focus and scroll position when the panel re-renders (e.g. AI result arrives).
      const active = shadow.activeElement;
      const focusKey = active && active.tagName === 'BUTTON' && panel.contains(active) ? active.getAttribute('aria-pressed') != null ? 'toggle' : active.textContent : null;
      const scroll = panel.scrollTop;
      renderBadge();
      renderPanel();
      panel.scrollTop = scroll;
      if (focusKey) {
        const btn = Array.from(panel.querySelectorAll('button')).find(b => focusKey === 'toggle' ? b.hasAttribute('aria-pressed') : b.textContent === focusKey);
        if (btn) btn.focus();
      }
    }

    return {
      mount() { if (!host.isConnected) document.documentElement.appendChild(host); },
      setVisible(v) { host.style.display = v ? '' : 'none'; if (!v) setOpen(false); },
      setLoading() { state = { loading: true }; resetReport(); render(); },
      update(next) { state = next; render(); },
      destroy() { host.remove(); }
    };
  }

  globalThis.PhishGuardUI = { create };
})();
