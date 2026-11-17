/*
 * Inbox list tags: checks each visible row of the message list (sender, subject, preview line)
 * before the email is opened, and puts a small "Suspicious" / "Phishing" tag on risky rows.
 * Safe rows get nothing: a preview can't prove an email is safe.
 *
 * Rows are analyzed in batches by the background worker (rules only, never AI) and cached by
 * the row's text, so scrolling and re-renders don't re-check anything. Read-only: the tag is
 * the only thing added to the page, and its text is drawn by CSS so it never ends up in the
 * text Off the Hook (or the webmail) reads back.
 */
(function () {
  'use strict';

  const TAG = 'phishguard-row-tag';
  const LABELS = { suspicious: '⚠ Suspicious', phishing: '✕ Phishing' };
  const MAX_CACHE = 1500;
  const BATCH = 40;

  /**
   * @param {{ adapter, send: (msg) => Promise, pause: (fn) => void }} opts
   *   pause runs DOM edits with the page observer off, so adding tags doesn't trigger rescans.
   */
  function create(opts) {
    const { adapter, send, pause } = opts;
    let cache = new Map();          // row key -> { result, data } (result null = nothing to show)
    const pending = new Set();      // row keys waiting for the background worker
    const info = new WeakMap();     // tag element -> { result, data } for the hover card
    let generation = 0;             // bumps on reset so late replies are dropped

    function makeTag(entry) {
      const v = entry.result.verdict;
      const tag = document.createElement('span');
      tag.className = `${TAG} phishguard-row-${v}`;
      tag.dataset.pgLabel = LABELS[v];
      tag.dataset.pgFor = v + ':' + entry.result.score;
      tag.setAttribute('role', 'img');
      tag.setAttribute('aria-label', `Off the Hook: ${entry.result.verdictLabel} (from the preview). Hover for details.`);
      info.set(tag, entry);
      return tag;
    }

    // Make the row's tag match its cached result (add, replace or remove).
    function sync(row, entry) {
      const existing = row.el.querySelector('.' + TAG);
      const show = entry && entry.result && LABELS[entry.result.verdict];
      if (!show) { if (existing) existing.remove(); return; }
      if (existing && existing.dataset.pgFor === entry.result.verdict + ':' + entry.result.score) {
        info.set(existing, entry);
        return;
      }
      if (existing) existing.remove();
      let anchor = null;
      try { const r = row.read(); anchor = r && r.anchorEl; } catch (e) { anchor = null; }
      const tag = makeTag(entry);
      // Inside the subject element, not next to it: an extra sibling in a flex row would become
      // its own column and shift the webmail's layout.
      if (anchor && anchor.isConnected && row.el.contains(anchor)) anchor.prepend(tag);
      else row.el.prepend(tag);
    }

    async function analyze(batch, gen) {
      let resp;
      try {
        resp = await send({ type: 'analyzeList', rows: batch.map(b => b.data) });
      } catch (e) {
        resp = null;
      }
      batch.forEach(b => pending.delete(b.key));
      if (gen !== generation || !resp || !resp.ok || !Array.isArray(resp.results)) return;
      if (cache.size > MAX_CACHE) cache = new Map();
      batch.forEach((b, i) => cache.set(b.key, { result: resp.results[i] || null, data: b.data }));
      pause(() => { for (const b of batch) if (b.row.el.isConnected) sync(b.row, cache.get(b.key)); });
    }

    function run(enabled) {
      if (!enabled || !adapter.getListRows) { removeTags(); return; }
      let rows;
      try { rows = adapter.getListRows() || []; } catch (e) { return; }
      const known = [], todo = [];
      for (const row of rows) {
        if (cache.has(row.key)) { known.push(row); continue; }
        if (pending.has(row.key)) continue;
        let r = null;
        try { r = row.read(); } catch (e) { r = null; }
        if (!r || !(r.data.subject || r.data.body)) { cache.set(row.key, null); continue; }
        r.data.body = String(r.data.body || '').slice(0, 1000);
        pending.add(row.key);
        todo.push({ row, key: row.key, data: r.data });
      }
      if (known.length) pause(() => known.forEach(row => sync(row, cache.get(row.key))));
      const gen = generation;
      for (let i = 0; i < todo.length; i += BATCH) analyze(todo.slice(i, i + BATCH), gen);
    }

    function removeTags() {
      const tags = document.querySelectorAll('.' + TAG);
      if (tags.length) pause(() => tags.forEach(t => t.remove()));
    }

    return {
      run,
      // Settings or reports changed: forget every result and check the rows again.
      reset() { generation++; cache = new Map(); pending.clear(); removeTags(); },
      infoFor(tag) { return info.get(tag) || null; },
      isTag(el) { return !!(el && el.classList && el.classList.contains(TAG)); }
    };
  }

  globalThis.PhishGuardListScan = { create };
})();
