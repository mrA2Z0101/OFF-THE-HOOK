/*
 * Reads a Learn post (a small Markdown file in learn/posts/) into a plain tree that the Learn
 * page turns into page elements. Nothing here creates HTML, so a post can never inject code.
 *
 *   parse(text) -> { meta: { title, date, summary, tags[], author, draft }, blocks[], words, minutes }
 *
 * Supported: front matter between --- lines; # or ## headings (and ### smaller ones); paragraphs; **bold**, *italic*,
 * `code`, [links](https://...), ==highlight== and ==highlight|why==; - and 1. lists; | tables |; > quotes;
 * > [!TIP] / [!WARNING] / [!REDFLAG] / [!NOTE] call-outs; --- lines; ![pictures](img/file.png);
 * ```email blocks (a practice email) and ```quiz blocks (one question).
 */
(function (root, factory) {
  const mod = factory();
  if (typeof module === 'object' && module.exports) module.exports = mod;
  else { root.PhishGuard = root.PhishGuard || {}; root.PhishGuard.learnmd = mod; }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const CALLOUTS = { tip: 'Tip', note: 'Note', warning: 'Watch out', redflag: 'Red flag' };
  const VERDICTS = { phishing: 'Phishing', suspicious: 'Suspicious', safe: 'Safe' };

  // Only web links, email links and links to other posts (#/slug). Anything else stays plain text.
  function safeHref(href) {
    const h = String(href || '').trim();
    if (/^https?:\/\/[^\s]+$/i.test(h) || /^mailto:[^\s]+$/i.test(h)) return h;
    if (/^#\/[a-z0-9-]+$/i.test(h)) return h;
    return null;
  }
  // Pictures must sit in the posts folder: no other sites (they would see who reads), no "..".
  function safeImg(src) {
    const s = String(src || '').trim();
    return /^[a-z0-9_\-./]+\.(png|jpe?g|gif|webp|svg)$/i.test(s) && !s.includes('..') && !s.startsWith('/') ? s : null;
  }

  function inline(s) {
    const out = [];
    let text = '';
    const flush = () => { if (text) { out.push({ t: 'text', v: text }); text = ''; } };
    let i = 0;
    while (i < s.length) {
      const rest = s.slice(i);
      let m;
      if (rest[0] === '\\' && rest.length > 1) { text += rest[1]; i += 2; continue; }
      if (rest[0] === '`' && (m = /^`([^`]+)`/.exec(rest))) { flush(); out.push({ t: 'code', v: m[1] }); i += m[0].length; continue; }
      if (rest.startsWith('**') && (m = /^\*\*(.+?)\*\*/.exec(rest))) { flush(); out.push({ t: 'b', c: inline(m[1]) }); i += m[0].length; continue; }
      if (rest.startsWith('==') && (m = /^==(.+?)==/.exec(rest))) {
        flush();
        const bar = m[1].indexOf('|');
        out.push(bar < 0 ? { t: 'mark', c: inline(m[1]) } : { t: 'mark', c: inline(m[1].slice(0, bar).trim()), note: m[1].slice(bar + 1).trim() });
        i += m[0].length; continue;
      }
      if (rest[0] === '[' && (m = /^\[([^\]]+)\]\(([^)\s]*)\)/.exec(rest))) {
        flush();
        const href = safeHref(m[2]);
        out.push(href ? { t: 'a', href, c: inline(m[1]) } : { t: 'text', v: m[1] });
        i += m[0].length; continue;
      }
      if ((rest[0] === '*' || rest[0] === '_') && (m = new RegExp('^\\' + rest[0] + '(?!\\s)(.+?)(?<!\\s)\\' + rest[0] + '(?![\\w*])').exec(rest)) &&
          !(rest[0] === '_' && /\w/.test(s[i - 1] || ''))) {
        flush(); out.push({ t: 'i', c: inline(m[1]) }); i += m[0].length; continue;
      }
      text += rest[0]; i++;
    }
    flush();
    return out;
  }

  function frontMatter(lines) {
    const meta = { title: '', date: '', summary: '', tags: [], author: '', draft: false };
    if ((lines[0] || '').trim() !== '---') return { meta, start: 0 };
    let end = 1;
    for (; end < lines.length && lines[end].trim() !== '---'; end++) {
      const m = /^([a-z]+)\s*:\s*(.*)$/i.exec(lines[end]);
      if (!m) continue;
      // Quotes around the whole value are dropped; a title like "Please sign": fake DocuSign keeps its own.
      const k = m[1].toLowerCase(), v = m[2].trim().replace(/^(["'])(.*)\1$/, '$2');
      if (k === 'tags') meta.tags = v.replace(/^\[|\]$/g, '').split(',').map(t => t.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
      else if (k === 'draft') meta.draft = /^(true|yes)$/i.test(v);
      else if (k in meta) meta[k] = v;
    }
    return { meta, start: end < lines.length ? end + 1 : 0 };
  }

  function emailBlock(lines) {
    const email = { t: 'email', from: '', to: '', subject: '', date: '', verdict: '', attachments: [], body: [] };
    let i = 0;
    for (; i < lines.length && lines[i].trim(); i++) {
      const m = /^([a-z]+)\s*:\s*(.*)$/i.exec(lines[i]);
      if (!m) break;
      const k = m[1].toLowerCase(), v = m[2].trim();
      if (k === 'verdict') email.verdict = VERDICTS[v.toLowerCase()] ? v.toLowerCase() : '';
      else if (k === 'attachment' || k === 'attachments') email.attachments.push(...v.split(',').map(a => a.trim()).filter(Boolean));
      else if (k in email && typeof email[k] === 'string') email[k] = v;
    }
    let para = [];
    // Line breaks inside an email paragraph are kept ("Regards," / "SupplyCo Accounts").
    const end = () => { if (para.length) { email.body.push(inline(para.join('\n'))); para = []; } };
    for (; i < lines.length; i++) { if (lines[i].trim()) para.push(lines[i].trim()); else end(); }
    end();
    return email;
  }

  function quizBlock(lines) {
    const quiz = { t: 'quiz', question: [], options: [], why: [] };
    const q = [];
    let why = null;
    for (const raw of lines) {
      const line = raw.trim();
      let m;
      if (why !== null) { if (line) why.push(line); continue; }
      if ((m = /^[-*]\s*\[( |x|X)\]\s*(.+)$/.exec(line))) quiz.options.push({ c: inline(m[2]), correct: m[1] !== ' ' });
      else if ((m = /^why\s*:\s*(.*)$/i.exec(line))) why = m[1] ? [m[1]] : [];
      else if (line) q.push(line);
    }
    quiz.question = inline(q.join(' '));
    quiz.why = why ? inline(why.join(' ')) : [];
    return quiz;
  }

  const START = /^(#{1,3}\s|>|[-*+]\s|\d+[.)]\s|```|---+\s*$|!\[|\|)/;

  // "| a | b |" -> ['a', 'b']. A \| inside a cell stays a literal bar.
  const cells = line => line.trim().replace(/^\||\|$/g, '').split(/(?<!\\)\|/).map(c => c.trim().replace(/\\\|/g, '|'));

  function parse(text) {
    const lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
    const { meta, start } = frontMatter(lines);
    const blocks = [];
    let i = start;
    while (i < lines.length) {
      const line = lines[i];
      const trimmed = line.trim();
      let m;
      if (!trimmed) { i++; continue; }

      if ((m = /^```\s*([a-z]*)/i.exec(trimmed))) {
        const kind = m[1].toLowerCase();
        const body = [];
        for (i++; i < lines.length && !/^```\s*$/.test(lines[i].trim()); i++) body.push(lines[i]);
        i++;
        if (kind === 'email') blocks.push(emailBlock(body));
        else if (kind === 'quiz') blocks.push(quizBlock(body));
        else blocks.push({ t: 'code', v: body.join('\n') });
        continue;
      }
      if ((m = /^(#{1,3})\s+(.+)$/.exec(trimmed))) { blocks.push({ t: 'h', level: Math.max(2, m[1].length), c: inline(m[2].replace(/\s+#+$/, '')) }); i++; continue; }
      if (/^---+$/.test(trimmed) || /^\*\*\*+$/.test(trimmed)) { blocks.push({ t: 'hr' }); i++; continue; }
      if ((m = /^!\[([^\]]*)\]\(([^)\s]+)\)$/.exec(trimmed))) {
        const src = safeImg(m[2]);
        if (src) blocks.push({ t: 'img', src, alt: m[1] });
        i++; continue;
      }
      if (trimmed.startsWith('|') && /^\|?\s*:?-{2,}/.test((lines[i + 1] || '').trim())) {
        const head = cells(trimmed);
        const rows = [];
        for (i += 2; i < lines.length && lines[i].trim().startsWith('|'); i++) rows.push(cells(lines[i]));
        blocks.push({ t: 'table', head: head.map(inline), rows: rows.map(r => head.map((_, c) => inline(r[c] || ''))) });
        continue;
      }
      if (trimmed.startsWith('>')) {
        const q = [];
        for (; i < lines.length && lines[i].trim().startsWith('>'); i++) q.push(lines[i].trim().replace(/^>\s?/, ''));
        const head = /^\[!([a-z]+)\]\s*(.*)$/i.exec(q[0] || '');
        const paras = [];
        let cur = [];
        for (const l of head ? q.slice(1) : q) { if (l.trim()) cur.push(l.trim()); else if (cur.length) { paras.push(inline(cur.join(' '))); cur = []; } }
        if (cur.length) paras.push(inline(cur.join(' ')));
        const kind = head && CALLOUTS[head[1].toLowerCase()] ? head[1].toLowerCase() : null;
        blocks.push(kind ? { t: 'callout', kind, title: head[2] || CALLOUTS[kind], c: paras } : { t: 'quote', c: paras });
        continue;
      }
      if ((m = /^([-*+]|\d+[.)])\s+/.exec(trimmed))) {
        const ordered = /\d/.test(m[1]);
        const items = [];
        const itemRe = ordered ? /^\d+[.)]\s+(.*)$/ : /^[-*+]\s+(.*)$/;
        for (; i < lines.length; i++) {
          const l = lines[i];
          const im = itemRe.exec(l.trim());
          if (im) items.push([im[1]]);
          else if (l.trim() && /^\s+/.test(l) && items.length) items[items.length - 1].push(l.trim());
          else break;
        }
        blocks.push({ t: ordered ? 'ol' : 'ul', items: items.map(parts => inline(parts.join(' '))) });
        continue;
      }
      const para = [];
      for (; i < lines.length && lines[i].trim() && !(para.length && START.test(lines[i].trim())); i++) para.push(lines[i].trim());
      blocks.push({ t: 'p', c: inline(para.join(' ')) });
    }

    const words = String(text || '').slice(0).replace(/^---[\s\S]*?\n---/, '').split(/\s+/).filter(w => /\w/.test(w)).length;
    if (!meta.title) {
      const h = blocks.find(b => b.t === 'h');
      if (h) meta.title = plain(h.c);
    }
    return { meta, blocks, words, minutes: Math.max(1, Math.round(words / 200)) };
  }

  function plain(nodes) {
    return (nodes || []).map(n => n.v != null ? n.v : plain(n.c)).join('');
  }

  // Turns a file name into the post's address: "Spot-the-Fake Boss.md" -> "spot-the-fake-boss".
  const slug = file => String(file).replace(/\.md$/i, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

  return { parse, inline, plain, slug, safeHref, safeImg };
});
