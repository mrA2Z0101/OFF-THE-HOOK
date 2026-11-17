'use strict';
/*
 * Learn page: lists the posts in learn/posts/ (see learn/HOW-TO-WRITE.md) and shows one at a time.
 * Posts are parsed by shared/learnmd.js and built with createElement/textContent only.
 * Which posts you've opened is kept in chrome.storage.local ("learnSeen") for the "New" tags.
 */
const MD = window.PhishGuard.learnmd;
const $ = id => document.getElementById(id);
const BASE_TITLE = document.title;
const SHOW_DRAFTS = new URLSearchParams(location.search).has('drafts');
const VERDICT = { phishing: ['v-phishing', '✕', 'Phishing'], suspicious: ['v-suspicious', '!', 'Suspicious'], safe: ['v-safe', '✓', 'Safe'] };

let posts = [];
let seen = new Set();
const filter = { q: '', tag: '' };

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'text') el.textContent = v;
    else if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid);
  return el;
}

// ---------- seen posts ----------
const store = typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local;
async function loadSeen() {
  try {
    if (store) seen = new Set((await store.get('learnSeen')).learnSeen || []);
    else seen = new Set(JSON.parse(localStorage.getItem('learnSeen') || '[]'));
  } catch (e) { seen = new Set(); }
}
function markSeen(slug) {
  if (seen.has(slug)) return;
  seen.add(slug);
  const list = [...seen].slice(-500);
  try { if (store) store.set({ learnSeen: list }); else localStorage.setItem('learnSeen', JSON.stringify(list)); } catch (e) { /* not saved; fine */ }
}

// ---------- loading ----------
async function loadPosts() {
  const index = await fetch('posts/index.json', { cache: 'no-cache' }).then(r => r.json());
  const files = (index.posts || []).filter(f => typeof f === 'string' && /^[\w-]+\.md$/i.test(f));
  const loaded = await Promise.all(files.map(async (file, order) => {
    try {
      const text = await fetch('posts/' + file, { cache: 'no-cache' }).then(r => { if (!r.ok) throw new Error(r.status); return r.text(); });
      const post = MD.parse(text);
      return Object.assign(post, { file, order, slug: MD.slug(file), search: (post.meta.title + ' ' + post.meta.summary + ' ' + post.meta.tags.join(' ') + ' ' + text).toLowerCase() });
    } catch (e) {
      console.warn('Off the Hook Learn: could not read', file, e);
      return null;
    }
  }));
  posts = loaded.filter(p => p && p.meta.title && (SHOW_DRAFTS || !p.meta.draft))
    .sort((a, b) => (b.meta.date || '').localeCompare(a.meta.date || '') || a.order - b.order);
}

function niceDate(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso || '');
  if (!m) return iso || '';
  return new Date(+m[1], m[2] - 1, +m[3]).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}
const metaLine = p => [niceDate(p.meta.date), p.minutes + ' min read', p.meta.author].filter(Boolean).join(' · ');

// ---------- list ----------
function renderTags() {
  const all = [...new Set(posts.flatMap(p => p.meta.tags))].sort((a, b) => a.localeCompare(b));
  const chip = (label, value) => h('button', {
    type: 'button', class: 'small chip', 'aria-pressed': String(filter.tag === value), text: label,
    onclick: () => { filter.tag = filter.tag === value && value ? '' : value; renderTags(); renderList(); }
  });
  $('tags').replaceChildren(chip('All', ''), ...all.map(t => chip(t, t)));
}

function renderList() {
  const q = filter.q.trim().toLowerCase();
  const shown = posts.filter(p => (!filter.tag || p.meta.tags.includes(filter.tag)) && (!q || q.split(/\s+/).every(w => p.search.includes(w))));
  const fresh = posts.filter(p => !seen.has(p.slug)).length;
  $('listStatus').textContent = !posts.length ? 'No posts yet.'
    : shown.length === posts.length ? `${posts.length} post${posts.length === 1 ? '' : 's'}${fresh ? `, ${fresh} new` : ''}`
    : `${shown.length} of ${posts.length} posts`;
  $('posts').replaceChildren(...shown.map(p => h('a', { class: 'card', href: '#/' + p.slug },
    h('div', { class: 'card-meta' },
      seen.has(p.slug) ? null : h('span', { class: 'new', text: 'New' }),
      p.meta.draft ? h('span', { class: 'draft', text: 'Draft' }) : null,
      h('span', { text: metaLine(p) })),
    h('h2', { text: p.meta.title }),
    p.meta.summary ? h('p', { text: p.meta.summary }) : null,
    p.meta.tags.length ? h('div', { class: 'chips' }, p.meta.tags.map(t => h('span', { class: 'chip-tag', text: t }))) : null)));
}

// ---------- one post ----------
function inline(nodes) {
  return (nodes || []).map(n => {
    switch (n.t) {
      case 'text': return document.createTextNode(n.v);
      case 'b': return h('strong', null, inline(n.c));
      case 'i': return h('em', null, inline(n.c));
      case 'code': return h('code', { text: n.v });
      case 'a': return n.href.startsWith('#') ? h('a', { href: n.href }, inline(n.c))
        : h('a', { href: n.href, target: '_blank', rel: 'noopener noreferrer' }, inline(n.c));
      case 'mark': return h('mark', { class: 'hl' + (n.note ? ' flag' : ''), title: n.note || null }, inline(n.c));
      default: return null;
    }
  });
}

function emailBlock(b) {
  const flags = [];
  const body = b.body.map(para => {
    const kids = inline(para);
    // Number the red flags so the list below the email can explain each one.
    const walk = el => {
      if (el.nodeType !== 1) return;
      if (el.matches('mark.flag')) { flags.push(el.title); el.dataset.n = flags.length; el.removeAttribute('title'); }
      [...el.children].forEach(walk);
    };
    kids.forEach(walk);
    return h('p', null, kids);
  });
  const v = VERDICT[b.verdict];
  const box = h('figure', { class: 'practice' });
  const reveal = h('button', { type: 'button', class: 'primary', 'aria-expanded': 'false',
    text: flags.length ? `Show red flags (${flags.length})` : 'Show the answer',
    onclick: () => {
      const open = !box.classList.contains('revealed');
      box.classList.toggle('revealed', open);
      reveal.setAttribute('aria-expanded', String(open));
      reveal.textContent = open ? 'Hide red flags' : flags.length ? `Show red flags (${flags.length})` : 'Show the answer';
    }
  });
  const row = (k, val) => val ? h('div', { class: 'hdr' }, h('span', { class: 'k', text: k }), h('span', { text: val })) : null;
  box.append(
    h('div', { class: 'mail' },
      h('div', { class: 'subj', text: b.subject || '(no subject)' }),
      row('From', b.from), row('To', b.to), row('Date', b.date),
      b.attachments.length ? h('div', { class: 'atts' }, b.attachments.map(a => h('span', { class: 'att', text: '📎 ' + a }))) : null,
      h('div', { class: 'mbody' }, body)),
    h('figcaption', null,
      h('div', { class: 'row-actions' }, reveal),
      h('div', { class: 'answer' },
        v ? h('div', { class: 'verdict ' + v[0] }, h('span', { class: 'vicon', 'aria-hidden': 'true', text: v[1] }),
          h('div', null, h('div', { class: 'vlabel', text: v[2] }), h('div', { class: 'vscore', text: 'This practice email is ' + v[2].toLowerCase() }))) : null,
        flags.length ? h('ol', { class: 'flaglist' }, flags.map(f => h('li', { text: f }))) : null)));
  return box;
}

function quizBlock(b) {
  const box = h('div', { class: 'quiz' }, h('div', { class: 'qhead', text: 'Quick check' }), h('p', { class: 'q' }, inline(b.question)));
  const why = h('div', { class: 'why', hidden: true }, h('strong', { text: 'Why: ' }), inline(b.why));
  const result = h('p', { class: 'result', role: 'status', 'aria-live': 'polite' });
  const buttons = b.options.map(o => h('button', { type: 'button', class: 'opt' }, inline(o.c)));
  buttons.forEach((btn, i) => btn.addEventListener('click', () => {
    buttons.forEach((x, j) => { x.disabled = true; if (b.options[j].correct) x.classList.add('right'); });
    const ok = b.options[i].correct;
    if (!ok) btn.classList.add('wrong');
    result.textContent = ok ? '✓ Right!' : '✗ Not quite.';
    result.className = 'result ' + (ok ? 'ok' : 'bad');
    why.hidden = !b.why.length;
  }));
  box.append(h('div', { class: 'opts' }, buttons), result, why);
  return box;
}

function block(b) {
  switch (b.t) {
    case 'h': return h('h' + Math.min(4, b.level), null, inline(b.c));
    case 'p': return h('p', null, inline(b.c));
    case 'ul': case 'ol': return h(b.t, null, b.items.map(it => h('li', null, inline(it))));
    case 'quote': return h('blockquote', null, b.c.map(p => h('p', null, inline(p))));
    case 'callout': return h('aside', { class: 'callout ' + b.kind }, h('div', { class: 'ctitle', text: b.title }), b.c.map(p => h('p', null, inline(p))));
    case 'hr': return h('hr');
    case 'img': return h('img', { src: 'posts/' + b.src, alt: b.alt, loading: 'lazy' });
    case 'code': return h('pre', null, h('code', { text: b.v }));
    case 'table': return h('div', { class: 'tablewrap' }, h('table', null,
      h('thead', null, h('tr', null, b.head.map(c => h('th', null, inline(c))))),
      h('tbody', null, b.rows.map(r => h('tr', null, r.map(c => h('td', null, inline(c))))))));
    case 'email': return emailBlock(b);
    case 'quiz': return quizBlock(b);
    default: return null;
  }
}

function renderPost(p) {
  document.title = p.meta.title + ' · ' + BASE_TITLE;
  $('article').replaceChildren(
    h('header', null,
      h('div', { class: 'card-meta' }, p.meta.draft ? h('span', { class: 'draft', text: 'Draft' }) : null, h('span', { text: metaLine(p) })),
      h('h1', { class: 'ptitle', text: p.meta.title }),
      p.meta.tags.length ? h('div', { class: 'chips' }, p.meta.tags.map(t => h('a', { class: 'chip-tag', href: '#/tag/' + encodeURIComponent(t), text: t }))) : null),
    ...p.blocks.map(block));
  const i = posts.indexOf(p);
  const link = (q, label) => q ? h('a', { class: 'pg', href: '#/' + q.slug }, h('span', { class: 'k', text: label }), h('span', { text: q.meta.title })) : h('span');
  $('pager').replaceChildren(link(posts[i + 1], '← Older'), link(posts[i - 1], 'Newer →'));
  markSeen(p.slug);
}

// ---------- routing ----------
function route() {
  const m = /^#\/(.*)$/.exec(location.hash);
  const path = m ? decodeURIComponent(m[1]) : '';
  const tag = /^tag\/(.+)$/.exec(path);
  const post = !tag && path && posts.find(p => p.slug === path);
  if (tag) { filter.tag = tag[1]; renderTags(); }
  $('listView').hidden = !!post;
  $('postView').hidden = !post;
  if (post) { renderPost(post); window.scrollTo(0, 0); return; }
  document.title = BASE_TITLE;
  if (path && !tag) $('listStatus').textContent = "That post wasn't found.";
  renderList();
}

async function main() {
  $('search').addEventListener('input', e => { filter.q = e.target.value; renderList(); });
  await loadSeen();
  try { await loadPosts(); }
  catch (e) { $('listStatus').textContent = "Couldn't read learn/posts/index.json. Check it for a missing comma or quote."; return; }
  renderTags();
  window.addEventListener('hashchange', route);
  route();
}

main();
