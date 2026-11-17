/*
 * Off the Hook design system: ONE source for the colors and components used by every
 * surface (on-page panel, link check card, hover tips, toolbar popup, settings page).
 *
 *   PhishGuard.brand.adopt(shadowRootOrDocument, extraCss)  apply the shared styles
 *   PhishGuard.brand.header({ chip, ai, closeLabel, onClose, headingTag, headingId })
 *                                                           the shared ink header bar
 *
 * Palette: ink #111, neon lime #a6ff00, hot pink #ff2e88. Dark "street" theme by default;
 * light mode is "concrete" (lime/pink become fills only; text accents use darker shades so
 * they stay readable). Verdict colors: safe = lime, suspicious = amber, phishing = red.
 */
(function (root) {
  'use strict';

  const GFX = 'italic 900 {size}/1.15 Impact, "Arial Black", "Segoe UI Black", system-ui, sans-serif';
  const gfx = size => GFX.replace('{size}', size);

  const CSS = `
  :root, :host {
    --ink: #111111; --lime: #a6ff00; --pink: #ff2e88; --on-ink: #f2f3ee; --on-ink-muted: #b9bdc1;
    --bg: #17181a; --card: #1b1c1f; --fg: #f2f3ee; --muted: #a4a9ad; --line: #383b40; --soft: #24272b;
    --edge: #000000; --btn-border: #4a4e55;
    --lime-text: #a6ff00; --pink-text: #ff5fa2;
    --safe: #a6ff00; --safe-text: #a6ff00; --safe-glyph: #111111;
    --suspicious: #ffb020; --suspicious-text: #ffb020; --suspicious-glyph: #111111;
    --phishing: #ff3b3b; --phishing-text: #ff6b6b; --phishing-glyph: #ffffff;
    --ai: #ff2e88; --focus: #ff2e88;
  }
  @media (prefers-color-scheme: light) {
    :root, :host {
      --bg: #f4f4ef; --card: #f8f8f3; --fg: #111111; --muted: #4f545a; --line: #c9c9bf; --soft: #e8e8e0;
      --edge: #111111; --btn-border: #111111;
      --lime-text: #2f6b00; --pink-text: #c2185b;
      --safe-text: #2f6b00; --suspicious-text: #8a4b00; --phishing: #e00000; --phishing-text: #c40000;
      --ai: #d81b60; --focus: #c2185b;
    }
  }

  /* ---------- focus ---------- */
  button:focus-visible, summary:focus-visible, a:focus-visible, textarea:focus-visible, input:focus-visible {
    outline: 3px solid var(--focus); outline-offset: 2px;
  }

  /* ---------- header bar (same on every surface) ---------- */
  .ot-bar { display: flex; align-items: center; gap: 9px; padding: 9px 12px; background: var(--ink); color: var(--on-ink);
    border-bottom: 3px solid var(--pink); }
  .ot-logo { display: block; flex: none; width: 30px; height: 30px; filter: drop-shadow(2px 2px 0 #000); }
  .ot-title { margin: 0; flex: 1; min-width: 0; line-height: 0; display: flex; align-items: center; }
  .ot-wordmark { display: block; height: 30px; width: auto; max-width: 100%; }
  .ot-title-text { display: none; font: ${gfx('18px')}; letter-spacing: .03em; text-transform: uppercase; color: var(--lime);
    text-shadow: 2px 2px 0 #000, 3px 3px 0 var(--pink); line-height: 1.1; }
  .ot-title.no-img .ot-wordmark { display: none; }
  .ot-title.no-img .ot-title-text { display: inline; }
  .mode { font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .05em; padding: 2px 9px;
    border-radius: 999px; border: 1.5px solid var(--lime); color: var(--lime); white-space: nowrap; flex: none; }
  .mode.ai { border-color: var(--pink); color: #ff7bb3; }
  .close { flex: none; border: 0; background: transparent; color: var(--on-ink); font-size: 22px; line-height: 1; padding: 2px 6px;
    border-radius: 6px; cursor: pointer; box-shadow: none; }
  .close:hover { background: #2a2c30; color: var(--lime); }

  /* ---------- verdict block (panel, popup, link card, hover tips) ---------- */
  .verdict { display: flex; align-items: center; gap: 12px; }
  .vicon { display: inline-grid; place-items: center; flex: none; width: 40px; height: 40px; color: var(--vglyph, #fff);
    background: var(--vc, var(--muted)); font-weight: 900; font-size: 21px; line-height: 1; border-radius: 50%; }
  .v-safe { --vc: var(--safe); --vglyph: var(--safe-glyph); --vtext: var(--safe-text); }
  .v-suspicious { --vc: var(--suspicious); --vglyph: var(--suspicious-glyph); --vtext: var(--suspicious-text); }
  .v-phishing { --vc: var(--phishing); --vglyph: var(--phishing-glyph); --vtext: var(--phishing-text); }
  .v-ai { --vc: var(--ai); --vglyph: #ffffff; --vtext: var(--pink-text); }
  .v-low { --vc: #fdd835; --vglyph: #111111; --vtext: var(--suspicious-text); }
  .v-low .vicon { border-radius: 0; clip-path: polygon(50% 0, 100% 100%, 0 100%); padding-top: 11px; font-size: 16px; }
  .v-pending { --vc: var(--muted); --vtext: var(--muted); }
  /* Shape differs by verdict so color is never the only cue. */
  .v-suspicious .vicon { border-radius: 0; clip-path: polygon(50% 0, 100% 100%, 0 100%); padding-top: 11px; font-size: 16px; }
  .v-phishing .vicon { border-radius: 0; clip-path: polygon(30% 0,70% 0,100% 30%,100% 70%,70% 100%,30% 100%,0 70%,0 30%); }
  .v-ai .vicon { border-radius: 8px; font-size: 14px; }
  .vlabel { font: ${gfx('22px')}; text-transform: uppercase; letter-spacing: .02em; color: var(--vtext, var(--fg)); }
  .vscore { color: var(--muted); font-size: 13px; margin-top: 2px; }
  .meter { height: 8px; background: var(--soft); border: 1px solid var(--line); border-radius: 4px; overflow: hidden; margin-top: 6px; width: 190px; max-width: 100%; }
  .meter > span { display: block; height: 100%; background: var(--vc);
    background-image: repeating-linear-gradient(-45deg, transparent 0 6px, rgba(0,0,0,.18) 6px 9px); }

  /* ---------- buttons: stickers with a hard shadow; lime = primary ---------- */
  .actions { display: flex; flex-wrap: wrap; gap: 8px; }
  .actions button, .ot-btn, .ot-page button:not(.close) {
    font: inherit; font-size: 13px; font-weight: 700; color: var(--fg); background: var(--soft); border: 2px solid var(--btn-border);
    border-radius: 8px; padding: 5px 12px; cursor: pointer; box-shadow: 2px 2px 0 var(--edge); transition: transform .06s, box-shadow .06s;
  }
  .actions button:hover:not(:disabled), .ot-btn:hover:not(:disabled), .ot-page button:not(.close):hover:not(:disabled) {
    transform: translate(-1px, -1px); box-shadow: 3px 3px 0 var(--edge); border-color: var(--lime-text);
  }
  .actions button:active:not(:disabled), .ot-btn:active:not(:disabled), .ot-page button:not(.close):active:not(:disabled) {
    transform: translate(1px, 1px); box-shadow: none;
  }
  button.primary, .ot-page button.primary { background: var(--lime); color: var(--ink); border-color: var(--ink); font-weight: 900;
    text-transform: uppercase; letter-spacing: .03em; }
  button.primary:hover:not(:disabled) { border-color: var(--ink) !important; }
  button.danger, .ot-page button.danger { color: #fff; background: #e00000; border-color: var(--ink); font-weight: 800; }
  button.danger:hover:not(:disabled) { border-color: var(--ink) !important; }
  .ot-page button.ghost { background: transparent; box-shadow: none; }
  button.small, .ot-page button.small { padding: 3px 10px; font-size: 13px; }
  button:disabled { opacity: .5; cursor: default; box-shadow: none; }

  /* ---------- headings, notes, alerts ---------- */
  h3, .ot-h { margin: 12px 0 6px; font: ${gfx('13px')}; text-transform: uppercase; letter-spacing: .05em; color: var(--pink-text); }
  .note { padding: 7px 10px; border-radius: 6px; background: var(--soft); border-left: 4px solid var(--note-color, var(--pink)); font-size: 13px; }
  .note.lime { --note-color: var(--lime-text); }
  .note.warn { --note-color: var(--suspicious); }
  .note.verdict-color { --note-color: var(--vc, var(--pink)); font-weight: 600; }
  .alertbox { padding: 10px 12px; border: 2px solid var(--phishing); border-radius: 10px;
    background: color-mix(in srgb, var(--phishing) 12%, var(--bg)); box-shadow: 3px 3px 0 var(--phishing); }
  .alertbox p { margin: 4px 0 0; font-size: 13px; }
  .alerttitle { font: ${gfx('15px')}; text-transform: uppercase; letter-spacing: .02em; color: var(--phishing-text); }

  /* ---------- check lists (✗ failed / ✓ passed / i info) ---------- */
  .checks { list-style: none; margin: 8px 0 0; padding: 6px 0 0; border-top: 2px solid var(--line); }
  .checks li { display: flex; gap: 6px; margin: 3px 0; font-size: 13px; }
  .checks .m { flex: none; width: 14px; text-align: center; font-weight: 900; }
  .checks .fail { font-weight: 600; } .checks .fail .m { color: var(--phishing-text); }
  .checks .fail.medium .m, .checks .fail.low .m { color: var(--suspicious-text); }
  .checks .pass { color: var(--muted); } .checks .pass .m { color: var(--safe-text); }
  .checks .info .m { color: var(--muted); }

  /* ---------- chips, code, labels ---------- */
  .chips { display: flex; flex-wrap: wrap; gap: 4px; }
  .chip, .code { font: 12px/1.4 ui-monospace, SFMono-Regular, Consolas, monospace; background: var(--soft); border: 1px solid var(--line);
    border-left: 3px solid var(--lime-text); border-radius: 4px; padding: 1px 6px; max-width: 100%; overflow-wrap: anywhere; color: var(--fg); }
  .stag { display: inline-block; margin-left: 6px; padding: 0 7px; border: 1.5px solid var(--pink-text); color: var(--pink-text);
    border-radius: 999px; font-size: 11px; font-weight: 700; }
  .ai-tag { font-size: 10px; font-weight: 800; color: #fff; background: var(--ai); border-radius: 3px; padding: 1px 4px; }
  .k { color: var(--muted); font-size: 12px; }

  /* ---------- collapsible sections ---------- */
  details { border-top: 2px solid var(--line); }
  summary { cursor: pointer; padding: 10px 14px; list-style-position: inside; font: ${gfx('14px')}; text-transform: uppercase; letter-spacing: .03em; }
  summary::marker { color: var(--lime-text); }

  /* ---------- footer / misc ---------- */
  .disclaimer { padding-top: 8px; border-top: 2px solid var(--line); font-size: 12px; color: var(--muted); }
  .empty { color: var(--muted); font-size: 13px; }
  .spin { display: inline-block; width: 10px; height: 10px; border: 2px solid var(--lime); border-right-color: transparent; border-radius: 50%;
    animation: ot-spin 0.8s linear infinite; vertical-align: -1px; }
  @keyframes ot-spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) { .spin { animation: none; } * { transition: none !important; } }
  `;

  function url(path) {
    try { if (root.chrome && chrome.runtime && chrome.runtime.getURL) return chrome.runtime.getURL(path); } catch (e) { /* fall through */ }
    return '/' + path;
  }

  // Apply the shared styles (plus surface-specific CSS) to a shadow root or a document.
  // Documents (popup, settings): a <style> placed FIRST in <head>, so the page's own
  // stylesheet can override it. Shadow roots (in webmail): a constructable stylesheet,
  // which also works on pages whose CSP blocks inline <style>.
  function adopt(target, extraCss) {
    const text = CSS + '\n' + (extraCss || '');
    if (target && target.nodeType === 9) {
      const style = target.createElement('style');
      style.id = 'ot-brand';
      style.textContent = text;
      target.head.insertBefore(style, target.head.firstChild);
      if (target.body) target.body.classList.add('ot-page');
      else target.addEventListener('DOMContentLoaded', () => target.body.classList.add('ot-page'));
      return;
    }
    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(text);
      target.adoptedStyleSheets = [...(target.adoptedStyleSheets || []), sheet];
    } catch (e) {
      const style = document.createElement('style');
      style.textContent = text;
      (target.head || target).appendChild(style);
    }
  }

  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) if (c != null && c !== false) e.append(c);
    return e;
  }

  // The shared header bar: logo, wordmark (falls back to graffiti text), mode chip, close.
  function header(opts) {
    const o = opts || {};
    const title = el(o.headingTag || 'div', { class: 'ot-title', id: o.headingId || null, tabindex: o.headingId ? '-1' : null });
    const word = el('img', { class: 'ot-wordmark', alt: 'Off the Hook', src: url('icons/wordmark.png'), width: '140', height: '30' });
    word.addEventListener('error', () => title.classList.add('no-img'));
    title.append(word, el('span', { class: 'ot-title-text', 'aria-hidden': 'true', text: 'Off the Hook' }));
    const logo = el('img', { class: 'ot-logo', alt: '', src: url('icons/icon48.png'), width: '30', height: '30' });
    logo.addEventListener('error', () => logo.remove());
    return el('header', { class: 'ot-bar' },
      logo,
      title,
      o.chip ? el('span', { class: 'mode' + (o.ai ? ' ai' : ''), text: o.chip }) : null,
      o.onClose ? el('button', { class: 'close', type: 'button', 'aria-label': o.closeLabel || 'Close', text: '×', onclick: o.onClose }) : null
    );
  }

  (root.PhishGuard = root.PhishGuard || {}).brand = { CSS, adopt, header, url };

  // Extension pages include <script src="../shared/brand.js" data-adopt> in <head>.
  const me = typeof document !== 'undefined' && document.currentScript;
  if (me && me.hasAttribute('data-adopt')) adopt(document);
})(typeof globalThis !== 'undefined' ? globalThis : this);
