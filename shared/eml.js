/*
 * Reads a saved email file (.eml, what Gmail and Outlook on the web give you when you
 * download a message) into the same shape the analyzer uses for an open email. Used by the
 * scoreboard. Pure JavaScript: no HTML is rendered and nothing in the email is run or fetched.
 *
 *   parse(bytes | string) -> emailData (from, replyTo, subject, body, links, attachments,
 *                            imageCount, imageAlts, authResults, headers)
 */
(function (root, factory) {
  const mod = factory();
  if (typeof module === 'object' && module.exports) module.exports = mod;
  else { root.PhishGuard = root.PhishGuard || {}; root.PhishGuard.eml = mod; }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const KEEP_HEADERS = ['authentication-results', 'return-path', 'reply-to', 'from', 'received-spf',
    'x-ms-exchange-organization-authas', 'x-ms-exchange-crosstenant-authas', 'x-ms-exchange-organization-authsource',
    'x-ms-exchange-organization-scl', 'x-forefront-antispam-report', 'x-microsoft-antispam'];

  function latin1(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 32768) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 32768));
    return s;
  }
  const bytesOf = s => Uint8Array.from(s, c => c.charCodeAt(0) & 255);
  function decodeText(bytes, charset) {
    const cs = String(charset || 'utf-8').toLowerCase().replace(/^"|"$/g, '');
    for (const label of [cs, 'utf-8', 'windows-1252']) {
      try { return new TextDecoder(label === 'us-ascii' || label === 'ascii' ? 'windows-1252' : label).decode(bytes); } catch (e) { /* try the next */ }
    }
    return latin1(bytes);
  }

  // RFC 2047 encoded words in headers: =?utf-8?B?...?= / =?utf-8?Q?...?=
  function decodeWords(s) {
    return String(s || '').replace(/\?=\s+=\?/g, '?==?').replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (m, cs, enc, data) => {
      try {
        const bytes = enc.toUpperCase() === 'B' ? bytesOf(atob(data))
          : bytesOf(data.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (x, h) => String.fromCharCode(parseInt(h, 16))));
        return decodeText(bytes, cs.split('*')[0]);
      } catch (e) { return m; }
    });
  }

  function splitHeadBody(s) {
    const m = /\r?\n\r?\n/.exec(s);
    return m ? { head: s.slice(0, m.index), body: s.slice(m.index + m[0].length) } : { head: s, body: '' };
  }
  function parseHeaders(head) {
    const out = {};
    let cur = null;
    for (const line of head.split(/\r?\n/)) {
      if (/^[ \t]/.test(line) && cur) { cur.v += ' ' + line.trim(); continue; }
      const m = line.match(/^([!-9;-~]+):[ \t]*(.*)$/);
      if (!m) continue;
      cur = { k: m[1].toLowerCase(), v: m[2] };
      (out[cur.k] = out[cur.k] || []).push(cur);
    }
    for (const k of Object.keys(out)) out[k] = out[k].map(x => x.v);
    return out;
  }
  // "text/html; charset=utf-8" -> { value, params }; handles quotes and RFC 2231 (filename*=utf-8''...).
  function parseParams(v) {
    const parts = String(v || '').split(/;(?=(?:[^"]*"[^"]*")*[^"]*$)/);
    const params = {};
    const pieces = {};
    for (const p of parts.slice(1)) {
      const m = p.match(/^\s*([^=\s]+)\s*=\s*(.*?)\s*$/);
      if (!m) continue;
      let key = m[1].toLowerCase(), val = m[2].replace(/^"(.*)"$/, '$1');
      const ext = key.match(/^([^*]+)\*(\d+)?\*?$/);
      if (ext) {
        const base = ext[1];
        if (/^[\w-]+'[\w-]*'/.test(val)) {
          const [cs, , rest] = val.split("'");
          val = decodeText(bytesOf(rest.replace(/%([0-9A-Fa-f]{2})/g, (x, h) => String.fromCharCode(parseInt(h, 16)))), cs);
        }
        (pieces[base] = pieces[base] || []).push([Number(ext[2] || 0), val]);
      } else params[key] = val;
    }
    for (const [k, list] of Object.entries(pieces)) params[k] = list.sort((a, b) => a[0] - b[0]).map(x => x[1]).join('');
    return { value: (parts[0] || '').trim().toLowerCase(), params };
  }
  function decodeBody(s, cte) {
    const enc = String(cte || '').trim().toLowerCase();
    if (enc === 'base64') {
      try { return bytesOf(atob(s.replace(/[^A-Za-z0-9+/=]/g, ''))); } catch (e) { return bytesOf(s); }
    }
    if (enc === 'quoted-printable') {
      return bytesOf(s.replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, (x, h) => String.fromCharCode(parseInt(h, 16))));
    }
    return bytesOf(s);
  }

  function parseAddress(s) {
    s = decodeWords(String(s || '')).trim();
    const m = s.match(/^\s*"?([^"<]*?)"?\s*<\s*([^<>\s]+@[^<>\s]+)\s*>/);
    if (m) return { name: m[1].trim(), address: m[2].trim().toLowerCase() };
    const a = s.match(/[^\s<>"',;]+@[^\s<>"',;]+/);
    return { name: '', address: a ? a[0].toLowerCase() : '' };
  }

  const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', copy: '©', reg: '®', trade: '™', hellip: '…', ndash: '–', mdash: '—',
    rsquo: '’', lsquo: '‘', rdquo: '”', ldquo: '“', laquo: '«', raquo: '»', bull: '•', middot: '·', euro: '€', pound: '£', cent: '¢',
    zwnj: '', zwj: '', shy: '', eacute: 'é', egrave: 'è', aacute: 'á', agrave: 'à', iacute: 'í', oacute: 'ó', uacute: 'ú',
    auml: 'ä', ouml: 'ö', uuml: 'ü', Auml: 'Ä', Ouml: 'Ö', Uuml: 'Ü', szlig: 'ß', ntilde: 'ñ', ccedil: 'ç', Eacute: 'É' };
  const decodeEntities = s => s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') { const n = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); try { return String.fromCodePoint(n); } catch (x) { return m; } }
    const v = ENTITIES[e] != null ? ENTITIES[e] : ENTITIES[e.toLowerCase()];
    return v == null ? m : v;
  });
  const attr = (tag, name) => { const m = tag.match(new RegExp('\\b' + name + '\\s*=\\s*("([^"]*)"|\'([^\']*)\'|([^\\s>]+))', 'i')); return m ? decodeEntities(m[2] != null ? m[2] : m[3] != null ? m[3] : m[4]) : ''; };
  const tidy = s => s.replace(/[ \t\u00a0]+/g, ' ').replace(/ *\n */g, '\n').replace(/\n{3,}/g, '\n\n').trim();

  // HTML -> visible text, links and pictures, without rendering it.
  function readHtml(html) {
    let h = String(html).replace(/<!--[\s\S]*?-->/g, ' ').replace(/<(script|style|head|title)\b[\s\S]*?<\/\1>/gi, ' ');
    const links = [], alts = [];
    let images = 0;
    h.replace(/<img\b[^>]*>/gi, tag => {
      const w = attr(tag, 'width'), ht = attr(tag, 'height');
      if (!(w === '1' && ht === '1')) { images++; const a = attr(tag, 'alt'); if (a) alts.push(a); }
      return tag;
    });
    h.replace(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi, (m, attrs, inner) => {
      const href = attr('<a ' + attrs + '>', 'href');
      const text = tidy(decodeEntities(inner.replace(/<img\b[^>]*>/gi, t => attr(t, 'alt') || ' ').replace(/<[^>]+>/g, ' ')));
      if (href) links.push({ text: text.slice(0, 300), href: href.trim() });
      return m;
    });
    const text = tidy(decodeEntities(h
      .replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|tr|li|h[1-6]|table|blockquote|section|article)>/gi, '\n')
      .replace(/<(td|th)\b[^>]*>/gi, ' ').replace(/<[^>]+>/g, '')));
    return { text, links, images, alts };
  }

  function walk(headers, body, out, depth) {
    if (depth > 12) return;
    const ct = parseParams((headers['content-type'] || ['text/plain'])[0]);
    const cte = (headers['content-transfer-encoding'] || [''])[0];
    const disp = parseParams((headers['content-disposition'] || [''])[0]);
    const filename = decodeWords(disp.params.filename || ct.params.name || '');
    if (ct.value.startsWith('multipart/')) {
      const b = ct.params.boundary;
      if (!b) return;
      const chunks = body.split(new RegExp('(?:^|\\r?\\n)--' + b.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(--)?[ \\t]*(?=\\r?\\n|$)'));
      // split() also returns the "(--)" capture: '--' marks the closing boundary; what follows is epilogue.
      for (let i = 1; i < chunks.length; i++) {
        const c = chunks[i];
        if (c === '--') break;
        if (c == null) continue;
        const piece = c.replace(/^\r?\n/, '');
        if (!piece.trim()) continue;
        const { head, body: pb } = splitHeadBody(piece);
        walk(parseHeaders(head), pb, out, depth + 1);
      }
      return;
    }
    if (ct.value === 'message/rfc822' && disp.value !== 'attachment') {
      const inner = splitHeadBody(latin1(decodeBody(body, cte)));
      walk(parseHeaders(inner.head), inner.body, out, depth + 1);
      return;
    }
    const isText = ct.value === 'text/plain' || ct.value === 'text/html';
    // Keep pictures (inline or attached) so a QR code in them can be read.
    if (ct.value.startsWith('image/') && out.imageData.length < 10) {
      const bytes = decodeBody(body, cte);
      if (bytes.length > 100 && bytes.length < 5e6) out.imageData.push({ mime: ct.value, bytes });
    }
    if (filename && (disp.value === 'attachment' || !isText)) {
      if (ct.value.startsWith('image/') && disp.value !== 'attachment') out.images++;
      else out.attachments.push(filename.slice(0, 200));
      return;
    }
    if (ct.value === 'text/html') out.htmls.push(decodeText(decodeBody(body, cte), ct.params.charset));
    else if (ct.value === 'text/plain' || !ct.value) out.texts.push(decodeText(decodeBody(body, cte), ct.params.charset));
    else if (ct.value.startsWith('image/')) out.images++;
  }

  function parse(input) {
    const raw = typeof input === 'string' ? input : latin1(input instanceof Uint8Array ? input : new Uint8Array(input));
    const { head, body } = splitHeadBody(raw.replace(/^\uFEFF/, ''));
    const H = parseHeaders(head);
    const out = { texts: [], htmls: [], attachments: [], images: 0, imageData: [] };
    walk(H, body, out, 0);
    let text = '', links = [], imageAlts = [], imageCount = out.images;
    if (out.htmls.length) {
      const r = readHtml(out.htmls.join('\n'));
      text = r.text; links = r.links; imageAlts = r.alts; imageCount += r.images;
    } else {
      text = tidy(out.texts.join('\n\n'));
      links = (text.match(/\bhttps?:\/\/[^\s<>"')\]]+/gi) || []).map(u => ({ text: u, href: u }));
    }
    const headers = {};
    for (const k of KEEP_HEADERS) if (H[k]) headers[k] = H[k].map(v => String(v).slice(0, 2000)).slice(0, 10);
    return {
      from: parseAddress((H.from || [''])[0]),
      replyTo: (H['reply-to'] || []).flatMap(v => decodeWords(v).split(',')).map(v => parseAddress(v).address).filter(Boolean),
      subject: decodeWords((H.subject || [''])[0]).trim(),
      body: text.slice(0, 100000),
      links: links.slice(0, 500),
      attachments: out.attachments.slice(0, 50),
      imageCount,
      imageAlts: imageAlts.slice(0, 20),
      authResults: (H['authentication-results'] || []).concat(H['arc-authentication-results'] || []).join('\n'),
      headers,
      date: (H.date || [''])[0],
      pictures: out.imageData // [{ mime, bytes }] for QR reading; not used by the analyzer
    };
  }

  return { parse, _internal: { readHtml, parseParams, decodeWords } };
});
