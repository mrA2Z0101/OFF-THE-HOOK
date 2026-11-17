/*
 * File checker: looks inside a file's bytes for signs it is dangerous, without opening or
 * running it and without sending it anywhere.
 *
 *   inspect({ name, bytes: Uint8Array }, { analyzer?, settings?, lists? }) -> Promise<Report>
 *   Report = { name, size, type: { id, label }, verdict: 'danger'|'caution'|'ok',
 *              findings: [{ id, severity: 'high'|'medium'|'low', title, detail }],
 *              links: [link entries from the analyzer], images: [{ mime, bytes } | { pixels }],
 *              notes: [string], inner: [Report] (files inside archives / PDFs) }
 *
 * What it checks:
 *   - the real file type (from its first bytes) against its name: a "PDF" that is a program
 *   - PDFs: JavaScript, auto-run actions, launching programs, embedded files, forms that send
 *     data, encryption, hidden keywords, links (checked like email links), "click to view" lures,
 *     and pictures (so QR codes inside can be read)
 *   - Word/Excel/PowerPoint: macros, Excel 4.0 macro sheets, content loaded from the internet
 *     when opened, DDE commands, embedded objects, "Enable editing" lures
 *   - archives: risky files inside, password protection, nested archives, zip bombs
 *   - web pages (.html/.svg): fake sign-in forms, redirects, scrambled code, hidden downloads
 *   - RTF documents with embedded objects, OneNote files hiding attachments
 *   - programs, scripts, shortcuts and disk images in any disguise
 */
(function (root, factory) {
  const isNode = typeof module === 'object' && module.exports;
  const mod = factory(isNode ? require('./config.js') : root.PhishGuard.config);
  if (isNode) module.exports = mod;
  else root.PhishGuard.filecheck = mod;
})(typeof globalThis !== 'undefined' ? globalThis : this, function (CONFIG) {
  'use strict';

  const MAX_FILE = 100 * 1024 * 1024;     // larger files only get name and type checks
  const MAX_INFLATE = 30 * 1024 * 1024;   // per stream / zip entry (zip-bomb guard)
  const MAX_TOTAL_INFLATE = 120 * 1024 * 1024;
  const MAX_DEPTH = 2;                    // archive inside archive inside archive: stop
  const RISKY_EXT = new Set(CONFIG.RISKY_EXTENSIONS);
  const ARCHIVE_EXT = new Set(CONFIG.ARCHIVE_EXTENSIONS);
  const DECOY_EXT = new Set(CONFIG.DECOY_EXTENSIONS);
  const SCRIPT_EXT = new Set(['js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'ps1', 'psm1', 'bat', 'cmd', 'scr', 'pif', 'com', 'cpl', 'msc', 'jar', 'reg', 'url', 'application', 'appref-ms', 'library-ms', 'settingcontent-ms', 'inf', 'sct', 'xll', 'iqy', 'slk', 'chm']);

  const TYPES = {
    pdf: 'PDF document', zip: 'ZIP archive', ooxml: 'Office document', docx: 'Word document', xlsx: 'Excel workbook',
    pptx: 'PowerPoint presentation', odf: 'OpenDocument file', jar: 'Java program', apk: 'Android app', ole: 'Older Office / Outlook file',
    msi: 'Windows installer', exe: 'Windows program', elf: 'Linux program', macho: 'Mac program', lnk: 'Windows shortcut',
    iso: 'Disk image', vhd: 'Virtual disk image', cab: 'Windows cabinet archive', onenote: 'OneNote file', rtf: 'Rich Text document',
    html: 'Web page', svg: 'SVG picture (can contain code)', '7z': '7-Zip archive', rar: 'RAR archive', gzip: 'GZIP archive',
    png: 'PNG picture', jpeg: 'JPEG picture', gif: 'GIF picture', webp: 'WebP picture', bmp: 'BMP picture', text: 'Plain text',
    script: 'Script', unknown: 'Unknown type'
  };
  // What a file name promises, by extension (used to spot disguises).
  const EXPECT = {
    pdf: ['pdf'], doc: ['ole', 'rtf'], dot: ['ole'], xls: ['ole'], ppt: ['ole'], msg: ['ole'], rtf: ['rtf'],
    docx: ['docx'], docm: ['docx'], dotx: ['docx'], dotm: ['docx'], xlsx: ['xlsx'], xlsm: ['xlsx'], xltx: ['xlsx'], xltm: ['xlsx'], xlsb: ['xlsx'],
    pptx: ['pptx'], pptm: ['pptx'], ppsx: ['pptx'], ppsm: ['pptx'], odt: ['odf'], ods: ['odf'], odp: ['odf'],
    zip: ['zip', 'docx', 'xlsx', 'pptx', 'ooxml', 'odf', 'jar', 'apk'], jpg: ['jpeg'], jpeg: ['jpeg'], png: ['png'], gif: ['gif'],
    webp: ['webp'], bmp: ['bmp'], txt: ['text'], csv: ['text'], html: ['html'], htm: ['html'], svg: ['svg', 'html'],
    one: ['onenote'], iso: ['iso'], img: ['iso'], exe: ['exe'], dll: ['exe'], msi: ['msi', 'ole'], '7z': ['7z'], rar: ['rar'], gz: ['gzip'],
    eml: ['text'], json: ['text'], xml: ['text', 'html', 'svg']
  };
  const PROGRAM_TYPES = new Set(['exe', 'elf', 'macho', 'lnk', 'iso', 'vhd', 'msi', 'jar', 'apk']);

  // ---------- byte helpers ----------
  function latin1(b, start, end) {
    start = start || 0; end = Math.min(end == null ? b.length : end, b.length);
    let s = '';
    for (let i = start; i < end; i += 32768) s += String.fromCharCode.apply(null, b.subarray(i, Math.min(end, i + 32768)));
    return s;
  }
  const at = (b, off, sig) => { for (let i = 0; i < sig.length; i++) if (b[off + i] !== sig[i]) return false; return off + sig.length <= b.length; };
  const ascii = s => Array.from(s, c => c.charCodeAt(0));
  const u16 = (b, o) => b[o] | (b[o + 1] << 8);
  const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16)) + b[o + 3] * 0x1000000;
  const u64 = (b, o) => u32(b, o) + u32(b, o + 4) * 0x100000000;
  function indexOfBytes(b, pat, from) {
    const first = pat[0];
    for (let i = from || 0; i <= b.length - pat.length; i++) {
      if (b[i] !== first) continue;
      let ok = true;
      for (let j = 1; j < pat.length; j++) if (b[i + j] !== pat[j]) { ok = false; break; }
      if (ok) return i;
    }
    return -1;
  }
  const utf16 = s => Array.from(s).flatMap(c => [c.charCodeAt(0) & 0xff, c.charCodeAt(0) >> 8]);
  const extOf = name => { const m = String(name || '').toLowerCase().replace(/[\s.]+$/, '').match(/\.([a-z0-9-]{1,12})$/); return m ? m[1] : ''; };

  // Decompress with the browser's built-in streams, refusing to produce more than `limit` bytes.
  async function inflate(bytes, format, budget) {
    if (typeof DecompressionStream === 'undefined') return null;
    const limit = Math.min(MAX_INFLATE, budget ? budget.left : MAX_INFLATE);
    try {
      const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
      const reader = stream.getReader();
      const chunks = [];
      let total = 0;
      for (;;) {
        let r;
        try { r = await reader.read(); } catch (e) { break; } // truncated / slightly corrupt data: keep what decoded
        if (r.done) break;
        chunks.push(r.value);
        total += r.value.length;
        if (total > limit) { try { await reader.cancel(); } catch (e) { /* ignore */ } if (budget) budget.bomb = true; break; }
      }
      if (budget) budget.left -= total;
      if (!total) return null;
      const out = new Uint8Array(total);
      let o = 0;
      for (const c of chunks) { out.set(c.subarray(0, Math.min(c.length, total - o)), o); o += c.length; }
      return out;
    } catch (e) { return null; }
  }

  // ---------- type sniffing ----------
  function sniff(b, name) {
    if (latin1(b, 0, 1024).includes('%PDF-')) return 'pdf';
    if (at(b, 0, [0x50, 0x4b, 0x03, 0x04]) || at(b, 0, [0x50, 0x4b, 0x05, 0x06])) return 'zip';
    if (at(b, 0, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return extOf(name) === 'msi' ? 'msi' : 'ole';
    if (at(b, 0, [0x4d, 0x5a])) return 'exe';
    if (at(b, 0, [0x7f, 0x45, 0x4c, 0x46])) return 'elf';
    if (at(b, 0, [0xcf, 0xfa, 0xed, 0xfe]) || at(b, 0, [0xfe, 0xed, 0xfa, 0xcf]) || at(b, 0, [0xca, 0xfe, 0xba, 0xbe])) return 'macho';
    if (at(b, 0, ascii('{\\rt'))) return 'rtf';
    if (at(b, 0, [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])) return 'lnk';
    if (at(b, 0, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return '7z';
    if (at(b, 0, ascii('Rar!\x1a\x07'))) return 'rar';
    if (at(b, 0, [0x1f, 0x8b])) return 'gzip';
    if (at(b, 0, ascii('MSCF'))) return 'cab';
    if (at(b, 0, [0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d])) return 'onenote';
    for (const off of [0x8001, 0x8801, 0x9001]) if (at(b, off, ascii('CD001'))) return 'iso';
    if (at(b, 0, ascii('conectix')) || at(b, 0, ascii('vhdxfile')) || (b.length > 512 && at(b, b.length - 512, ascii('conectix')))) return 'vhd';
    if (at(b, 0, [0x89, 0x50, 0x4e, 0x47])) return 'png';
    if (at(b, 0, [0xff, 0xd8, 0xff])) return 'jpeg';
    if (at(b, 0, ascii('GIF8'))) return 'gif';
    if (at(b, 0, ascii('RIFF')) && at(b, 8, ascii('WEBP'))) return 'webp';
    if (at(b, 0, ascii('BM')) && b.length > 26 && u32(b, 2) === b.length) return 'bmp';
    const head = latin1(b, 0, 4096).replace(/^﻿|^\xEF\xBB\xBF/, '').toLowerCase();
    if (/<svg[\s>]/.test(head) && !/<html[\s>]/.test(head)) return 'svg';
    if (/<!doctype html|<html[\s>]|<head[\s>]|<body[\s>]|<script[\s>]|<form[\s>]|<iframe[\s>]|<meta\s/.test(head)) return 'html';
    if (SCRIPT_EXT.has(extOf(name))) return 'script';
    let printable = 0;
    const n = Math.min(b.length, 4096);
    for (let i = 0; i < n; i++) { const c = b[i]; if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 160) printable++; }
    return n && printable / n > 0.95 ? 'text' : 'unknown';
  }

  // ---------- report building ----------
  function newReport(name, size) {
    return { name, size, type: { id: 'unknown', label: TYPES.unknown }, verdict: 'ok', findings: [], links: [], images: [], notes: [], inner: [], urls: [] };
  }
  function add(rep, id, severity, title, detail) {
    if (rep.findings.some(f => f.id === id && f.title === title)) return;
    rep.findings.push({ id, severity, title, detail });
  }
  const addUrl = (rep, url, source) => {
    const u = String(url || '').trim().replace(/[\u0000-\u001f]/g, '');
    if (!/^(https?:\/\/|mailto:|\\\\|file:)/i.test(u) || u.length > 2000) return;
    if (!rep.urls.some(x => x.href === u)) rep.urls.push({ href: u, source });
  };

  function checkName(rep, name) {
    const hasRtlo = /[‮‭‏؜]/.test(name);
    const clean = name.replace(/[‪-‮‎‏؜]/g, '').toLowerCase().replace(/[\s.]+$/, '');
    const parts = clean.split('.');
    const ext = parts.length > 1 ? parts[parts.length - 1] : '';
    const prev = parts.length > 2 ? parts[parts.length - 2] : '';
    if (hasRtlo) add(rep, 'name_rtlo', 'high', 'File name hides its real type', 'The name contains an invisible character that reverses text, so the end of the name (its real type) is disguised.');
    else if (prev && DECOY_EXT.has(prev) && (RISKY_EXT.has(ext) || ARCHIVE_EXT.has(ext))) add(rep, 'name_double_ext', 'high', `Looks like a .${prev} but is a .${ext}`, `"${name}" pretends to be a .${prev} file. The real type is whatever comes last.`);
    if (/\s{6,}\S+\.\w+$/.test(name)) add(rep, 'name_padding', 'high', 'File name pushes its real type out of view', 'Lots of spaces in the name hide the real file type at the end.');
    return ext;
  }

  // ---------- PDF ----------
  function pdfUnescape(s) {
    return s.replace(/\\(\r\n|\n|\r|[0-7]{1,3}|.)/g, (m, c) => {
      if (/^[\r\n]/.test(c)) return '';
      if (/^[0-7]+$/.test(c)) return String.fromCharCode(parseInt(c, 8) & 0xff);
      return { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f' }[c] || c;
    });
  }
  const hexToStr = h => { h = h.replace(/[^0-9a-f]/gi, ''); if (h.length % 2) h += '0'; let s = ''; for (let i = 0; i < h.length; i += 2) s += String.fromCharCode(parseInt(h.substr(i, 2), 16)); return s; };
  // PDF text strings may be UTF-16BE with a BOM.
  const pdfText = s => (s.charCodeAt(0) === 0xfe && s.charCodeAt(1) === 0xff
    ? Array.from({ length: (s.length - 2) >> 1 }, (_, i) => String.fromCharCode((s.charCodeAt(2 + 2 * i) << 8) | s.charCodeAt(3 + 2 * i))).join('') : s);

  // Value of a string after a key: "/URI (...)" or "/URI <...>".
  function pdfStrings(text, key) {
    const out = [];
    const re = new RegExp('\\/' + key + '\\s*(\\((?:\\\\[\\s\\S]|[^\\\\)])*\\)|<[0-9a-fA-F\\s]*>)', 'g');
    let m;
    while ((m = re.exec(text)) && out.length < 500) {
      const v = m[1];
      out.push(pdfText(v[0] === '(' ? pdfUnescape(v.slice(1, -1)) : hexToStr(v.slice(1, -1))));
    }
    return out;
  }

  const dictNum = (d, key) => { const m = d.match(new RegExp('\\/' + key + '\\s+(\\d+)(?!\\s+\\d+\\s+R)')); return m ? Number(m[1]) : null; };
  function filtersOf(dict) {
    const m = dict.match(/\/Filter\s*(\[[^\]]*\]|\/[A-Za-z0-9]+)/);
    if (!m) return [];
    return (m[1].match(/\/[A-Za-z0-9]+/g) || []).map(f => f.slice(1));
  }

  function asciiHex(b) { return Uint8Array.from(hexToStr(latin1(b).split('>')[0]), c => c.charCodeAt(0)); }
  function ascii85(b) {
    const s = latin1(b).replace(/\s/g, '').replace(/^<~/, '').split('~>')[0];
    const out = [];
    let tuple = 0, count = 0;
    for (const ch of s) {
      if (ch === 'z' && count === 0) { out.push(0, 0, 0, 0); continue; }
      const c = ch.charCodeAt(0) - 33;
      if (c < 0 || c > 84) continue;
      tuple = tuple * 85 + c;
      if (++count === 5) { out.push((tuple >>> 24) & 255, (tuple >>> 16) & 255, (tuple >>> 8) & 255, tuple & 255); tuple = 0; count = 0; }
    }
    if (count > 1) {
      for (let i = count; i < 5; i++) tuple = tuple * 85 + 84;
      for (let i = 0; i < count - 1; i++) out.push((tuple >>> (24 - 8 * i)) & 255);
    }
    return Uint8Array.from(out);
  }
  // PNG predictors (DecodeParms /Predictor >= 10).
  function unpredict(data, dict) {
    const pred = dictNum(dict, 'Predictor');
    if (!pred || pred < 10) return data;
    const colors = dictNum(dict, 'Colors') || 1, bpc = dictNum(dict, 'BitsPerComponent') || 8, cols = dictNum(dict, 'Columns') || 1;
    const bpp = Math.max(1, Math.ceil(colors * bpc / 8)), rowLen = Math.ceil(cols * colors * bpc / 8);
    const rows = Math.floor(data.length / (rowLen + 1));
    const out = new Uint8Array(rows * rowLen);
    for (let r = 0; r < rows; r++) {
      const type = data[r * (rowLen + 1)];
      for (let i = 0; i < rowLen; i++) {
        const x = data[r * (rowLen + 1) + 1 + i];
        const a = i >= bpp ? out[r * rowLen + i - bpp] : 0;
        const up = r ? out[(r - 1) * rowLen + i] : 0;
        const ul = r && i >= bpp ? out[(r - 1) * rowLen + i - bpp] : 0;
        let v = x;
        if (type === 1) v = x + a; else if (type === 2) v = x + up; else if (type === 3) v = x + ((a + up) >> 1);
        else if (type === 4) { const p = a + up - ul, pa = Math.abs(p - a), pb = Math.abs(p - up), pc = Math.abs(p - ul); v = x + (pa <= pb && pa <= pc ? a : pb <= pc ? up : ul); }
        out[r * rowLen + i] = v & 255;
      }
    }
    return out;
  }

  // Raw image samples -> RGBA (8-bit gray/RGB, 1-bit gray or masks: enough for QR codes).
  function rawImage(data, dict) {
    const w = dictNum(dict, 'Width'), h = dictNum(dict, 'Height');
    const mask = /\/ImageMask\s+true/.test(dict);
    const bpc = mask ? 1 : dictNum(dict, 'BitsPerComponent') || 8;
    const cs = /\/DeviceRGB|\/CalRGB|\/ICCBased[^/]*\/N\s+3/.test(dict) ? 3 : /\/DeviceCMYK/.test(dict) ? 4 : 1;
    if (!w || !h || w < 21 || h < 21 || w * h > 16e6 || (bpc !== 8 && bpc !== 1) || (bpc === 1 && cs !== 1)) return null;
    const invert = /\/Decode\s*\[\s*1(\.0*)?\s+0/.test(dict) !== mask; // image masks paint where bits are 0
    const rgba = new Uint8ClampedArray(w * h * 4);
    const rowLen = Math.ceil(w * cs * bpc / 8);
    if (data.length < rowLen * h) return null;
    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        let v;
        if (bpc === 1) v = (data[y * rowLen + (x >> 3)] >> (7 - (x & 7))) & 1 ? 255 : 0;
        else if (cs === 1) v = data[y * rowLen + x];
        else if (cs === 3) { const i = y * rowLen + x * 3; v = (data[i] * 77 + data[i + 1] * 150 + data[i + 2] * 29) >> 8; }
        else { const i = y * rowLen + x * 4; v = 255 - Math.min(255, (data[i] * 77 + data[i + 1] * 150 + data[i + 2] * 29) / 256 + data[i + 3]); }
        if (invert) v = 255 - v;
        const o = (y * w + x) * 4;
        rgba[o] = rgba[o + 1] = rgba[o + 2] = v; rgba[o + 3] = 255;
      }
    }
    return { data: rgba, width: w, height: h };
  }

  const LURE_RE = /\b(view|open|access|download|read|review)\s+(the\s+|your\s+|this\s+)?(secure(d)?\s+)?(document|file|invoice|pdf|attachment|message|statement|fax|voicemail)|secure(d)?\s+(document|file|message|pdf)|shared\s+(a|an|the)?\s*(document|file|folder)\s+with\s+you|click\s+(here|below|the\s+(link|button))|enable\s+(editing|content|macros)|sign\s+in\s+to\s+(view|access|continue)|verify\s+your\s+(identity|account|email)|(has|have)\s+expired|pending\s+(payment|invoice|document)|docusign|onedrive|sharepoint|adobe\s+(sign|document\s+cloud|acrobat)|scan\s+(the|this)\s+(qr|code)/i;

  async function checkPdf(rep, b, ctx) {
    const raw = latin1(b);
    const budget = ctx.budget;
    let scan = raw;          // dictionaries / object streams for keyword search
    let pageText = '';       // text drawn on pages (for lure phrases)
    const embedded = [];
    let decoded = 0, failed = 0, textOps = 0;
    const encrypted = /\/Encrypt\b/.test(raw);
    const streamRe = /stream(\r\n|\n|\r)/g;
    let m, streams = 0;
    while ((m = streamRe.exec(raw)) && streams < 5000) {
      // the dictionary right before "stream"
      let p = m.index - 1;
      while (p > 0 && /\s/.test(raw[p])) p--;
      if (raw[p] !== '>' || raw[p - 1] !== '>') continue;
      let depth = 0, q = p, start = -1;
      for (; q > 0 && p - q < 20000; q--) {
        if (raw[q] === '>' && raw[q - 1] === '>') { depth++; q--; } else if (raw[q] === '<' && raw[q - 1] === '<') { depth--; q--; if (depth === 0) { start = q; break; } }
      }
      if (start < 0) continue;
      streams++;
      const dict = raw.slice(start, p + 1);
      const dataStart = m.index + m[0].length;
      let end = raw.indexOf('endstream', dataStart);
      if (end < 0) end = raw.length;
      const len = dictNum(dict, 'Length');
      let dataEnd;
      if (len != null && dataStart + len <= end) dataEnd = dataStart + len;
      else { dataEnd = end; while (dataEnd > dataStart && (raw[dataEnd - 1] === '\n' || raw[dataEnd - 1] === '\r')) dataEnd--; }
      let data = b.subarray(dataStart, dataEnd);
      const filters = filtersOf(dict);
      const isImage = /\/Subtype\s*\/Image\b/.test(dict);
      if (filters.includes('DCTDecode') || filters.includes('DCT')) {
        if (isImage && rep.images.length < 20 && data.length > 200) rep.images.push({ mime: 'image/jpeg', bytes: data.slice() });
        continue;
      }
      let ok = true;
      for (const f of filters) {
        if (f === 'FlateDecode' || f === 'Fl') {
          const out = (await inflate(data, 'deflate', budget)) || (await inflate(data, 'deflate-raw', budget));
          if (!out) { ok = false; break; }
          data = unpredict(out, dict);
        } else if (f === 'ASCIIHexDecode' || f === 'AHx') data = asciiHex(data);
        else if (f === 'ASCII85Decode' || f === 'A85') data = ascii85(data);
        else { ok = false; break; } // LZW, JBIG2, CCITT, JPX...: not needed for the checks
      }
      if (!ok) { failed++; continue; }
      decoded++;
      if (isImage) {
        if (rep.images.length < 20) { const px = rawImage(data, dict); if (px) rep.images.push({ pixels: px }); }
        continue;
      }
      if (data.length > 4 * 1024 * 1024) continue;
      const text = latin1(data);
      if (/\/Type\s*\/EmbeddedFile\b/.test(dict)) { embedded.push({ dict, bytes: data }); continue; }
      if (/\/Type\s*\/ObjStm\b/.test(dict) || /\/(JavaScript|JS|URI|OpenAction|Launch|AA)\b/.test(text)) scan += '\n' + text;
      if (/\bBT\b[\s\S]*?\bET\b/.test(text)) textOps += (text.match(/[)>\]]\s*(Tj|TJ|'|")/g) || []).length;
      if (/\bBT\b[\s\S]*?\bET\b/.test(text) && pageText.length < 20000) {
        const parts = [];
        text.replace(/\((?:\\[\s\S]|[^\\)])*\)\s*(Tj|'|")|\[((?:\((?:\\[\s\S]|[^\\)])*\)|[^\]])*)\]\s*TJ/g, (all, op, arr) => {
          if (arr != null) arr.replace(/\((?:\\[\s\S]|[^\\)])*\)/g, s => { parts.push(pdfUnescape(s.slice(1, -1))); return s; });
          else parts.push(pdfUnescape(all.slice(1, all.lastIndexOf(')'))));
          return all;
        });
        pageText += parts.join('').replace(/[^\x20-\x7e -ÿ]+/g, ' ') + ' ';
      }
    }

    // Keywords may be disguised with #hex escapes in names ("/J#61vaScript").
    let obfuscated = false;
    scan = scan.replace(/\/[A-Za-z0-9]*#[0-9A-Fa-f]{2}[A-Za-z0-9#]*/g, nm => {
      const plain = nm.replace(/#([0-9A-Fa-f]{2})/g, (x, h) => String.fromCharCode(parseInt(h, 16)));
      if (/^\/(JavaScript|JS|OpenAction|AA|Launch|EmbeddedFiles?|URI|SubmitForm|RichMedia|AcroForm|XFA)$/.test(plain)) obfuscated = true;
      return plain;
    });
    const count = re => (scan.match(re) || []).length;
    const js = count(/\/(JavaScript|JS)\b/g);
    const auto = /\/OpenAction\b/.test(scan) || /\/AA\b/.test(scan);
    const pages = (raw.match(/\/Type\s*\/Page\b(?!s)/g) || []).length;
    rep.notes.push(`${pages || 'Unknown number of'} page${pages === 1 ? '' : 's'}${decoded ? `, ${decoded} compressed sections checked` : ''}.`);

    if (obfuscated) add(rep, 'pdf_obfuscated', 'high', 'Hides its commands with escape codes', 'Keywords inside the PDF are written in a scrambled form so simple scanners miss them. Normal PDFs never do this.');
    if (js && auto) add(rep, 'pdf_autorun_js', 'high', 'Runs code as soon as it opens', 'The PDF contains JavaScript and an action that starts automatically when the file is opened.');
    else if (js) add(rep, 'pdf_js', 'high', 'Contains JavaScript code', 'PDFs you get by email almost never need code. Malicious PDFs use it to exploit the reader or redirect you.');
    if (/\/Launch\b/.test(scan)) {
      const targets = pdfStrings(scan, 'F').filter(t => /\.(exe|cmd|bat|ps1|vbs|js|hta|scr|lnk)\b|cmd|powershell/i.test(t)).slice(0, 3);
      add(rep, 'pdf_launch', 'high', 'Can start programs on your computer', 'The PDF has a "launch" action that asks your PDF reader to run something' + (targets.length ? `: ${targets.join(', ')}` : '') + '.');
    }
    if (/\/RichMedia\b/.test(scan)) add(rep, 'pdf_richmedia', 'medium', 'Contains embedded media (Flash)', 'Embedded media has been used to exploit PDF readers.');
    if (/\/SubmitForm\b/.test(scan)) {
      pdfStrings(scan, 'F').filter(t => /^https?:/i.test(t)).forEach(u => addUrl(rep, u, 'form'));
      add(rep, 'pdf_submitform', 'medium', 'Has a form that sends what you type to a website', 'Typing into this PDF can send your answers (for example a password) straight to a website.');
    }
    if (/\/XFA\b/.test(scan)) add(rep, 'pdf_xfa', 'low', 'Uses a dynamic (XFA) form', 'Dynamic forms can contain scripts. Most PDFs you receive by email do not need one.');
    if (/\/(GoToE|GoToR|ImportData)\b/.test(scan)) add(rep, 'pdf_remote', 'low', 'Opens other files', 'The PDF can open other files or embedded documents.');
    if (/\/JBIG2Decode\b/.test(scan)) rep.notes.push('Uses JBIG2 image compression (common in scanned documents; also used in past reader exploits).');
    if (encrypted) add(rep, 'pdf_encrypted', 'medium', 'Encrypted, so parts could not be checked', 'Some PDFs are encrypted just to restrict printing, but attackers also encrypt PDFs so scanners can\'t look inside.' + (failed ? ` ${failed} section(s) could not be read.` : ''));

    // Embedded files: what are they really?
    if (embedded.length || /\/EmbeddedFiles?\b/.test(scan)) {
      const names = pdfStrings(scan, 'UF').concat(pdfStrings(scan, 'F')).filter(n => /\.[a-z0-9]{1,8}$/i.test(n));
      add(rep, 'pdf_embedded', 'medium', 'Has files attached inside it', 'The PDF carries other files inside it' + (names.length ? `: ${Array.from(new Set(names)).slice(0, 5).join(', ')}` : '') + '. They are checked below.');
      for (let i = 0; i < embedded.length && i < 10; i++) {
        const nm = names[i] || `embedded-file-${i + 1}`;
        rep.inner.push(await inspectBytes(nm, embedded[i].bytes, ctx));
      }
    }

    // Links: clickable ones and web addresses written on the page.
    pdfStrings(scan, 'URI').forEach(u => addUrl(rep, u, 'link'));
    (pageText.match(/https?:\/\/[^\s<>"')]+/gi) || []).slice(0, 30).forEach(u => addUrl(rep, u, 'text'));
    const words = pageText.replace(/\s+/g, ' ').trim();
    // "Little text" is judged by how many text-drawing commands there are, since many PDFs
    // store their text in a coded form Off the Hook doesn't decode.
    const lure = LURE_RE.test(words);
    const bare = textOps < 8 && !failed && !encrypted;
    if (rep.urls.length && pages && pages <= 3 && (lure || bare)) {
      add(rep, 'pdf_lure', 'medium', lure ? 'Looks like a "click to view the document" lure' : 'Mostly a link or button, with little real content',
        'A short PDF whose main purpose is to send you to a website is a common phishing trick: the PDF looks harmless to email filters, and the link does the damage.' +
        (lure ? ` It says: "${(words.match(LURE_RE) || [''])[0]}".` : ''));
    }
    rep.pageText = words.slice(0, 2000);
  }

  // ---------- ZIP and everything built on it ----------
  function readZip(b) {
    let eocd = -1;
    for (let i = b.length - 22; i >= Math.max(0, b.length - 65557); i--) if (at(b, i, [0x50, 0x4b, 0x05, 0x06])) { eocd = i; break; }
    if (eocd < 0) return null;
    let total = u16(b, eocd + 10), cdOff = u32(b, eocd + 16);
    if (cdOff === 0xffffffff || total === 0xffff) {
      const loc = eocd - 20;
      if (loc >= 0 && at(b, loc, [0x50, 0x4b, 0x06, 0x07])) {
        const z = u64(b, loc + 8);
        if (at(b, z, [0x50, 0x4b, 0x06, 0x06])) { total = u64(b, z + 32); cdOff = u64(b, z + 48); }
      }
    }
    const entries = [];
    let o = cdOff;
    for (let n = 0; n < total && n < 20000 && at(b, o, [0x50, 0x4b, 0x01, 0x02]); n++) {
      const flags = u16(b, o + 8), method = u16(b, o + 10);
      let csize = u32(b, o + 20), usize = u32(b, o + 24);
      const nameLen = u16(b, o + 28), extraLen = u16(b, o + 30), commentLen = u16(b, o + 32);
      let local = u32(b, o + 42);
      const nameBytes = b.subarray(o + 46, o + 46 + nameLen);
      let name;
      try { name = flags & 0x800 ? new TextDecoder('utf-8').decode(nameBytes) : latin1(nameBytes); } catch (e) { name = latin1(nameBytes); }
      // ZIP64 sizes/offset in the extra field
      let e = o + 46 + nameLen;
      const eEnd = e + extraLen;
      while (e + 4 <= eEnd) {
        const id = u16(b, e), sz = u16(b, e + 2);
        if (id === 1) {
          let p = e + 4;
          if (usize === 0xffffffff) { usize = u64(b, p); p += 8; }
          if (csize === 0xffffffff) { csize = u64(b, p); p += 8; }
          if (local === 0xffffffff) { local = u64(b, p); }
        }
        e += 4 + sz;
      }
      entries.push({ name, flags, method, csize, usize, local, encrypted: !!(flags & 1) });
      o += 46 + nameLen + extraLen + commentLen;
    }
    return entries;
  }
  async function zipEntry(b, en, budget) {
    if (en.encrypted || !at(b, en.local, [0x50, 0x4b, 0x03, 0x04])) return null;
    const start = en.local + 30 + u16(b, en.local + 26) + u16(b, en.local + 28);
    const data = b.subarray(start, start + en.csize);
    if (en.method === 0) return data;
    if (en.method === 8) return inflate(data, 'deflate-raw', budget);
    return null;
  }
  const xmlText = s => s.replace(/<w:tab\/>|<\/w:p>|<\/a:p>|<\/text:p>/g, ' ').replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'");
  const ENABLE_LURE_RE = /enable\s+(editing|content|macros)|(this|the)\s+document\s+(is\s+)?(protected|encrypted|created\s+(in|with)\s+(an?\s+)?(earlier|newer|previous)\s+version)|click\s+(on\s+)?["“]?enable|to\s+view\s+(the\s+)?(content|document)|can(no|')t\s+be\s+(viewed|displayed)/i;

  async function checkZip(rep, b, ctx, ext) {
    const entries = readZip(b);
    if (!entries) { add(rep, 'zip_broken', 'medium', 'Damaged or unusual archive', 'Off the Hook could not read the list of files inside. Some malware is packed in deliberately broken archives so scanners give up.'); return; }
    const names = entries.map(e => e.name);
    const has = re => names.some(n => re.test(n));
    let kind = 'zip';
    if (has(/^\[Content_Types\]\.xml$/i)) kind = has(/^word\//i) ? 'docx' : has(/^xl\//i) ? 'xlsx' : has(/^ppt\//i) ? 'pptx' : 'ooxml';
    else if (has(/^mimetype$/) && has(/^content\.xml$/)) kind = 'odf';
    else if (has(/^AndroidManifest\.xml$/) && has(/\.dex$/i)) kind = 'apk';
    else if (has(/^META-INF\/MANIFEST\.MF$/i) && has(/\.class$/i)) kind = 'jar';
    rep.type = { id: kind, label: TYPES[kind] };

    if (kind === 'apk' || kind === 'jar') { add(rep, 'program', 'high', `This is a program (${TYPES[kind]})`, 'Opening it can run code. Programs should never arrive as email attachments.'); return; }

    if (kind === 'docx' || kind === 'xlsx' || kind === 'pptx' || kind === 'ooxml' || kind === 'odf') {
      rep.notes.push(`${entries.length} parts inside.`);
      if (has(/vbaProject\.bin$/i) || (kind === 'odf' && has(/^(Basic|Scripts)\//))) {
        add(rep, 'office_macros', 'high', 'Contains macros (code that runs inside Office)', 'Macros are the most common way Office files install malware. Never click "Enable content" on a file you weren\'t expecting.' + (/^(docx|xlsx|pptx)$/.test(ext) ? ` The name ends in .${ext}, which normally can't hold macros, so it is disguised.` : ''));
      }
      if (has(/^xl\/macrosheets\//i)) add(rep, 'office_xlm', 'high', 'Contains Excel 4.0 macro sheets', 'Old-style Excel macros that run when the workbook opens; a favourite of malware.');
      if (has(/activeX/i)) add(rep, 'office_activex', 'medium', 'Contains ActiveX controls', 'ActiveX controls can run code.');
      const embedded = names.filter(n => /\/embeddings\/|oleObject\d*\.bin$/i.test(n));
      if (embedded.length) add(rep, 'office_embedded', 'medium', 'Has other files embedded inside', `Embedded objects can hide programs behind an icon: ${embedded.slice(0, 5).map(n => n.split('/').pop()).join(', ')}.`);
      let docText = '';
      for (const en of entries) {
        if (/\.rels$/i.test(en.name) && en.usize < 2e6) {
          const data = await zipEntry(b, en, ctx.budget);
          if (!data) continue;
          const xml = latin1(data);
          for (const rel of xml.match(/<Relationship\b[^>]*>/g) || []) {
            if (!/TargetMode\s*=\s*"External"/i.test(rel)) continue;
            const target = ((rel.match(/Target\s*=\s*"([^"]*)"/) || [])[1] || '').replace(/&amp;/g, '&');
            const type = ((rel.match(/Type\s*=\s*"([^"]*)"/) || [])[1] || '').split('/').pop();
            if (/^(attachedTemplate|oleObject|frame|subDocument|externalLinkPath)$/i.test(type) || /^(\\\\|file:)/i.test(target)) {
              add(rep, 'office_remote', 'high', 'Downloads content from the internet when opened', `The document loads a ${type === 'attachedTemplate' ? 'template' : 'file'} from ${target.slice(0, 120)} as soon as it opens. Attackers use this to pull in malware or to steal your Windows sign-in.`);
              addUrl(rep, target, 'remote');
            } else if (/hyperlink/i.test(type)) addUrl(rep, target, 'link');
          }
        } else if (/^(word\/(document|header\d*|footer\d*)\.xml|ppt\/slides\/slide\d+\.xml|xl\/sharedStrings\.xml|content\.xml)$/i.test(en.name) && en.usize < 20e6) {
          const data = await zipEntry(b, en, ctx.budget);
          if (!data) continue;
          const xml = latin1(data);
          if (/<w:instrText[^>]*>[^<]*\bDDE(AUTO)?\b|w:instr\s*=\s*"[^"]*\bDDE(AUTO)?\b|\bDDEAUTO\b/i.test(xml)) add(rep, 'office_dde', 'high', 'Contains a DDE command', 'DDE fields can run programs when the document is opened, without macros.');
          if (docText.length < 20000) docText += xmlText(xml).slice(0, 20000) + ' ';
        }
      }
      const words = docText.replace(/\s+/g, ' ').trim();
      if (ENABLE_LURE_RE.test(words)) add(rep, 'office_lure', rep.findings.some(f => f.id === 'office_macros') ? 'high' : 'medium', 'Tells you to "enable editing" or "enable content"', `It says: "${(words.match(ENABLE_LURE_RE) || [''])[0]}". This is how malicious documents get you to switch off Office's protection.`);
      (words.match(/https?:\/\/[^\s<>"')]+/gi) || []).slice(0, 30).forEach(u => addUrl(rep, u, 'text'));
      rep.pageText = words.slice(0, 2000);
      return;
    }

    // A plain archive: what's inside?
    rep.notes.push(`${entries.length} file${entries.length === 1 ? '' : 's'} inside.`);
    const enc = entries.filter(e => e.encrypted);
    if (enc.length) add(rep, 'archive_encrypted', 'high', 'Password-protected archive', 'Virus scanners can\'t look inside password-protected archives, which is exactly why attackers send them (often with the password in the email). Only open it if you were expecting it.');
    const ratio = entries.reduce((s, e) => s + e.usize, 0) / Math.max(1, b.length);
    if (entries.length > 5000 || ratio > 1000) add(rep, 'archive_bomb', 'medium', 'Unusually packed archive', 'It expands to a huge size or file count, a trick used to crash or overwhelm scanners.');
    for (const en of entries) {
      if (/\/$/.test(en.name)) continue;
      const base = en.name.split('/').pop();
      const e2 = extOf(base);
      const parts = base.toLowerCase().split('.');
      const prev = parts.length > 2 ? parts[parts.length - 2] : '';
      if ((prev && DECOY_EXT.has(prev) && (RISKY_EXT.has(e2) || SCRIPT_EXT.has(e2))) || /[‮‭]/.test(base)) add(rep, 'archive_disguised', 'high', `Contains a disguised file: ${base}`, 'A file inside pretends to be one type but is really another.');
      else if (RISKY_EXT.has(e2) || SCRIPT_EXT.has(e2)) add(rep, 'archive_risky', 'high', `Contains a risky file: ${base}`, 'Programs, scripts, shortcuts and disk images inside an archive are a classic way to deliver malware.');
      else if (ARCHIVE_EXT.has(e2)) add(rep, 'archive_nested', 'medium', `Contains another archive: ${base}`, 'Archives inside archives are used to get past scanners.');
    }
    // Look inside the files themselves (one level, size-limited).
    if (ctx.depth < MAX_DEPTH) {
      let n = 0;
      for (const en of entries) {
        if (n >= 40 || en.encrypted || /\/$/.test(en.name) || en.usize > 25e6) continue;
        const data = await zipEntry(b, en, ctx.budget);
        if (!data) continue;
        n++;
        rep.inner.push(await inspectBytes(en.name, data, Object.assign({}, ctx, { depth: ctx.depth + 1 })));
      }
    }
  }

  // ---------- older Office (OLE) ----------
  function checkOle(rep, b, ext) {
    // Stream/storage names in the file's directory are UTF-16 and end in a null character,
    // which ordinary document text (also UTF-16) doesn't.
    const has = s => indexOfBytes(b, utf16(s).concat([0, 0])) >= 0;
    if (has('EncryptedPackage') || has('EncryptionInfo')) {
      add(rep, 'office_encrypted', 'high', 'Password-protected Office file', 'Its contents are encrypted, so neither Off the Hook nor a virus scanner can check them. Attackers send password-protected documents (with the password in the email) for exactly that reason.');
      return;
    }
    if (indexOfBytes(b, utf16('__substg1.0_')) >= 0) { rep.type = { id: 'ole', label: 'Outlook message (.msg)' }; rep.notes.push('An email saved as a file. Open it only if you expected it.'); }
    if (rep.type.id === 'msi') add(rep, 'program', 'high', 'This is a Windows installer', 'Installers run programs on your computer. They should never arrive by email.');
    if (has('_VBA_PROJECT') || has('VBA') || has('Macros')) add(rep, 'office_macros', 'high', 'Contains macros (code that runs inside Office)', 'Macros are the most common way Office files install malware. Never click "Enable content" on a file you weren\'t expecting.');
    if (has('\x01Ole10Native')) add(rep, 'office_package', 'high', 'Contains a packaged file', 'A "package" object can hide a program or script behind an icon in the document.');
    if (has('Equation Native')) add(rep, 'office_equation', 'high', 'Contains an Equation Editor object', 'The old Equation Editor has a well-known security hole that attackers still use.');
    const text = latin1(b, 0, Math.min(b.length, 20e6));
    if (/\bDDEAUTO\b/.test(text)) add(rep, 'office_dde', 'high', 'Contains a DDE command', 'DDE fields can run programs when the document is opened, without macros.');
    // BOUNDSHEET record (0x0085) whose sheet-type byte is 1 = an Excel 4.0 macro sheet.
    if (ext === 'xls' && /\x85\x00[\x08-\xff]\x00[\s\S]{4}[\x00-\x02]\x01/.test(text.slice(0, 1e6))) add(rep, 'office_xlm', 'medium', 'Appears to contain Excel 4.0 macro sheets', 'Old-style Excel macros run when the workbook opens and are a favourite of malware.');
  }

  // ---------- RTF ----------
  function checkRtf(rep, b) {
    const t = latin1(b, 0, Math.min(b.length, 20e6));
    if (/\\obj(data|update|emb|link|autlink)\b|\\object\b/.test(t)) {
      const why = /\\objupdate\b/.test(t) ? ' It is set to update (run) automatically.' : '';
      const eq = /Equation\.3|4571756174696f6e2e33/i.test(t) ? ' It includes an Equation Editor object, tied to a well-known Office security hole.' : '';
      const pkg = /\\objclass\s+Package|5061636b616765/i.test(t) ? ' It includes a packaged file that can hide a program.' : '';
      add(rep, 'rtf_object', 'high', 'Has an embedded object', 'Embedded objects in RTF documents are a top way attackers exploit Word.' + why + eq + pkg);
    }
    (t.match(/HYPERLINK\s+"([^"]+)"/g) || []).slice(0, 30).forEach(h => addUrl(rep, h.replace(/^HYPERLINK\s+"|"$/g, ''), 'link'));
  }

  // ---------- web pages / SVG ----------
  function checkHtml(rep, b, kind) {
    const t = latin1(b, 0, Math.min(b.length, 10e6));
    const lower = t.toLowerCase();
    if (kind === 'svg') {
      if (/<script\b|\bon(load|click|mouseover|error)\s*=|<foreignobject\b|javascript:/i.test(t)) add(rep, 'svg_script', 'high', 'Picture that contains code', 'SVG pictures can carry scripts and web pages. Attackers send them as "images" that open fake sign-in pages.');
    } else {
      add(rep, 'html_attachment', 'medium', 'Web page attachment', 'Web pages open in your browser and are a common way to show fake sign-in pages, since they don\'t need a website. Real companies rarely send them.');
    }
    if (/<input[^>]+type\s*=\s*["']?password/i.test(t)) add(rep, 'html_password', 'high', 'Asks for a password', 'The page contains a password box. A sign-in form inside an attachment is almost always phishing.');
    const actions = (t.match(/<form[^>]+action\s*=\s*["']?([^"'\s>]+)/gi) || []).map(f => f.replace(/^.*action\s*=\s*["']?/i, ''));
    if (actions.some(a => /^https?:/i.test(a))) add(rep, 'html_form_external', 'high', 'Sends what you type to a website', `A form in the page sends its contents to ${actions.find(a => /^https?:/i.test(a)).slice(0, 100)}.`);
    actions.forEach(a => addUrl(rep, a, 'form'));
    if (/\batob\s*\(|\bunescape\s*\(|fromcharcode|\beval\s*\(|document\.write\s*\(\s*(unescape|atob|decodeuri)/i.test(t)) add(rep, 'html_obfuscated', 'high', 'Contains scrambled code', 'The page decodes hidden code when it opens, which phishing pages do to slip past scanners.');
    if (/(window\.|document\.|top\.)?location(\.href)?\s*=|location\.(replace|assign)\s*\(|http-equiv\s*=\s*["']?refresh/i.test(t)) add(rep, 'html_redirect', 'high', 'Redirects you to a website', 'Opening it sends your browser somewhere else automatically.');
    if (/new\s+blob\s*\(/i.test(t) && /createobjecturl|mssaveoropenblob|\.download\s*=/i.test(t)) add(rep, 'html_smuggling', 'high', 'Builds and downloads a hidden file', 'The page assembles a file inside your browser and saves it ("HTML smuggling"), a way to sneak malware past email filters.');
    if (/<iframe[^>]+src\s*=\s*["']?https?:/i.test(t)) add(rep, 'html_iframe', 'medium', 'Shows another website inside it', 'The page loads an outside website inside a frame.');
    const urls = (t.match(/(?:href|src|action)\s*=\s*["']?(https?:\/\/[^"'\s>]+)/gi) || []).map(u => u.replace(/^[^h]*?(https?:)/i, '$1'));
    urls.slice(0, 60).forEach(u => addUrl(rep, u, 'link'));
    (t.match(/location(?:\.href)?\s*=\s*["'](https?:\/\/[^"']+)/gi) || []).forEach(u => addUrl(rep, u.replace(/^.*?["'](https?:)/i, '$1'), 'redirect'));
    const text = xmlText(lower.replace(/<(script|style)[\s\S]*?<\/\1>/g, ' ')).replace(/\s+/g, ' ');
    rep.pageText = text.slice(0, 2000);
  }

  function checkOneNote(rep, b) {
    add(rep, 'onenote', 'medium', 'OneNote file', 'OneNote files have been used to hide malware behind fake "double-click to view" buttons.');
    const guid = [0xe7, 0x16, 0xe3, 0xbd, 0x65, 0x26, 0x11, 0x45, 0xa4, 0xc4, 0x8d, 0x4d, 0x0b, 0x7a, 0x9e, 0xac];
    if (indexOfBytes(b, guid) >= 0) {
      const t = latin1(b);
      const hit = /\.(exe|js|vbs|hta|bat|cmd|ps1|wsf|lnk|chm|scr)\b/i.exec(t);
      add(rep, 'onenote_embedded', hit ? 'high' : 'medium', 'Has files embedded inside', hit ? `It carries a ${hit[1].toLowerCase()} file, which can run code if you double-click it.` : 'Files embedded in OneNote pages can run when double-clicked.');
    }
  }

  // ---------- main ----------
  async function inspectBytes(name, b, ctx) {
    const rep = newReport(String(name || 'file'), b.length);
    const ext = checkName(rep, rep.name);
    if (b.length > MAX_FILE) {
      rep.notes.push('Too large to check inside; only the name and type were checked.');
    }
    const t = sniff(b, rep.name);
    rep.type = { id: t, label: TYPES[t] || TYPES.unknown };

    // Real type vs. name.
    const expected = EXPECT[ext];
    const disguised = expected && !expected.includes(t) && !(t === 'zip' && expected.some(x => /docx|xlsx|pptx|ooxml|odf|jar|apk/.test(x))) && t !== 'unknown';
    const kind = TYPES[t].replace(/^(Plain|Web|Disk|Virtual|Older|Rich|Unknown|Script)\b/, w => w.toLowerCase());
    if (disguised && (PROGRAM_TYPES.has(t) || t === 'script')) add(rep, 'disguised_program', 'high', `This "${ext.toUpperCase()}" is really a ${kind}`, `The file's contents show it is a ${kind}, not a .${ext} file. Opening it could run code. Delete it.`);
    else if (disguised && (t === 'html' || t === 'svg')) add(rep, 'disguised_html', 'high', `This "${ext.toUpperCase()}" is really a web page`, 'It is a web page dressed up as another file type, a common way to open a fake sign-in page.');
    else if (disguised && t === 'rtf' && ext !== 'rtf') add(rep, 'disguised_rtf', 'medium', `This "${ext.toUpperCase()}" is really an RTF document`, 'Word files secretly saved as RTF are often used to exploit Word.');
    else if (disguised) rep.notes.push(`Named .${ext} but the contents are a ${kind}.`);

    if (PROGRAM_TYPES.has(t) && t !== 'msi' && !rep.findings.some(f => f.id === 'disguised_program')) {
      add(rep, 'program', 'high', t === 'lnk' ? 'This is a Windows shortcut' : t === 'iso' || t === 'vhd' ? 'This is a disk image' : `This is a program (${TYPES[t]})`,
        t === 'lnk' ? 'Shortcut files can run any command when opened. They are a common malware trick.'
          : t === 'iso' || t === 'vhd' ? 'Disk images open like a folder and are used to smuggle programs past Windows security warnings.'
            : 'Opening it runs code on your computer. Programs should never arrive as email attachments.');
    } else if (t === 'script' || (SCRIPT_EXT.has(ext) && (t === 'text' || t === 'unknown'))) {
      add(rep, 'script', 'high', `This is a script (.${ext})`, 'Script files run commands on your computer when opened. They should never arrive by email.');
    } else if (RISKY_EXT.has(ext) && !rep.findings.length && !/^(html?|svg|docm|xlsm|pptm|dotm|xltm|ppsm|one)$/.test(ext)) {
      add(rep, 'risky_ext', 'high', `Risky file type (.${ext})`, 'This kind of file can run code or install software when opened.');
    }
    if (b.length <= MAX_FILE) {
      if (t === 'pdf') await checkPdf(rep, b, ctx);
      else if (t === 'zip') await checkZip(rep, b, ctx, ext);
      else if (t === 'ole' || t === 'msi') checkOle(rep, b, ext);
      else if (t === 'rtf') checkRtf(rep, b);
      else if (t === 'html' || t === 'svg') checkHtml(rep, b, t);
      else if (t === 'onenote') checkOneNote(rep, b);
      else if (t === '7z' || t === 'rar' || t === 'gzip' || t === 'cab') add(rep, 'archive_unreadable', 'medium', `${TYPES[t]}: contents can't be checked`, 'Off the Hook can only look inside ZIP archives. Attackers use other archive types to get past scanners; only open it if you expected it.');
      else if (/^(png|jpeg|gif|webp|bmp)$/.test(t)) rep.images.push({ mime: 'image/' + t, bytes: b });
    }
    if (ctx.budget.bomb) add(rep, 'archive_bomb', 'medium', 'Expands to an enormous size', 'Part of the file decompresses to far more data than it holds, a trick used to overwhelm scanners. Off the Hook stopped reading it.');
    return rep;
  }

  const RANK = { high: 3, medium: 2, low: 1 };
  // Files inside archives / PDFs count toward the outer verdict.
  function finish(rep) {
    if (!rep.merged) rep.merged = true; else return grade(rep);
    for (const inner of rep.inner) {
      finish(inner);
      for (const f of inner.findings) {
        if (f.severity === 'low') continue;
        add(rep, 'inner_' + f.id, f.severity, `Inside, ${inner.name.split('/').pop()}: ${f.title.charAt(0).toLowerCase() + f.title.slice(1)}`, f.detail);
      }
      for (const u of inner.urls) addUrl(rep, u.href, u.source);
      rep.images.push(...inner.images.slice(0, Math.max(0, 20 - rep.images.length)));
    }
    return grade(rep);
  }
  function grade(rep) {
    rep.findings.sort((a, b) => RANK[b.severity] - RANK[a.severity]);
    const top = rep.findings.length ? rep.findings[0].severity : null;
    rep.verdict = top === 'high' ? 'danger' : top === 'medium' ? 'caution' : 'ok';
    return rep;
  }

  /**
   * Run the link checks on addresses found in the file (and QR codes read from its pictures).
   * Adds findings for risky links and recomputes the verdict.
   */
  function applyLinks(rep, extraUrls, deps) {
    for (const u of extraUrls || []) addUrl(rep, u.href, u.source);
    rep.links = [];
    const A = deps && deps.analyzer;
    if (!A || !rep.urls.length) return finish(rep);
    const urls = rep.urls.slice(0, 100);
    const res = A.analyze({ from: { name: '', address: '' }, subject: '', body: '', links: urls.map(u => ({ text: '', href: u.href, qr: u.source === 'qr' })) },
      Object.assign({ sensitivity: 'medium' }, deps.settings || {}), deps.lists || {});
    rep.links = res.links.map(l => Object.assign(l, { source: urls[l.index] && urls[l.index].source }));
    for (const l of rep.links) {
      const where = l.source === 'qr' ? 'QR code' : l.source === 'remote' ? 'Remote content' : l.source === 'form' ? 'Form' : 'Link';
      if (l.risk === 'danger') add(rep, 'link_danger', 'high', `${where} goes to a dangerous site: ${l.domain}`, l.flags.join(', '));
      else if (l.risk === 'caution' && l.source !== 'qr') add(rep, 'link_caution', 'medium', `${where} to check: ${l.domain}`, l.flags.join(', '));
      else if (l.source === 'qr') add(rep, 'qr_link', l.risk === 'ok' ? 'low' : 'medium', `QR code inside opens a website: ${l.domain}`, 'Scanning QR codes from files you weren\'t expecting skips your work computer\'s protections.');
    }
    finish(rep);
    rep.linkOnly = rep.findings.every(f => LINK_FINDINGS.has(f.id) || f.severity === 'low');
    return rep;
  }
  const LINK_FINDINGS = new Set(['link_danger', 'link_caution', 'qr_link', 'pdf_lure']);
  // (Links on the scam-site lists come back from the analyzer with risk 'danger', so they show as link_danger.)

  async function inspect(file, deps) {
    const bytes = file.bytes instanceof Uint8Array ? file.bytes : new Uint8Array(file.bytes);
    const ctx = { depth: 0, budget: { left: MAX_TOTAL_INFLATE, bomb: false } };
    const rep = await inspectBytes(file.name, bytes, ctx);
    return applyLinks(rep, [], deps);
  }

  return { inspect, applyLinks, sniff, TYPES, _internal: { readZip, pdfStrings, ascii85, unpredict, rawImage, checkName } };
});
