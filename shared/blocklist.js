/*
 * Known-bad site lists, checked on this computer.
 *
 * Public lists of active phishing and malware sites are downloaded once a day by the
 * background worker (shared/config.js BLOCKLIST_SOURCES). Only the lists are downloaded:
 * nothing about your email is sent anywhere. ~550,000 sites are kept as a sorted array of
 * 64-bit fingerprints (about 5 MB), so a lookup is a binary search.
 *
 *   parse(text, format, skip?)     -> [host]          format: 'domains' | 'hosts' | 'urls'
 *   neverMatcher(patterns)         -> host => true for big shared sites a list must never add
 *   build([{ name, hosts }])       -> set
 *   create(set)                    -> { size, has(host) -> list name | null }
 *   serialize(set) / deserialize(buffer)
 */
(function (root, factory) {
  const mod = factory();
  if (typeof module === 'object' && module.exports) module.exports = mod;
  else { root.PhishGuard = root.PhishGuard || {}; root.PhishGuard.blocklist = mod; }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Two independent 32-bit hashes = one 64-bit fingerprint (collisions are practically impossible).
  function hashA(s) {
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
    return h >>> 0;
  }
  function hashB(s) {
    let h = 0x9e3779b9;
    for (let i = 0; i < s.length; i++) { h = Math.imul(h ^ s.charCodeAt(i), 0x5bd1e995); h ^= h >>> 15; }
    return h >>> 0;
  }

  const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$|^\d{1,3}(?:\.\d{1,3}){3}$/;
  const norm = h => String(h || '').trim().toLowerCase().replace(/\.$/, '').replace(/^\*\./, '');

  /** One host per line ('domains'), or a hosts file "0.0.0.0 host" ('hosts'). Comments (#) skipped. */
  function parse(text, format, skip) {
    const out = [];
    const lines = String(text || '').split(/\r?\n/);
    for (const line of lines) {
      const t = line.trim();
      if (!t || t[0] === '#' || t[0] === '!') continue;
      const parts = t.split(/\s+/);
      let host = parts[0];
      if (format === 'hosts' && parts.length > 1 && /^(0\.0\.0\.0|127\.0\.0\.1|::1?)$/.test(parts[0])) host = parts[1];
      if (format === 'urls') {
        const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^/?#@\s]*@)?([^/?#:\s]+)/i.exec(host);
        if (!m) continue;
        host = m[1];
      }
      host = norm(host);
      if (host && host.length <= 253 && HOST_RE.test(host) && host !== 'localhost' && !(skip && skip(host))) out.push(host);
    }
    return out;
  }

  /**
   * Hosts a list must never add (big shared sites; see shared/config.js BLOCKLIST_NEVER).
   * "site.com" matches site.com and www.site.com; "*.site.com" any subdomain; "s3*.x.com" any
   * host starting "s3" on x.com.
   */
  function neverMatcher(patterns) {
    const exact = new Set(), res = [];
    for (const p of patterns || []) {
      const s = String(p || '').trim().toLowerCase(); // not norm(): that drops a leading "*."
      if (!s) continue;
      if (s.includes('*')) res.push(new RegExp('^' + s.split('*').map(x => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[a-z0-9.-]+') + '$'));
      else exact.add(s);
    }
    return host => {
      const h = norm(host).replace(/^www\./, '');
      return exact.has(h) || res.some(r => r.test(h));
    };
  }

  function build(sources) {
    const n = sources.reduce((s, x) => s + x.hosts.length, 0);
    const order = new Uint32Array(n);
    const A = new Uint32Array(n), B = new Uint32Array(n), S = new Uint8Array(n);
    let i = 0;
    sources.forEach((src, si) => {
      for (const h of src.hosts) { A[i] = hashA(h); B[i] = hashB(h); S[i] = si; order[i] = i; i++; }
    });
    const idx = Array.from(order).sort((p, q) => A[p] - A[q] || B[p] - B[q] || S[p] - S[q]);
    const keys = new Uint32Array(n * 2), src = new Uint8Array(n);
    let m = 0;
    for (const k of idx) {
      if (m && keys[2 * (m - 1)] === A[k] && keys[2 * (m - 1) + 1] === B[k]) continue; // same host twice: keep the first list
      keys[2 * m] = A[k]; keys[2 * m + 1] = B[k]; src[m] = S[k]; m++;
    }
    return { n: m, keys: keys.slice(0, 2 * m), src: src.slice(0, m), names: sources.map(s => s.name) };
  }

  function find(set, host) {
    const a = hashA(host), b = hashB(host);
    let lo = 0, hi = set.n - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const ka = set.keys[2 * mid], kb = set.keys[2 * mid + 1];
      if (ka < a || (ka === a && kb < b)) lo = mid + 1;
      else if (ka > a || kb > b) hi = mid - 1;
      else return set.src[mid];
    }
    return -1;
  }

  function create(set) {
    return {
      size: set.n,
      names: set.names,
      /** The list that names this exact host (also tried without "www."), or null. */
      has(host) {
        const h = norm(host);
        if (!h) return null;
        let i = find(set, h);
        if (i < 0 && h.startsWith('www.')) i = find(set, h.slice(4));
        return i < 0 ? null : set.names[i] || 'blocklist';
      }
    };
  }

  // Binary layout: [n][names byte length][names JSON, padded to 4][keys][src]
  function serialize(set) {
    const names = new TextEncoder().encode(JSON.stringify(set.names));
    const pad = (4 - (names.length % 4)) % 4;
    const buf = new ArrayBuffer(8 + names.length + pad + set.keys.byteLength + set.src.byteLength);
    const dv = new DataView(buf);
    dv.setUint32(0, set.n, true);
    dv.setUint32(4, names.length, true);
    new Uint8Array(buf, 8, names.length).set(names);
    const ko = 8 + names.length + pad;
    new Uint32Array(buf, ko, set.keys.length).set(set.keys);
    new Uint8Array(buf, ko + set.keys.byteLength, set.src.length).set(set.src);
    return buf;
  }
  function deserialize(buf) {
    const dv = new DataView(buf);
    const n = dv.getUint32(0, true), nl = dv.getUint32(4, true);
    const names = JSON.parse(new TextDecoder().decode(new Uint8Array(buf, 8, nl)));
    const ko = 8 + nl + ((4 - (nl % 4)) % 4);
    return { n, names, keys: new Uint32Array(buf.slice(ko, ko + n * 8)), src: new Uint8Array(buf.slice(ko + n * 8, ko + n * 9)) };
  }

  return { parse, neverMatcher, build, create, serialize, deserialize };
});
