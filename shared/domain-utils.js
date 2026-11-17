/*
 * Domain and URL helpers: registrable-domain approximation, punycode decoding,
 * homoglyph "skeletons", edit distance, redirect unwrapping and brand lookalike checks.
 * Pure functions, no DOM or network access.
 */
(function (root, factory) {
  const mod = factory();
  if (typeof module === 'object' && module.exports) module.exports = mod;
  else (root.PhishGuard = root.PhishGuard || {}).domain = mod;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Small stand-in for the Public Suffix List: common two-part suffixes.
  const MULTI_PART_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'ltd.uk', 'plc.uk', 'me.uk', 'net.uk', 'nhs.uk', 'police.uk',
    'com.au', 'net.au', 'org.au', 'gov.au', 'edu.au', 'co.nz', 'org.nz', 'govt.nz', 'net.nz',
    'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp', 'com.br', 'net.br', 'gov.br', 'org.br',
    'com.mx', 'gob.mx', 'org.mx', 'com.ar', 'gob.ar', 'com.cn', 'net.cn', 'org.cn', 'gov.cn',
    'com.hk', 'com.sg', 'gov.sg', 'com.tw', 'co.in', 'gov.in', 'net.in', 'org.in', 'co.za',
    'gov.za', 'org.za', 'co.kr', 'or.kr', 'com.tr', 'gov.tr', 'com.my', 'com.ph', 'com.vn',
    'co.id', 'go.id', 'co.il', 'org.il', 'com.sa', 'com.eg', 'com.pk', 'com.ng', 'co.ke',
    'com.ua', 'com.pl', 'co.th', 'in.th', 'gc.ca', 'qc.ca', 'on.ca', 'bc.ca', 'ab.ca',
    'com.co', 'com.pe', 'com.ec', 'com.uy', 'com.ve', 'co.ve', 'com.es', 'gob.es', 'com.pt',
    'com.gr', 'com.cy', 'com.mt', 'co.at', 'or.at', 'com.ru', 'com.qa', 'com.kw', 'ac.nz'
  ]);

  // Characters that look like Latin letters (Cyrillic, Greek, IPA, etc.).
  const CONFUSABLES = {
    'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'і': 'i', 'ї': 'i', 'ј': 'j', 'ӏ': 'l', 'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ѕ': 's',
    'к': 'k', 'м': 'm', 'н': 'h', 'т': 't', 'ь': 'b', 'ѡ': 'w', 'ү': 'y', 'ɡ': 'g', 'ɑ': 'a',
    'ο': 'o', 'α': 'a', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'ι': 'i', 'κ': 'k', 'υ': 'u', 'ϲ': 'c',
    'ε': 'e', 'η': 'n', 'χ': 'x', 'β': 'b', 'ʏ': 'y', 'ɩ': 'i', 'ɪ': 'i', 'ɴ': 'n', 'ʀ': 'r',
    'ꜱ': 's', 'ᴅ': 'd', 'ᴇ': 'e', 'ᴏ': 'o', 'ᴘ': 'p', 'ᴛ': 't', 'ᴜ': 'u', 'ı': 'i', 'ł': 'l',
    'ø': 'o', 'đ': 'd', 'ħ': 'h', 'ŀ': 'l'
  };
  const LEET = { '0': 'o', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g', '$': 's', '@': 'a' };

  function lower(s) { return String(s || '').trim().toLowerCase().replace(/\.$/, ''); }

  function isIP(host) {
    host = lower(host);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;
    if (host.startsWith('[') || (host.includes(':') && /^[0-9a-f:.]+$/.test(host))) return true;
    return false;
  }

  function registrableDomain(host) {
    host = lower(host);
    if (!host || isIP(host)) return host;
    const parts = host.split('.').filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    const lastTwo = parts.slice(-2).join('.');
    if (MULTI_PART_SUFFIXES.has(lastTwo)) return parts.slice(-3).join('.');
    return lastTwo;
  }

  // Public suffix part of a registrable domain ("com", "co.uk").
  function suffixOf(reg) {
    const parts = lower(reg).split('.');
    if (parts.length >= 3 && MULTI_PART_SUFFIXES.has(parts.slice(-2).join('.'))) return parts.slice(-2).join('.');
    return parts[parts.length - 1] || '';
  }

  // The "name" portion of a registrable domain ("paypa1-security" from paypa1-security.com).
  function labelOf(reg) {
    reg = lower(reg);
    const suffix = suffixOf(reg);
    return reg.slice(0, Math.max(0, reg.length - suffix.length - 1));
  }

  function tldOf(host) {
    const parts = lower(host).split('.');
    return parts[parts.length - 1] || '';
  }

  function isCountrySuffix(suffix) {
    return suffix.length === 2 || MULTI_PART_SUFFIXES.has(suffix);
  }

  function domainOfEmail(addr) {
    const m = String(addr || '').trim().match(/@([^@\s>]+)$/);
    return m ? lower(m[1]) : '';
  }

  function hostMatches(host, domain) {
    host = lower(host); domain = lower(domain);
    return host === domain || host.endsWith('.' + domain);
  }

  function inList(host, list) {
    host = lower(host);
    for (const d of list) if (hostMatches(host, d)) return true;
    return false;
  }

  // ---- Punycode (RFC 3492) decoding ----
  const P_BASE = 36, P_TMIN = 1, P_TMAX = 26, P_SKEW = 38, P_DAMP = 700;
  function pAdapt(delta, numPoints, firstTime) {
    let k = 0;
    delta = firstTime ? Math.floor(delta / P_DAMP) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    for (; delta > ((P_BASE - P_TMIN) * P_TMAX) >> 1; k += P_BASE) delta = Math.floor(delta / (P_BASE - P_TMIN));
    return Math.floor(k + ((P_BASE - P_TMIN + 1) * delta) / (delta + P_SKEW));
  }
  function pDigit(cp) {
    if (cp >= 0x30 && cp < 0x3a) return 26 + (cp - 0x30);
    if (cp >= 0x41 && cp < 0x5b) return cp - 0x41;
    if (cp >= 0x61 && cp < 0x7b) return cp - 0x61;
    return P_BASE;
  }
  function punycodeDecode(input) {
    const output = [];
    let i = 0, n = 128, bias = 72;
    let basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; ++j) {
      if (input.charCodeAt(j) >= 0x80) throw new Error('invalid punycode');
      output.push(input.charCodeAt(j));
    }
    for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
      const oldi = i;
      for (let w = 1, k = P_BASE; ; k += P_BASE) {
        if (index >= input.length) throw new Error('invalid punycode');
        const digit = pDigit(input.charCodeAt(index++));
        if (digit >= P_BASE) throw new Error('invalid punycode');
        i += digit * w;
        const t = k <= bias ? P_TMIN : k >= bias + P_TMAX ? P_TMAX : k - bias;
        if (digit < t) break;
        w *= P_BASE - t;
      }
      const out = output.length + 1;
      bias = pAdapt(i - oldi, out, oldi === 0);
      n += Math.floor(i / out);
      i %= out;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  }

  function toUnicodeHost(host) {
    return lower(host).split('.').map(label => {
      if (!label.startsWith('xn--')) return label;
      try { return punycodeDecode(label.slice(4)); } catch (e) { return label; }
    }).join('.');
  }

  // Map look-alike characters to plain Latin. Returns variants because "1" may stand
  // in for either "l" or "i".
  function skeletons(str) {
    let s = String(str || '').toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '');
    s = Array.from(s).map(ch => CONFUSABLES[ch] || LEET[ch] || ch).join('');
    s = s.replace(/rn/g, 'm').replace(/vv/g, 'w');
    const a = s.replace(/[1|!]/g, 'l');
    const b = s.replace(/[1|!]/g, 'i');
    return a === b ? [a] : [a, b];
  }

  // Edit distance counting an adjacent swap (paypla vs paypal) as one edit.
  // Returns Infinity as soon as the distance must exceed `max`.
  let rowA = new Uint16Array(64), rowB = new Uint16Array(64), rowC = new Uint16Array(64);
  function levenshtein(a, b, max) {
    if (a === b) return 0;
    if (max == null) max = Infinity;
    const n = a.length, m = b.length;
    if (Math.abs(n - m) > max) return Infinity;
    if (m + 1 > rowA.length) { rowA = new Uint16Array(m + 1); rowB = new Uint16Array(m + 1); rowC = new Uint16Array(m + 1); }
    let prev2 = rowA, prev = rowB, cur = rowC;
    for (let j = 0; j <= m; j++) prev[j] = j;
    for (let i = 1; i <= n; i++) {
      cur[0] = i;
      let rowMin = i;
      const ai = a.charCodeAt(i - 1);
      for (let j = 1; j <= m; j++) {
        const bj = b.charCodeAt(j - 1);
        let v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ai === bj ? 0 : 1));
        if (i > 1 && j > 1 && ai === b.charCodeAt(j - 2) && a.charCodeAt(i - 2) === bj) v = Math.min(v, prev2[j - 2] + 1);
        cur[j] = v;
        if (v < rowMin) rowMin = v;
      }
      if (rowMin > max) return Infinity;
      const t = prev2; prev2 = prev; prev = cur; cur = t;
    }
    return prev[m] > max ? Infinity : prev[m];
  }

  function parseUrl(href) {
    try { return new URL(String(href).trim()); } catch (e) { return null; }
  }

  // Follow known security/redirect wrappers to the real destination.
  function unwrapRedirect(url) {
    let current = url, wrapper = null;
    for (let depth = 0; depth < 3 && current; depth++) {
      const host = lower(current.hostname);
      let next = null;
      if (hostMatches(host, 'safelinks.protection.outlook.com')) {
        next = current.searchParams.get('url');
      } else if ((host === 'www.google.com' || host === 'google.com') && current.pathname === '/url') {
        next = current.searchParams.get('q') || current.searchParams.get('url');
      } else if (hostMatches(host, 'urldefense.com') || hostMatches(host, 'urldefense.proofpoint.com')) {
        const m = current.href.match(/\/v3\/__(.+?)__;/);
        if (m) next = m[1];
        else if (current.searchParams.get('u')) {
          next = current.searchParams.get('u').replace(/-/g, '%').replace(/_/g, '/');
          try { next = decodeURIComponent(next); } catch (e) { next = null; }
        }
      } else if (host === 'l.facebook.com' || host === 'lm.facebook.com') {
        next = current.searchParams.get('u');
      }
      if (!next) break;
      const parsed = parseUrl(next);
      if (!parsed) break;
      wrapper = wrapper || host;
      current = parsed;
    }
    return { url: current, wrapper };
  }

  // Domain written in a link's visible text, e.g. "https://www.paypal.com/signin" -> "www.paypal.com".
  function domainFromText(text) {
    const t = String(text || '').trim().replace(/[​-‍﻿]/g, '');
    // Only text that IS a URL or bare domain counts, not sentences that mention one.
    if (!t || t.length > 300 || /\s/.test(t)) return null;
    const m = t.match(/^(?:[a-z][a-z0-9+.-]*:\/\/)?(?:[^\/\s@]+@)?((?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?\.)+[a-z¡-￿]{2,63})\.?(?::\d+)?(?:[\/?#]\S*)?$/i);
    if (!m) return null;
    const host = lower(m[1]);
    // Avoid treating file names ("invoice.pdf") as domains.
    if (/\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip|exe|html?)$/i.test(host) && !/^[a-z]+:\/\//i.test(t)) return null;
    try { return lower(new URL('http://' + host).hostname); } catch (e) { return host; }
  }

  // Does `host` imitate one of the brands? Returns { brand, reason } or null.
  // Memoized per host (emails often repeat the same link host many times).
  // One cache per brand list (the built-in list and the list including your company).
  const memos = new WeakMap();
  function findLookalike(host, brands) {
    host = lower(host);
    let memo = memos.get(brands);
    if (!memo) { memo = new Map(); memos.set(brands, memo); }
    if (memo.has(host)) return memo.get(host);
    const result = findLookalikeUncached(host, brands);
    if (memo.size > 2000) memo.clear();
    memo.set(host, result);
    return result;
  }

  function findLookalikeUncached(host, brands) {
    if (!host || isIP(host)) return null;
    const reg = registrableDomain(host);
    for (const b of brands) {
      if (isOfficial(b, reg, true)) return null;
    }
    const suffix = suffixOf(reg);
    const rawLabel = labelOf(reg);
    const uniLabel = toUnicodeHost(rawLabel);
    const variants = skeletons(uniLabel).map(sk => ({ flat: sk.replace(/[-_]/g, ''), tokens: sk.split(/[-_]+/) }));
    const subPart = toUnicodeHost(host.slice(0, Math.max(0, host.length - reg.length - 1)));
    const subTokens = subPart ? skeletons(subPart).flatMap(s => s.split(/[.\-_]+/)) : [];
    const dotted = '.' + host + '.';

    for (const brand of brands) {
      for (const d of brand.domains || []) {
        if (dotted.includes('.' + d + '.')) {
          return { brand: brand.name, reason: `puts the real ${brand.name} domain (${d}) in front of a different domain (${reg})` };
        }
      }
      for (const kw of brand.keywords || []) {
        for (const { flat, tokens } of variants) {
          if (flat === kw) {
            if (uniLabel === kw && isCountrySuffix(suffix)) continue; // e.g. paypal.de, likely owned by the brand
            if (uniLabel === kw) return { brand: brand.name, reason: `uses the ${brand.name} name on an unofficial domain ending in .${suffix}` };
            if (uniLabel.replace(/[-_]/g, '') === kw) return { brand: brand.name, reason: `adds hyphens to imitate "${kw}"` };
            return { brand: brand.name, reason: `swaps look-alike characters to imitate "${kw}"` };
          }
          // Brand name only appears after undoing character swaps (paypa1 -> paypal)?
          const swap = uniLabel.includes(kw) ? '' : `swaps look-alike characters to spell "${kw}" and `;
          if (tokens.includes(kw) && tokens.length > 1) {
            return { brand: brand.name, reason: `${swap}combines "${kw}" with extra words` };
          }
          if (kw.length >= 4 && (flat.startsWith(kw) || flat.endsWith(kw))) {
            const rest = flat.startsWith(kw) ? flat.slice(kw.length) : flat.slice(0, flat.length - kw.length);
            if (LOOKALIKE_WORDS_SET.has(rest)) return { brand: brand.name, reason: `${swap}adds "${rest}" to the ${brand.name} name` };
          }
          // Short names ("apple" vs "apply") collide with real words, so only longer ones.
          if (kw.length >= 6) {
            const limit = kw.length >= 8 ? 2 : 1;
            const d = levenshtein(flat, kw, limit);
            if (d > 0 && d <= limit) return { brand: brand.name, reason: `is one or two letters off from "${kw}" (typosquatting)` };
          }
        }
        if (kw.length >= 3 && subTokens.includes(kw)) {
          return { brand: brand.name, reason: `uses "${kw}" as a subdomain of an unrelated domain (${reg})` };
        }
      }
    }
    return null;
  }

  // Filled by setLookalikeWords() from config so this module stays independent.
  let LOOKALIKE_WORDS_SET = new Set();
  function setLookalikeWords(words) { LOOKALIKE_WORDS_SET = new Set(words || []); }

  function isOfficial(brand, reg, forLinks) {
    reg = lower(reg);
    if ((brand.domains || []).includes(reg)) return true;
    if (forLinks && (brand.linkDomains || []).includes(reg)) return true;
    return false;
  }

  return {
    lower, isIP, registrableDomain, suffixOf, labelOf, tldOf, isCountrySuffix, domainOfEmail,
    hostMatches, inList, punycodeDecode, toUnicodeHost, skeletons, levenshtein, parseUrl,
    unwrapRedirect, domainFromText, findLookalike, setLookalikeWords, isOfficial
  };
});
