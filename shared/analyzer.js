/*
 * Off the Hook rule-based analyzer.
 *
 *   analyze(emailData, settings, lists) -> { score, verdict, verdictLabel, findings[], links[], notes[], summary }
 *
 * Pure function: no DOM, no network, no storage. `lists` holds the parsed contents of
 * data/keywords.json and data/brands.json ({ keywords, brands }).
 *
 * emailData shape:
 *   { from: { name, address }, replyTo: string|string[], subject, body,
 *     links: [{ text, href }], attachments: [filename], imageCount, imageAlts: [],
 *     authResults: string|null, headersOnly: boolean }
 *
 * Each finding: { id, severity, title, explanation, matches[], kind, points, links? }
 *   kind: 'sender' | 'link' | 'content' | 'attachment' | 'header' | 'other'
 *   links: indexes into emailData.links (link findings only)
 */
(function (root, factory) {
  const isNode = typeof module === 'object' && module.exports;
  const deps = isNode
    ? { config: require('./config.js'), domain: require('./domain-utils.js') }
    : root.PhishGuard;
  const mod = factory(deps.config, deps.domain);
  if (isNode) module.exports = mod;
  else root.PhishGuard.analyzer = mod;
})(typeof globalThis !== 'undefined' ? globalThis : this, function (CONFIG, D) {
  'use strict';

  D.setLookalikeWords(CONFIG.LOOKALIKE_WORDS);
  const FREEMAIL = new Set(CONFIG.FREEMAIL_DOMAINS);
  const SHORTENERS = new Set(CONFIG.URL_SHORTENERS);
  const SUSPICIOUS_TLDS = new Set(CONFIG.SUSPICIOUS_TLDS);
  const RISKY_EXT = new Set(CONFIG.RISKY_EXTENSIONS);
  const ARCHIVE_EXT = new Set(CONFIG.ARCHIVE_EXTENSIONS);
  const DECOY_EXT = new Set(CONFIG.DECOY_EXTENSIONS);
  const SEVERITY_RANK = { high: 3, medium: 2, low: 1 };
  const PLATFORMS = new Set(CONFIG.SHARED_PLATFORMS || []);

  const now = () => (typeof performance !== 'undefined' && performance.now ? performance.now() : Date.now());
  const escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // "Word character" class for whole-word matching (Latin, Latin-extended, Greek, Cyrillic).
  // A plain class is used instead of \p{L} because /u property escapes are ~40x slower to
  // compile, and the service worker recompiles after every restart.
  const WORD = 'A-Za-z0-9_\\u00C0-\\u024F\\u0370-\\u052F';
  const NOT_AFTER_WORD = '(?<![' + WORD + '])';
  const NOT_BEFORE_WORD = '(?![' + WORD + '])';
  const WORD_CHAR_RE = new RegExp('[' + WORD + ']');
  const wordListRe = words => new RegExp(NOT_AFTER_WORD + '(' + words.map(w => escapeRe(w).replace(/\s+/g, '\\s+')).join('|') + ')' + NOT_BEFORE_WORD, 'i');
  const ORG_RE = wordListRe(CONFIG.ORG_WORDS);
  const EXEC_RE = wordListRe(CONFIG.EXEC_TITLES);
  const DISPLAY_LURE_RE = new RegExp(NOT_AFTER_WORD + '(update[sd]?|awaiting|response|respond|reply needed|urgent(ly)?|immediate(ly)?|action required|verify|verification|confirm(ation)?|alert|warning|notice|important|reminder|suspended|locked|expir(e|ed|es|ing|ation)|pending|attention|info update|contact info|re-?activate)' + NOT_BEFORE_WORD, 'i');
  // Typical corporate email-footer disclaimers.
  const DISCLAIMER_RE = /intended (solely|only|exclusively) for the (use of the )?(individual|person|addressee|named recipient)|if you (have )?received this (e-?mail|message|communication) in error|(confidential|privileged)(,| and\/or| and| or) (proprietary|privileged|confidential)|property of [A-Z][\w&.\- ]{1,40}\. It may contain/i;
  // Content rules that mean "the sender wants you to do something".
  const REQUEST_RULES = ['kw_credential', 'kw_money', 'kw_authority', 'kw_contact_request', 'kw_prize'];

  // ---------- keyword compilation (cached) ----------
  const phraseCache = new Map();
  function compilePhrases(phrases) {
    const key = phrases.join('\u0001');
    if (phraseCache.has(key)) return phraseCache.get(key);
    // Phrases that start and end with a letter/digit share one pair of word-boundary
    // checks (much faster to compile than one pair per phrase); the rest stand alone.
    const bounded = [], other = [];
    for (const p of phrases) {
      if (!p || typeof p !== 'string' || !p.trim()) continue;
      if (p.startsWith('re:')) {
        try { new RegExp(p.slice(3), 'i'); other.push(p.slice(3)); } catch (e) { /* skip invalid user regex */ }
        continue;
      }
      const t = p.trim();
      const body = escapeRe(t).replace(/\s+/g, '\\s+').replace(/'/g, "['\u2019]");
      const pre = WORD_CHAR_RE.test(t[0]), post = WORD_CHAR_RE.test(t[t.length - 1]);
      if (pre && post) bounded.push(body);
      else other.push((pre ? NOT_AFTER_WORD : '') + body + (post ? NOT_BEFORE_WORD : ''));
    }
    // Longest first so "account has been suspended" wins over "account suspended".
    const byLen = (a, b) => b.length - a.length;
    const parts = [];
    if (bounded.length) parts.push(NOT_AFTER_WORD + '(?:' + bounded.sort(byLen).join('|') + ')' + NOT_BEFORE_WORD);
    for (const s of other.sort(byLen)) parts.push('(?:' + s + ')');
    const re = parts.length ? new RegExp(parts.join('|'), 'gi') : null;
    if (phraseCache.size > 50) phraseCache.clear();
    phraseCache.set(key, re);
    return re;
  }
  function findPhrases(text, re, limit) {
    if (!re) return [];
    re.lastIndex = 0;
    const seen = new Map();
    let m, guard = 0;
    while ((m = re.exec(text)) && guard++ < 1000) {
      if (m[0] === '') { re.lastIndex++; continue; }
      const k = m[0].toLowerCase().replace(/\s+/g, ' ');
      if (!seen.has(k)) seen.set(k, m[0].replace(/\s+/g, ' '));
      if (seen.size >= limit) break;
    }
    return Array.from(seen.values());
  }

  // ---------- brand helpers ----------
  const brandNameCache = new WeakMap();
  function brandNameRes(brand) {
    let c = brandNameCache.get(brand);
    if (!c) {
      const amb = new Set((brand.ambiguous || []).map(n => n.toLowerCase()));
      c = (brand.names || []).map(n => ({ name: n, ambiguous: amb.has(n.toLowerCase()), re: wordListRe([n]) }));
      brandNameCache.set(brand, c);
    }
    return c;
  }
  function findBrandIn(text, brands) {
    if (!text) return null;
    for (const brand of brands) {
      for (const n of brandNameRes(brand)) {
        if (!n.re.test(text)) continue;
        if (n.ambiguous && text.trim().toLowerCase() !== n.name.toLowerCase() && !ORG_RE.test(text)) continue;
        return { brand, matched: n.name };
      }
    }
    return null;
  }
  function brandOwning(reg, brands, forLinks) {
    for (const b of brands) if (D.isOfficial(b, reg, forLinks)) return b;
    return null;
  }

  // ---------- context ----------
  function normalizeEmail(e) {
    e = e || {};
    const from = e.from || {};
    let replyTo = e.replyTo || [];
    if (!Array.isArray(replyTo)) replyTo = [replyTo];
    return {
      from: { name: String(from.name || '').trim(), address: String(from.address || '').trim().toLowerCase() },
      replyTo: replyTo.map(r => String(r || '').trim().toLowerCase()).filter(Boolean),
      subject: String(e.subject || ''),
      body: String(e.body || '').slice(0, 100000),
      links: Array.isArray(e.links) ? e.links.slice(0, 500) : [],
      attachments: Array.isArray(e.attachments) ? e.attachments.map(String) : [],
      imageCount: Number(e.imageCount) || 0,
      imageAlts: Array.isArray(e.imageAlts) ? e.imageAlts.map(String) : [],
      authResults: e.authResults ? String(e.authResults) : '',
      headersOnly: !!e.headersOnly,
      // Selected raw header lines (lower-case name -> [values]), e.g. from Outlook "Message details".
      headers: (e.headers && typeof e.headers === 'object')
        ? Object.fromEntries(Object.entries(e.headers).slice(0, 40)
            .filter(([k, v]) => /^[a-z0-9-]{1,80}$/.test(k) && Array.isArray(v))
            .map(([k, v]) => [k, v.slice(0, 10).map(x => String(x).slice(0, 2000))]))
        : null,
      // Banners the webmail itself showed: [{ level: 'high'|'low', text }]
      providerWarnings: Array.isArray(e.providerWarnings)
        ? e.providerWarnings.filter(w => w && w.text).map(w => ({ level: w.level === 'high' ? 'high' : 'low', text: String(w.text).slice(0, 200) }))
        : []
    };
  }

  function makeTrust(list) {
    const domains = [], addresses = new Set();
    for (const raw of list || []) {
      const v = String(raw || '').trim().toLowerCase().replace(/^@/, '');
      if (!v) continue;
      if (v.includes('@')) addresses.add(v); else domains.push(v);
    }
    return {
      address: a => addresses.has(a),
      domain: host => !!host && domains.some(d => D.hostMatches(host, d))
    };
  }

  // "yourcompany.com", "@yourcompany.com", "https://www.yourcompany.com/" -> "yourcompany.com"
  function cleanDomainInput(s) {
    return String(s || '').trim().toLowerCase()
      .replace(/^[a-z]+:\/\//, '').replace(/^.*@/, '').replace(/[\/?#].*$/, '').replace(/^www\./, '').replace(/\.$/, '');
  }

  // Your company's domains, plus a brand-style entry for each so look-alike detection
  // also catches fakes like "yourcompany-payroll.com". Cached so the look-alike memo stays warm.
  let companyCache = { key: null, brands: null, value: null };
  function makeCompany(list, brands) {
    const domains = Array.from(new Set((list || []).map(cleanDomainInput).filter(d => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d))));
    const key = domains.join(',');
    if (companyCache.key === key && companyCache.brands === brands) return companyCache.value;
    const regs = Array.from(new Set(domains.map(D.registrableDomain)));
    const companyBrands = regs.map(r => ({
      name: `your company (${r})`,
      keywords: [D.labelOf(r).replace(/[-_.]/g, '')].filter(k => k.length >= 3),
      domains: [r]
    }));
    const value = {
      domains,
      regs,
      keywords: companyBrands.flatMap(b => b.keywords),
      lookalikeBrands: companyBrands.length ? companyBrands.concat(brands) : brands,
      has: host => !!host && domains.some(d => D.hostMatches(host, d))
    };
    companyCache = { key, brands, value };
    return value;
  }

  function addFinding(ctx, id, data) {
    const rule = CONFIG.RULES[id] || { weight: 5, severity: 'low' };
    const matches = (data.matches || []).filter(m => m != null && m !== '').map(String);
    let f = ctx.findings.find(x => x.id === id);
    if (!f) {
      f = {
        id,
        severity: data.severity || rule.severity,
        title: data.title,
        explanation: data.explanation,
        matches: [],
        kind: data.kind || 'other',
        points: data.points != null ? data.points : rule.weight
      };
      if (data.links) f.links = [];
      ctx.findings.push(f);
    }
    for (const m of matches) {
      if (!f.matches.includes(m) && f.matches.length < CONFIG.SCORING.maxMatchesPerFinding) f.matches.push(m);
    }
    if (data.links) for (const i of data.links) if (!f.links.includes(i)) f.links.push(i);
    return f;
  }

  // Is this host on a downloaded list of active phishing / malware sites? Exact host first, then
  // its registrable domain, except for shared platforms (a list naming one weeblysite.com site
  // must not flag all of them). Returns the list's name or null.
  function blockHit(ctx, host) {
    const bl = ctx.lists.blocklist;
    if (!bl || !host) return null;
    const exact = bl.has(host);
    if (exact) return exact;
    const reg = D.registrableDomain(host);
    return reg && reg !== host && !PLATFORMS.has(reg) ? bl.has(reg) : null;
  }

  // ---------- sender checks ----------
  function checkSender(ctx) {
    const { email, brands } = ctx;
    const name = email.from.name;
    const addr = email.from.address;
    const domain = D.domainOfEmail(addr);
    if (!domain) {
      ctx.notes.push("Off the Hook couldn't read the sender's address on this page, so sender checks were skipped.");
      ctx.unreadSender = { name };
      return;
    }
    const reg = D.registrableDomain(domain);
    const freemail = FREEMAIL.has(reg) || FREEMAIL.has(domain);
    const officialBrand = brandOwning(reg, brands, false);
    const trusted = ctx.trust.address(addr) || ctx.trust.domain(domain);
    const internal = ctx.company.has(domain);
    ctx.sender = { name, address: addr, domain, reg, freemail, trusted, internal, officialBrand: officialBrand && officialBrand.name };
    const fromLabel = name ? `${name} <${addr}>` : addr;

    // 0. Outside sender using your company's name in the display name ("Acme Steel HR" <x@gmail.com>).
    if (!internal && name && ctx.company.keywords.length) {
      const squashed = name.toLowerCase().replace(/[^a-z0-9]/g, '');
      const kw = ctx.company.keywords.find(k => k.length >= 4 && squashed.includes(k));
      if (kw) {
        addFinding(ctx, 'company_impersonation', {
          kind: 'sender',
          severity: freemail ? 'high' : undefined,
          points: freemail ? 30 : undefined,
          title: "Outside sender using your company's name",
          explanation: `The sender's name "${name}" uses your company's name, but the email came from ${addr}, not from ${ctx.company.regs.join(' or ')}. Scammers pose as coworkers, HR, or payroll this way.`,
          matches: [fromLabel]
        });
      }
    }

    // 1. Display name contains a different address or domain.
    const embAddr = name.match(/[\w.+-]+@((?:[\w-]+\.)+[a-z]{2,})/i);
    const embDomain = embAddr ? embAddr[1] : (name.match(/(?<![\w@-])((?:[a-z0-9-]+\.)+(?:com|net|org|gov|edu|io|co|us|uk|ca|de|info|biz|me|app))(?![\w-])/i) || [])[1];
    if (embDomain) {
      const embReg = D.registrableDomain(embDomain);
      const sameBrand = officialBrand && D.isOfficial(officialBrand, embReg, true);
      if (embReg !== reg && !sameBrand) {
        addFinding(ctx, 'display_name_mismatch', {
          kind: 'sender',
          title: 'Display name shows a different address',
          explanation: `The sender's name shows "${embAddr ? embAddr[0] : embDomain}", but the message really came from ${addr}. This trick makes a fake sender look official.`,
          matches: [name, addr]
        });
      }
    }

    // 2. Display name claims a known brand, but the domain isn't theirs.
    const nameBrand = findBrandIn(name, brands);
    if (nameBrand && !D.isOfficial(nameBrand.brand, reg, false)) {
      addFinding(ctx, 'brand_impersonation', {
        kind: 'sender',
        title: `Claims to be ${nameBrand.brand.name} from an unofficial address`,
        explanation: `The sender calls itself "${nameBrand.matched}", but ${domain} is not one of ${nameBrand.brand.name}'s official domains (${nameBrand.brand.domains.slice(0, 3).join(', ')}).`,
        matches: [name, addr]
      });
    }

    // 3. Free-mail account pretending to be a company or executive.
    if (freemail) {
      const local = addr.split('@')[0].replace(/[._\-\d]+/g, ' ');
      const org = name.match(ORG_RE);
      const exec = name.match(EXEC_RE) || local.match(EXEC_RE);
      if (nameBrand || org || exec) {
        const what = nameBrand ? `the company "${nameBrand.matched}"` : exec ? `an executive ("${exec[0]}")` : `an organization ("${org[0]}")`;
        // A role word alone ("Billing Team") is weaker evidence than a brand or executive title.
        const strong = !!(nameBrand || exec);
        addFinding(ctx, 'freemail_impersonation', {
          kind: 'sender',
          severity: strong ? undefined : 'medium',
          points: strong ? undefined : 15,
          title: 'Free email account posing as a company or executive',
          explanation: `This comes from a free ${reg} account but presents itself as ${what}. Companies and executives normally email from their own domain.`,
          matches: [fromLabel]
        });
      }
    }

    // 4. Look-alike sender domain.
    if (!trusted && !officialBrand && !internal && !freemail) {
      const listed = blockHit(ctx, domain);
      if (listed) {
        const f = addFinding(ctx, 'sender_blocklisted', {
          kind: 'sender',
          title: "Sender's domain is a known phishing or malware site",
          explanation: `${D.toUnicodeHost(domain)} is on a public list of active phishing and malware sites (${listed}). Don't reply, click or open anything in this email.`,
          matches: [addr]
        });
        f.floor = 'phishing';
      }
    }
    if (!trusted && !officialBrand && !internal) {
      const la = D.findLookalike(domain, ctx.company.lookalikeBrands);
      if (la) {
        addFinding(ctx, 'sender_lookalike', {
          kind: 'sender',
          title: `Sender domain imitates ${la.brand}`,
          explanation: `The sender's domain ${D.toUnicodeHost(domain)} ${la.reason}.`,
          matches: [addr]
        });
      }
      if (SUSPICIOUS_TLDS.has(D.tldOf(domain))) {
        addFinding(ctx, 'sender_suspicious_tld', {
          kind: 'sender',
          title: 'Sender uses a high-risk domain ending',
          explanation: `Domains ending in .${D.tldOf(domain)} are cheap and frequently used for spam and phishing.`,
          matches: [addr]
        });
      }
    }

    // 4b. Display name reads like a subject line or alert instead of a person or company
    //     ("CONTACT INFO UPDATE -- Awaiting your response now !!!").
    if (name && !officialBrand && !trusted) {
      const letters = name.replace(/[^A-Za-z]/g, '');
      const shouty = letters.length >= 10 && letters === letters.toUpperCase() && name.trim().split(/\s+/).length >= 3;
      const punct = /[!?]{2,}|--|\*\*|>>/.test(name); // single "!" allowed ("Yahoo!")
      const lure = name.match(DISPLAY_LURE_RE);
      if (punct || lure || shouty) {
        addFinding(ctx, 'display_name_lure', {
          kind: 'sender',
          title: 'Sender name looks like a headline, not a person or company',
          explanation: `The sender's name is "${name}". Real people and companies use their name here; scammers put alerts or calls to action in it so the message stands out and feels urgent.`,
          matches: [name]
        });
      }
    }

    // 5. Reply-To goes somewhere else.
    for (const rt of email.replyTo) {
      const rtDomain = D.domainOfEmail(rt);
      if (!rtDomain) continue;
      const rtReg = D.registrableDomain(rtDomain);
      if (rtReg === reg) continue;
      if (officialBrand && D.isOfficial(officialBrand, rtReg, true)) continue;
      if (ctx.trust.domain(rtDomain)) continue;
      const rtFree = FREEMAIL.has(rtReg);
      addFinding(ctx, rtFree && !freemail ? 'reply_to_freemail' : 'reply_to_mismatch', {
        kind: 'sender',
        title: rtFree && !freemail ? 'Replies go to a free email account' : 'Replies go to a different domain',
        explanation: `The message is from ${domain}, but if you hit Reply it goes to ${rt}. Scammers do this so your answer reaches them, not the real sender.`,
        matches: [rt]
      });
    }

    // 6. Subject mentions a brand the sender doesn't belong to.
    if (!nameBrand && !trusted) {
      const subjBrand = findBrandIn(email.subject, brands);
      if (subjBrand && !D.isOfficial(subjBrand.brand, reg, false)) {
        addFinding(ctx, 'brand_in_subject', {
          kind: 'sender',
          title: `Subject mentions ${subjBrand.brand.name}, sender isn't ${subjBrand.brand.name}`,
          explanation: `The subject refers to ${subjBrand.brand.name}, but the email comes from ${domain}. That can be normal (for example a store receipt), but is also common in impersonation.`,
          matches: [subjBrand.matched]
        });
      }
    }
  }

  // ---------- link checks ----------
  function checkLinks(ctx) {
    const { email, brands } = ctx;
    const report = [];
    // Links read from QR code images say so in their titles ("QR code link goes to ...").
    const linkFinding = (id, i, title, explanation, match) =>
      addFinding(ctx, id, { kind: 'link', title: email.links[i].qr ? title.replace(/^Link/, 'QR code link') : title, explanation, matches: [match], links: [i] });

    email.links.forEach((link, i) => {
      const text = String(link.text || '').trim().replace(/\s+/g, ' ').slice(0, 200);
      const href = String(link.href || '').trim();
      if (!href || href.startsWith('#')) return;
      // checks: what the hover card lists. ok=true passed, ok=false failed, ok=null information.
      const entry = { index: i, text, href, display: href, domain: '', flags: [], severity: null, checks: [], risk: 'ok' };
      if (link.qr) entry.qr = true;
      const flag = (id, label, detail) => {
        entry.flags.push(label);
        const sev = (CONFIG.RULES[id] || {}).severity || 'low';
        if (!entry.severity || SEVERITY_RANK[sev] > SEVERITY_RANK[entry.severity]) entry.severity = sev;
        entry.checks.push({ ok: false, severity: sev, text: detail || label });
      };
      const pass = t => entry.checks.push({ ok: true, text: t });
      const info = t => entry.checks.push({ ok: null, text: t });

      const scheme = (href.match(/^([a-z][a-z0-9+.-]*):/i) || [])[1];
      const lscheme = scheme ? scheme.toLowerCase() : '';
      if (lscheme === 'javascript' || lscheme === 'data' || lscheme === 'vbscript') {
        linkFinding('link_script_scheme', i, 'Link runs code instead of opening a web page',
          `A link uses a "${lscheme}:" address, which can run code or show a fake page in your browser. Legitimate emails don't do this.`, text || href.slice(0, 60));
        flag('link_script_scheme', 'Runs code', `Runs code ("${lscheme}:") instead of opening a web page`);
        entry.display = lscheme + ':…';
        finishEntry(entry);
        report.push(entry);
        return;
      }
      if (lscheme === 'mailto') {
        let addr = href.slice(7).split('?')[0];
        try { addr = decodeURIComponent(addr); } catch (e) { /* keep raw */ }
        addr = addr.slice(0, 200);
        const target = D.domainOfEmail(addr);
        entry.kind = 'email';
        entry.display = addr;
        entry.domain = target;
        const shown = (text.match(/[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/) || [])[1];
        if (shown && target && D.registrableDomain(shown) !== D.registrableDomain(target)) {
          linkFinding('link_text_mismatch', i, 'Link text does not match where it goes',
            'The link shows one address or website but actually points somewhere else.', `${text} → ${addr}`);
          flag('link_text_mismatch', 'Text mismatch', `Shows ${shown} but writes to ${target}`);
        } else if (shown) {
          pass('Shown address matches the real one');
        }
        info('Opens a new email to ' + addr);
        finishEntry(entry);
        report.push(entry);
        return;
      }
      if (lscheme === 'tel' || lscheme === 'cid' || lscheme === 'sms') return;

      const parsed = D.parseUrl(href);
      if (!parsed || !/^https?:$/.test(parsed.protocol)) return;
      const { url: real, wrapper } = D.unwrapRedirect(parsed);
      const host = D.lower(real.hostname);
      const reg = D.registrableDomain(host);
      const uniHost = D.toUnicodeHost(host);
      entry.display = real.href;
      entry.domain = uniHost;
      entry.registrable = D.toUnicodeHost(reg);
      if (wrapper) {
        entry.wrapper = wrapper;
        const kind = /safelinks/.test(wrapper) ? 'Microsoft Safe Links' : /google/.test(wrapper) ? 'Google redirect' : 'security';
        info(`Unwrapped from a ${kind} wrapper (${wrapper})`);
      }
      const linkBrand = brandOwning(reg, brands, true);
      const companyLink = ctx.company.has(host);
      const userTrusted = ctx.trust.domain(host);
      const trustedLink = userTrusted || companyLink || !!linkBrand;
      const isTracker = D.inList(host, CONFIG.TRACKER_DOMAINS) || D.inList(D.lower(parsed.hostname), CONFIG.TRACKER_DOMAINS);
      if (companyLink) pass("Your company's own website");
      else if (linkBrand) pass(`Official ${linkBrand.name} website`);
      else if (userTrusted) pass('On your trusted list');
      if (isTracker) info('Goes through an email tracking service first');

      // Visible text names a different site.
      const shownHost = D.domainFromText(text);
      if (shownHost) {
        const shownReg = D.registrableDomain(shownHost);
        const sameOwner = shownReg === reg || (linkBrand && D.isOfficial(linkBrand, shownReg, true));
        if (!sameOwner) {
          if (isTracker) {
            linkFinding('link_text_tracked', i, 'Link text differs from its address (tracking link)',
              'Some links show one website but go through an email-tracking service first. This is common in newsletters, but check the final destination before signing in anywhere.', `${text} → ${uniHost}`);
            flag('link_text_tracked', 'Via tracker', `Shows ${shownHost} but goes through ${uniHost} first`);
          } else {
            linkFinding('link_text_mismatch', i, 'Link text does not match where it goes',
              'A link displays one web address but actually takes you to a different website. This is one of the most common phishing tricks.', `${text} → ${uniHost}`);
            flag('link_text_mismatch', `Shows ${shownHost}`, `Shows ${shownHost} but really goes to ${uniHost}`);
          }
        } else {
          pass('Link text matches where it goes');
        }
      }

      if (D.isIP(host)) {
        linkFinding('link_ip', i, 'Link points to a raw IP address',
          'Real companies link to their named website, not a numeric address like 192.168.1.10.', host);
        flag('link_ip', 'IP address', 'Goes to a raw IP address instead of a named website');
      } else {
        pass('Goes to a named website, not a raw IP address');
      }
      if (real.username || real.password || parsed.username) {
        linkFinding('link_at_trick', i, 'Link uses the "@" trick',
          `Everything before "@" in a web address is ignored, so a link like "paypal.com@${uniHost}" really goes to ${uniHost}.`, href.slice(0, 120));
        flag('link_at_trick', '@ trick', `Uses the "@" trick: everything before "@" is ignored, so it really goes to ${uniHost}`);
      }
      if (host.split('.').some(l => l.startsWith('xn--'))) {
        linkFinding('link_punycode', i, 'Link uses international look-alike characters',
          `The address ${host} is written with non-English letters and displays as "${uniHost}". Attackers use this to make fake sites look identical to real ones.`, `${uniHost} (${host})`);
        flag('link_punycode', 'Look-alike letters', `Uses non-English look-alike letters (real address: ${host})`);
      }
      if (SHORTENERS.has(reg) || SHORTENERS.has(host)) {
        linkFinding('link_shortener', i, 'Shortened link hides the destination',
          'URL shorteners (bit.ly, tinyurl, etc.) hide where a link really goes. Be careful with these in unexpected emails.', real.href.slice(0, 120));
        flag('link_shortener', 'Shortened', `Shortened link (${reg}): the final destination is hidden`);
      } else {
        pass('Not a shortened link');
      }
      if (!trustedLink) {
        const listed = blockHit(ctx, host);
        if (listed) {
          const f = linkFinding('link_blocklisted', i, 'Link goes to a known phishing or malware site',
            `${uniHost} is on a public list of active phishing and malware sites (${listed}). Don't open it.`, uniHost);
          f.floor = 'phishing';
          flag('link_blocklisted', 'Known scam site', `Listed as an active phishing or malware site (${listed})`);
        } else if (ctx.lists.blocklist) {
          pass('Not on the known scam-site lists');
        }
      }
      if (!trustedLink && !D.isIP(host)) {
        const subCount = host.split('.').length - reg.split('.').length;
        if (subCount >= 3) {
          linkFinding('link_many_subdomains', i, 'Link has an unusually long chain of subdomains',
            'Long addresses like "secure.login.account.example.xyz" are used to push the real domain out of view.', uniHost);
          flag('link_many_subdomains', 'Many subdomains', `Long chain of subdomains hides the real site, which is ${D.toUnicodeHost(reg)}`);
        }
        const la = D.findLookalike(host, ctx.company.lookalikeBrands);
        if (la) {
          linkFinding('link_lookalike', i, `Link goes to a site imitating ${la.brand}`,
            `The link goes to ${uniHost}, which ${la.reason}.`, uniHost);
          flag('link_lookalike', `Imitates ${la.brand}`, `Imitates ${la.brand}: ${uniHost} ${la.reason}`);
        } else {
          pass('Not a look-alike of a known brand' + (ctx.company.regs.length ? ' or your company' : ''));
        }
        if (SUSPICIOUS_TLDS.has(D.tldOf(host))) {
          linkFinding('link_suspicious_tld', i, 'Link uses a high-risk domain ending',
            `Domains ending in .${D.tldOf(host)} are frequently used for spam and phishing sites.`, uniHost);
          flag('link_suspicious_tld', 'Risky ending', `High-risk domain ending (.${D.tldOf(host)})`);
        }
      }
      if (real.protocol === 'http:' && !D.isIP(host)) {
        linkFinding('link_insecure', i, 'Link is not encrypted (http)',
          'The link uses http instead of https. Never enter a password or payment details on such a page.', real.href.slice(0, 120));
        flag('link_insecure', 'Not HTTPS', 'Not encrypted (http, not https): never enter passwords there');
      } else if (real.protocol === 'https:') {
        pass('Encrypted connection (https)');
      }
      if (link.qr) {
        // Phishers hide links in QR codes because text scanners can't read them and a phone
        // skips the work computer's protections. An official site counts much less.
        const where = trustedLink ? `an official site (${uniHost})` : uniHost;
        addFinding(ctx, 'qr_link', {
          kind: 'link', title: 'QR code in the email opens a website',
          explanation: `Off the Hook read the QR code: it goes to ${where}. Scammers use QR codes because email filters can't read them and scanning one on your phone skips your work computer's protections. Only scan QR codes you were expecting.`,
          matches: [uniHost], links: [i],
          severity: trustedLink ? 'low' : 'medium', points: trustedLink ? 3 : CONFIG.RULES.qr_link.weight
        });
        if (trustedLink) info('Read from a QR code image in the email');
        else flag('qr_link', 'QR code', 'Hidden in a QR code image: scanning it on a phone skips your computer\'s protections');
      }
      finishEntry(entry);
      report.push(entry);
    });

    report.sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0) || a.index - b.index);
    ctx.linkReport = report;
  }

  // Overall risk of one link for the hover card (danger / caution / ok), failed checks first.
  function finishEntry(entry) {
    entry.risk = entry.severity === 'high' ? 'danger' : entry.severity ? 'caution' : 'ok';
    const order = c => (c.ok === false ? 0 : c.ok === null ? 1 : 2);
    entry.checks.sort((a, b) => order(a) - order(b));
  }

  // ---------- content checks ----------
  function checkContent(ctx) {
    const { email, lists, settings } = ctx;
    const text = email.subject + '\n' + email.body;
    const cats = (lists.keywords && lists.keywords.categories) || {};
    const limit = CONFIG.SCORING.maxMatchesPerFinding;
    const pointsFor = (ruleId, n) => {
      const base = (CONFIG.RULES[ruleId] || { weight: 5 }).weight;
      return base + Math.min(CONFIG.SCORING.keywordExtraPerMatch * (n - 1), CONFIG.SCORING.keywordMaxExtra);
    };
    for (const key of Object.keys(cats)) {
      const cat = cats[key];
      if (!cat || !Array.isArray(cat.phrases) || !CONFIG.RULES[cat.ruleId]) continue;
      const found = findPhrases(text, compilePhrases(cat.phrases), limit);
      if (!found.length) continue;
      addFinding(ctx, cat.ruleId, {
        kind: 'content', title: cat.title, explanation: cat.explanation, matches: found,
        points: pointsFor(cat.ruleId, found.length)
      });
    }
    const custom = (settings.customKeywords || []).map(s => String(s).trim()).filter(Boolean);
    if (custom.length) {
      const found = findPhrases(text, compilePhrases(custom), limit);
      if (found.length) {
        addFinding(ctx, 'kw_custom', {
          kind: 'content', title: 'Matches your custom watch-list',
          explanation: 'This email contains phrases you added to your own keyword list in Off the Hook settings.',
          matches: found, points: pointsFor('kw_custom', found.length)
        });
      }
    }
    // Phrases you highlighted when reporting phishing ("What gave it away?").
    const learned = (ctx.memory && ctx.memory.phrases) || [];
    if (learned.length) {
      const found = findPhrases(text, compilePhrases(learned), limit);
      if (found.length) {
        addFinding(ctx, 'kw_learned', {
          kind: 'content', title: 'Matches wording from phishing you reported',
          explanation: 'You marked this wording as a giveaway when you reported an earlier phishing email.',
          matches: found, points: pointsFor('kw_learned', found.length)
        });
      }
    }
  }

  // ---------- memory from your reports ----------
  function applyMemory(ctx) {
    const mem = ctx.memory;
    const s = ctx.sender;
    if (!mem) return;
    const date = id => {
      const r = Object.values(mem.reportedKeys || {}).find(x => x.id === id);
      return r ? ' on ' + new Date(r.at).toLocaleDateString() : '';
    };

    if (s && mem.phishSenders && mem.phishSenders[s.address]) {
      const f = addFinding(ctx, 'reported_sender', {
        kind: 'sender', title: 'You reported this sender as phishing',
        explanation: `You reported an earlier email from ${s.address} as phishing${date(mem.phishSenders[s.address])}. Treat anything from this sender as dangerous.`,
        matches: [s.address]
      });
      f.pinned = true; f.floor = 'phishing';
    } else if (s && mem.phishDomains && mem.phishDomains[s.reg]) {
      const f = addFinding(ctx, 'reported_domain', {
        kind: 'sender', title: 'Sent from a domain you reported',
        explanation: `You reported phishing from ${s.reg} before${date(mem.phishDomains[s.reg])}. This email comes from the same domain.`,
        matches: [s.address]
      });
      f.pinned = true; f.floor = 'suspicious';
    }

    if (mem.phishLinkDomains) {
      for (const entry of ctx.linkReport) {
        const reg = entry.domain && D.registrableDomain(D.lower(entry.domain));
        if (!reg || !mem.phishLinkDomains[reg]) continue;
        const f = addFinding(ctx, 'reported_link', {
          kind: 'link', title: 'Link goes to a site from phishing you reported',
          explanation: `A link points to ${reg}, which appeared in phishing you reported${date(mem.phishLinkDomains[reg])}.`,
          matches: [entry.domain], links: [entry.index]
        });
        f.pinned = true; f.floor = 'suspicious';
        entry.flags.push('Reported site');
        entry.severity = 'high';
        entry.risk = 'danger';
        if (entry.checks) entry.checks.unshift({ ok: false, severity: 'high', text: `${reg} appeared in phishing you reported` });
      }
    }

    // "It's safe" reports quiet the warnings that fired for this sender before.
    const quiet = s && mem.quiet && mem.quiet[s.address];
    if (quiet && quiet.length) {
      const q = new Set(quiet);
      const keep = [];
      for (const f of ctx.findings) (q.has(f.id) ? ctx.quieted : keep).push(f);
      if (ctx.quieted.length) {
        ctx.findings = keep;
        ctx.notes.push(`You marked email from ${s.address} as safe before, so ${ctx.quieted.length} warning(s) were quieted.`);
      }
    }
  }

  // ---------- free-mail sender combinations (run after content checks) ----------
  function checkFreemailCombos(ctx) {
    const s = ctx.sender;
    if (!s || !s.freemail || s.trusted) return;

    // An unknown personal account asking you to do something (phone number, money,
    // credentials, a "quick favor") is the core pattern of most business-email scams.
    const requests = ctx.findings.filter(f => REQUEST_RULES.includes(f.id));
    if (requests.length) {
      const what = requests.map(f => ({
        kw_credential: 'passwords or personal details', kw_money: 'money or payment changes',
        kw_authority: 'a secret or urgent favor', kw_contact_request: 'your phone number', kw_prize: 'a prize or reward'
      })[f.id]);
      addFinding(ctx, 'freemail_request', {
        kind: 'sender',
        title: `Personal ${s.reg} account asking for ${what[0]}`,
        explanation: `This comes from a free personal account (${s.address}) and asks for ${what.join(' and ')}. Businesses and coworkers write from their own company domain. Treat requests from unknown personal accounts as suspicious, and check with the person by a phone number you already have.`,
        matches: [s.address].concat(requests.flatMap(f => f.matches.slice(0, 2)))
      });
    }

    // Company legal footer sent from a free-mail account.
    const m = ctx.email.body.match(DISCLAIMER_RE);
    if (m) {
      addFinding(ctx, 'freemail_disclaimer', {
        kind: 'content',
        title: 'Company disclaimer sent from a personal account',
        explanation: `The message ends with a company's legal disclaimer, but it was sent from a free ${s.reg} account. Scammers paste real disclaimers to look official.`,
        matches: [m[0]]
      });
    }
  }

  // ---------- coworker account asking for something personal ----------
  // Only the "personal" part of each content rule counts, so everyday office mail
  // ("text me when the truck arrives", "the invoice is past due", "are you free at 2?")
  // doesn't trigger it.
  const INTERNAL_ASKS = {
    kw_credential: { what: 'passwords or personal details', keep: () => true },
    kw_money: { what: 'gift cards, money transfers, or bank details', keep: m => /gift|card|wire|bank|crypto|bitcoin|btc|usdt|ethereum|western union|moneygram|send money|account details|banking|transfer|payment details/i.test(m) },
    kw_contact_request: { what: 'your phone number', keep: m => /number|no\.|#|whatsapp|personal|mobile|cell/i.test(m) },
    kw_authority: { what: 'a secret favor', keep: m => /confidential|between us|tell anyone|do not discuss|discreet/i.test(m) },
    kw_prize: { what: 'a prize or reward claim', keep: () => true }
  };
  const INTERNAL_RISKS = {
    link_lookalike: 'a link to a fake look-alike website', link_text_mismatch: 'a link that hides its real destination',
    link_at_trick: 'a disguised link', link_ip: 'a link to a raw IP address', link_script_scheme: 'a link that runs code',
    link_punycode: 'a link with look-alike letters', attachment_double_ext: 'a disguised attachment',
    attachment_risky: 'a risky attachment', kw_ai_manipulation: 'hidden instructions aimed at email filters'
  };

  // What personal or risky thing the email asks for, using only the "personal" part of
  // each content rule. Returns { list: "your phone number and …", matches: [] } or null.
  function personalAsks(ctx) {
    const what = [], matches = [];
    for (const f of ctx.findings) {
      const ask = INTERNAL_ASKS[f.id];
      if (ask) {
        const kept = f.matches.filter(ask.keep);
        if (kept.length) { what.push(ask.what); matches.push(...kept.slice(0, 2)); }
      } else if (INTERNAL_RISKS[f.id]) {
        what.push(INTERNAL_RISKS[f.id]);
        matches.push(...f.matches.slice(0, 1));
      }
    }
    if (!what.length) return null;
    const items = Array.from(new Set(what));
    const list = items.length > 1 ? items.slice(0, -1).join(', ') + ' and ' + items[items.length - 1] : items[0];
    return { list, matches };
  }

  // Personal requests with extra red flags around them.
  function checkRequestContext(ctx) {
    const asks = personalAsks(ctx);
    if (!asks) return;
    // Both real-world scams that slipped through had a blank subject line.
    if (!ctx.email.subject.trim()) {
      addFinding(ctx, 'no_subject_request', {
        kind: 'other', title: 'No subject line, but asks for something personal',
        explanation: `This email has no subject yet asks for ${asks.list}. Scammers often send short, subject-less messages so they look like a quick note from someone you know.`,
        matches: asks.matches.slice(0, 2)
      });
    }
    // Sender address couldn't be read: we can't tell coworker from stranger, so say so.
    if (!ctx.sender) {
      const f = addFinding(ctx, 'unverified_request', {
        kind: 'sender', title: "Asks for something personal, and the sender couldn't be checked",
        explanation: `This email asks for ${asks.list}, but Off the Hook couldn't read the sender's email address to check who really sent it. ` +
          `Even if the name looks familiar, ask the person in person (or call a number you already know) before sending anything.`,
        matches: asks.matches.slice(0, 3)
      });
      f.floor = 'suspicious';
    }
  }

  function checkInternalCompromise(ctx) {
    const s = ctx.sender;
    if (!s || !s.internal) return;
    const asks = personalAsks(ctx);
    if (!asks) return;
    const who = s.name || s.address;
    const list = asks.list;
    const matches = asks.matches;
    const f = addFinding(ctx, 'internal_compromised', {
      kind: 'sender',
      title: 'Possibly compromised coworker account: verify in person',
      explanation: `This email comes from your own company's domain (${s.domain}) but asks for or contains ${list}. ` +
        `When a coworker's account is hacked, or their address is faked, attackers use it to ask colleagues for exactly this. ` +
        `Before you reply, click, or send anything, ask ${who} in person, or call them on a number you already know. ` +
        `Don't use a phone number or link from this email, and don't just reply to it to check. If they didn't send it, tell IT right away.`,
      matches: [s.address].concat(matches)
    });
    f.pinned = true; // shown first, never discounted
    f.floor = 'suspicious';
  }

  // ---------- warnings the webmail itself displayed ----------
  // ---------- contact memory ----------
  // ctx.lists.history describes this sender against the people you've had normal email from:
  //   { learned, addrSeen, addrEstablished, nameCount, nameAddrKnown, nameDomains: { domain: count } }
  // (built by the background worker from fingerprints; see background.js historyFor).
  function checkHistory(ctx) {
    const h = ctx.lists.history;
    const s = ctx.sender;
    if (!h || !s) return;
    if (h.addrEstablished) {
      ctx.notes.push(`You've had ${h.addrSeen} earlier email${h.addrSeen === 1 ? '' : 's'} from this address that looked normal.`);
      return;
    }
    // A familiar person's name on an address (and domain) they've never used with you.
    const usual = Object.entries(h.nameDomains || {}).sort((a, b) => b[1] - a[1]).map(([d]) => d);
    if (h.nameCount >= 2 && !h.nameAddrKnown && usual.length && !usual.includes(s.reg)) {
      const strong = s.freemail || ctx.findings.some(f => f.id === 'sender_lookalike' || f.id === 'sender_suspicious_tld' || f.id === 'sender_blocklisted');
      const first = (s.name || '').trim().split(/\s+/)[0] || 'them';
      const f = addFinding(ctx, 'history_new_address', {
        kind: 'sender',
        severity: strong ? 'high' : undefined,
        points: strong ? 40 : undefined,
        title: `${s.name} usually emails you from a different address`,
        explanation: `You've had ${h.nameCount} normal emails from "${s.name}" at ${usual.slice(0, 2).join(' / ')}, but never from ${s.address}. Scammers put a familiar name on a new account to ask for money or information. Check with ${first} using an address or phone number you already know.`,
        matches: [s.address]
      });
      f.floor = 'suspicious';
      return;
    }
    // First email ever from this address (only once enough normal mail has been learned).
    if (h.learned >= 40 && !h.addrSeen && !s.internal && !s.trusted && !s.officialBrand) {
      const asks = ctx.findings.some(f => REQUEST_RULES.includes(f.id)) || !!personalAsks(ctx);
      if (asks) {
        addFinding(ctx, 'first_contact_request', {
          kind: 'sender', title: 'First email from this sender, and it asks for something',
          explanation: `You've never had a normal email from ${s.address} before, and this one asks you to do or send something. Be extra careful with requests from people you haven't dealt with.`,
          matches: [s.address]
        });
      } else {
        addFinding(ctx, 'first_contact', {
          kind: 'sender', title: 'First email from this sender',
          explanation: `Off the Hook hasn't seen a normal email from ${s.address} before. That's fine for a new contact; just be careful with anything it asks.`,
          matches: [s.address]
        });
      }
    }
  }

  function checkProviderWarnings(ctx) {
    for (const w of ctx.email.providerWarnings) {
      if (w.level === 'high') {
        addFinding(ctx, 'webmail_warning', {
          kind: 'other', title: 'Your email service flagged this message',
          explanation: 'Gmail or Outlook showed its own warning on this email. Take that warning seriously.',
          matches: [w.text]
        });
      } else {
        addFinding(ctx, 'webmail_first_contact', {
          kind: 'other', title: 'First email from this sender',
          explanation: 'Your email service says you don\'t usually get email from this address. Most scams come from senders you have never dealt with.',
          matches: [w.text]
        });
      }
    }
  }

  // ---------- attachments ----------
  function checkAttachments(ctx) {
    for (const raw of ctx.email.attachments) {
      const name = raw.trim();
      if (!name) continue;
      const hasRtlo = /[\u202E\u202D\u200F\u061C]/.test(name);
      const clean = name.replace(/[\u202A-\u202E\u200E\u200F\u061C]/g, '').toLowerCase().replace(/\s+$/, '');
      const parts = clean.split('.');
      const ext = parts.length > 1 ? parts[parts.length - 1] : '';
      const prev = parts.length > 2 ? parts[parts.length - 2] : '';
      if (hasRtlo || (prev && DECOY_EXT.has(prev) && (RISKY_EXT.has(ext) || ARCHIVE_EXT.has(ext)))) {
        addFinding(ctx, 'attachment_double_ext', {
          kind: 'attachment', title: 'Attachment hides its real file type',
          explanation: hasRtlo
            ? 'The file name contains a hidden character that reverses text, so the real file type is disguised. Do not open it.'
            : `"${name}" looks like a .${prev} file but is really a .${ext} file. This is a classic way to sneak in malware.`,
          matches: [name]
        });
      } else if (RISKY_EXT.has(ext)) {
        addFinding(ctx, 'attachment_risky', {
          kind: 'attachment', title: 'Risky attachment type',
          explanation: 'Program files, scripts, disk images, web pages (.html/.svg) and macro-enabled Office files can install malware or open fake login pages. Do not open unless you were expecting it.',
          matches: [name]
        });
      } else if (ARCHIVE_EXT.has(ext)) {
        addFinding(ctx, 'attachment_archive', {
          kind: 'attachment', title: 'Compressed archive attached',
          explanation: 'Zip and other archives can hide dangerous files from email scanners. Only open them if you expected the file.',
          matches: [name]
        });
      }
    }
  }

  // ---------- authentication headers (if available) ----------
  function checkHeaders(ctx) {
    checkRawHeaders(ctx);
    const h = ctx.email.authResults;
    if (!h) return;
    const results = {};
    // compauth = Microsoft's combined "is the sender who they claim to be" verdict.
    const re = /\b(spf|dkim|dmarc|compauth)\s*=\s*([a-z]+)/gi;
    let m;
    while ((m = re.exec(h))) {
      const k = m[1].toLowerCase(), v = m[2].toLowerCase();
      // Keep the worst result per mechanism (several DKIM signatures may exist).
      const rank = v === 'pass' || v === 'softpass' || v === 'bestguesspass' ? 0 : v === 'none' || v === 'neutral' ? 1 : v === 'softfail' || v === 'temperror' ? 2 : 3;
      if (!(k in results) || rank > results[k].rank) results[k] = { v, rank };
    }
    // "compauth=none" just means Microsoft didn't need to decide; don't call that weak.
    if (results.compauth && results.compauth.rank === 1) delete results.compauth;
    const summary = Object.keys(results).map(k => `${k.toUpperCase()}=${results[k].v}`);
    if (!summary.length) return;
    ctx.authResults = Object.fromEntries(Object.entries(results).map(([k, v]) => [k, v.v]));
    const fails = Object.keys(results).filter(k => results[k].rank >= 3 && results[k].v !== 'temperror');
    const weak = Object.keys(results).filter(k => results[k].rank === 2 || (k === 'dmarc' && results[k].rank === 1));
    if (fails.length) {
      ctx.authFailed = true;
      addFinding(ctx, 'auth_fail', {
        kind: 'header', title: 'Sender authentication failed',
        explanation: `The email failed ${fails.map(f => f.toUpperCase()).join(' and ')} checks, meaning the sending server was not authorized to send for this domain. The "From" address may be forged.`,
        matches: summary
      });
    } else if (weak.length) {
      addFinding(ctx, 'auth_weak', {
        kind: 'header', title: 'Sender authentication is weak or missing',
        explanation: 'Some sender verification checks (SPF/DKIM/DMARC) were not passed cleanly. That is common for small senders but also for spoofed mail.',
        matches: summary
      });
    } else {
      ctx.notes.push(`Sender authentication passed (${summary.join(', ')}).`);
    }
  }

  // ---------- raw header lines (Outlook "View message details", Gmail "Show original") ----------
  const MS_CATEGORIES = {
    PHSH: 'phishing', HPHSH: 'high-confidence phishing', GIMP: 'impersonation', UIMP: 'user impersonation',
    DIMP: 'domain impersonation', SPOOF: 'spoofing', MALW: 'malware', HPHISH: 'high-confidence phishing'
  };
  function checkRawHeaders(ctx) {
    const h = ctx.email.headers;
    if (!h || !Object.keys(h).length) return;
    ctx.headerChecked = true;
    const first = k => (h[k] && h[k][0]) || '';
    const s = ctx.sender;

    // Where Microsoft 365 says the message came from: "Internal" (inside your organization),
    // "Anonymous" (from the internet), "Partner"…
    const authAs = (first('x-ms-exchange-organization-authas') || first('x-ms-exchange-crosstenant-authas')).trim().toLowerCase();
    ctx.headerAuthAs = authAs;
    if (s && s.internal && authAs === 'anonymous') {
      // Your company's address, but it arrived from outside: the address is faked.
      ctx.findings = ctx.findings.filter(f => f.id !== 'internal_compromised');
      const f = addFinding(ctx, 'spoofed_internal', {
        kind: 'header', title: 'Fake coworker address: sent from outside your company',
        explanation: `This email shows your company's address (${s.address}), but the message header says it came from outside your organization. That means the address was faked. Don't reply or act on it; report it to IT.`,
        matches: [s.address, 'AuthAs: Anonymous']
      });
      f.pinned = true; f.floor = 'phishing';
    } else if (s && s.internal && authAs === 'internal') {
      const comp = ctx.findings.find(f => f.id === 'internal_compromised');
      if (comp) {
        comp.explanation = comp.explanation.replace("When a coworker's account is hacked, or their address is faked, attackers",
          "The message header confirms it really came from inside your company's email system, so if this request is unusual the account itself may be hacked. Attackers who take over an account");
      }
      ctx.notes.push("Message header confirms this was sent from inside your company's email system.");
    }

    // Microsoft's own filter verdict, recorded in the header even when no banner is shown.
    const report = first('x-forefront-antispam-report') + ';' + first('x-microsoft-antispam');
    const cat = ((report.match(/\bCAT:([A-Z]+)/i) || [])[1] || '').toUpperCase();
    const sclRaw = first('x-ms-exchange-organization-scl') || (report.match(/\bSCL:(-?\d+)/i) || [])[1] || '';
    const scl = parseInt(sclRaw, 10);
    if (MS_CATEGORIES[cat]) {
      const f = addFinding(ctx, 'provider_verdict', {
        kind: 'header', title: `Microsoft's filter flagged this as ${MS_CATEGORIES[cat]}`,
        explanation: `The message header shows Microsoft's email filter categorized this message as ${MS_CATEGORIES[cat]} (CAT:${cat}). Treat it as dangerous even if it landed in your inbox.`,
        matches: ['CAT:' + cat]
      });
      f.floor = 'suspicious';
    } else if (cat === 'SPM' || cat === 'HSPM' || cat === 'BULK' || (!isNaN(scl) && scl >= 5)) {
      addFinding(ctx, 'provider_spam', {
        kind: 'header', title: 'Microsoft rated this as spam',
        explanation: `Microsoft's filter scored this message as ${cat === 'BULK' ? 'bulk mail' : 'spam'}${!isNaN(scl) ? ` (spam level ${scl} out of 9)` : ''}. Spam and phishing often come from the same senders.`,
        matches: [cat ? 'CAT:' + cat : 'SCL:' + scl]
      });
    }

    // Hidden bounce address on a different domain, without DMARC vouching for the From domain.
    const rp = D.domainOfEmail((first('return-path').match(/<([^>]*)>/) || [null, first('return-path')])[1].trim());
    const dmarcPass = /\bdmarc\s*=\s*pass\b/i.test(ctx.email.authResults || '');
    if (s && rp && !dmarcPass) {
      const rpReg = D.registrableDomain(rp);
      const sameBrand = s.officialBrand && brands().some(b => b.name === s.officialBrand && D.isOfficial(b, rpReg, true));
      if (rpReg !== s.reg && !sameBrand && !D.inList(rp, CONFIG.TRACKER_DOMAINS)) {
        addFinding(ctx, 'return_path_mismatch', {
          kind: 'header', title: 'Hidden sender address is on a different domain',
          explanation: `The email says it's from ${s.domain}, but the hidden "Return-Path" address (where bounces go) is on ${rpReg}, and DMARC didn't confirm the From address. Spoofed mail often looks like this.`,
          matches: [rp]
        });
      }
    }
    function brands() { return ctx.brands; }
  }

  // ---------- image-only / QR ----------
  function checkImages(ctx) {
    const { email } = ctx;
    if (!email.imageCount) return;
    const words = email.body.replace(/\s+/g, ' ').trim();
    const qr = /\bqr[\s-]?code\b/i.test(words) || /\bscan\b/i.test(words) || email.imageAlts.some(a => /\bqr\b/i.test(a)) || email.links.some(l => l.qr);
    if (words.length < 120 || (qr && words.length < 400)) {
      addFinding(ctx, 'image_only', {
        kind: 'other',
        title: qr ? 'Email relies on a QR code or image' : 'Email is mostly images with little text',
        explanation: qr
          ? 'Phishers put links inside QR codes or pictures because text scanners cannot read them. Do not scan QR codes from unexpected emails.'
          : 'Messages made almost entirely of images can hide their real content from filters. Be cautious if you did not expect it.',
        matches: qr ? ['QR code'] : [`${email.imageCount} image(s), ${words.length} characters of text`]
      });
    }
  }

  // ---------- scoring ----------
  function verdictFor(score, sensitivity) {
    const t = CONFIG.THRESHOLDS[sensitivity] || CONFIG.THRESHOLDS.medium;
    return score >= t.phishing ? 'phishing' : score >= t.suspicious ? 'suspicious' : 'safe';
  }

  function summarize(verdict, findings, notes) {
    if (!findings.length) {
      return 'Off the Hook found none of the common warning signs it checks for. That does not guarantee the email is safe.';
    }
    if (findings.some(f => f.id === 'internal_compromised')) {
      return "This came from your company's own domain but asks for something personal or risky. The account may be compromised: ask the sender in person (or call a number you already know) before you reply, click, or send anything.";
    }
    const high = findings.filter(f => f.severity === 'high');
    // Lowercase only the first letter so brand names keep their capitals.
    const top = (high.length ? high : findings).slice(0, 3).map(f => f.title.replace(/\.$/, '')).map(t => t.charAt(0).toLowerCase() + t.slice(1));
    const lead = verdict === 'phishing' ? 'This email shows strong signs of phishing.'
      : verdict === 'suspicious' ? 'This email has some warning signs.'
      : 'Only minor warning signs were found.';
    return `${lead} Main concerns: ${top.join('; ')}.` + (notes.some(n => /trusted/i.test(n)) ? ' The sender is on your trusted list.' : '');
  }

  function analyze(emailData, settings, lists) {
    const t0 = now();
    settings = settings || {};
    lists = lists || {};
    const ctx = {
      email: normalizeEmail(emailData),
      settings,
      lists,
      brands: (lists.brands && lists.brands.brands) || [],
      trust: makeTrust(settings.trustedDomains),
      company: makeCompany(settings.companyDomains, (lists.brands && lists.brands.brands) || []),
      memory: lists.memory || null,
      quieted: [],
      findings: [],
      notes: [],
      linkReport: [],
      sender: null,
      authFailed: false
    };

    checkSender(ctx);
    if (!ctx.email.headersOnly) {
      checkLinks(ctx);
      checkContent(ctx);
      checkAttachments(ctx);
      checkImages(ctx);
      checkFreemailCombos(ctx);
      checkInternalCompromise(ctx);
      checkRequestContext(ctx);
      checkHistory(ctx);
    }
    checkProviderWarnings(ctx);
    checkHeaders(ctx);
    applyMemory(ctx);

    // Everyday office wording ("past due", "are you free", "text me") from your own company's
    // domain counts much less. Anything personal or risky already raised internal_compromised.
    if (ctx.sender && ctx.sender.internal) {
      const soft = ctx.findings.filter(f => ['kw_urgency', 'kw_money', 'kw_authority', 'kw_contact_request', 'kw_generic_greeting'].includes(f.id));
      for (const f of soft) f.points = Math.round(f.points * CONFIG.SCORING.trustedSenderMultiplier);
      if (soft.length) ctx.notes.push("Sent from your company's domain, so everyday office wording counts less.");
    }

    const sumPoints = list => list.reduce((s, f) => s + f.points, 0);
    let score = sumPoints(ctx.findings.filter(f => !f.pinned));
    if (ctx.sender && ctx.sender.trusted && !ctx.authFailed) {
      score *= CONFIG.SCORING.trustedSenderMultiplier;
      ctx.notes.push(`${ctx.sender.address} is on your trusted senders list, so the score was reduced.`);
    }
    score += sumPoints(ctx.findings.filter(f => f.pinned));
    // Some findings guarantee a minimum verdict (compromised coworker, reported sender...).
    const t = CONFIG.THRESHOLDS[settings.sensitivity] || CONFIG.THRESHOLDS.medium;
    for (const f of ctx.findings) {
      if (f.floor === 'phishing') score = Math.max(score, t.phishing);
      else if (f.floor === 'suspicious') score = Math.max(score, t.suspicious);
    }
    score = Math.max(0, Math.min(100, Math.round(score)));
    const verdict = verdictFor(score, settings.sensitivity);

    ctx.findings.sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0) ||
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.points - a.points);
    if (ctx.email.headersOnly) ctx.notes.push('Only the message headers were analyzed on this page.');

    return {
      score,
      verdict,
      verdictLabel: CONFIG.VERDICT_LABELS[verdict],
      summary: summarize(verdict, ctx.findings, ctx.notes),
      findings: ctx.findings,
      quieted: ctx.quieted,
      links: ctx.linkReport,
      notes: ctx.notes,
      sender: ctx.sender,
      unreadSender: ctx.unreadSender || null,
      auth: ctx.authResults || null,
      headerChecked: !!ctx.headerChecked,
      headerAuthAs: ctx.headerAuthAs || null,
      elapsedMs: Math.round((now() - t0) * 10) / 10
    };
  }

  /**
   * Inbox list row: only the sender, subject and preview line are visible before the email is
   * opened, so links and attachments are never part of this check. Returns a compact result
   * for the row tag (no email text).
   * @param {{ from, subject, body, providerWarnings? }} row  body = the preview line
   */
  function analyzePreview(row, settings, lists) {
    const r = row || {};
    const result = analyze({
      from: r.from, subject: r.subject, body: String(r.body || '').slice(0, 1000),
      links: [], attachments: [], providerWarnings: r.providerWarnings
    }, settings, lists);
    return {
      score: result.score,
      verdict: result.verdict,
      verdictLabel: result.verdictLabel,
      reasons: result.findings.slice(0, 5).map(f => ({ id: f.id, severity: f.severity, title: f.title }))
    };
  }

  return { analyze, analyzePreview, verdictFor, compilePhrases, findPhrases, normalizeEmail };
});
