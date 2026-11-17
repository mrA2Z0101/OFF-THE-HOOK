/*
 * User feedback ("It's phishing" / "It's safe" reports) and the local memory built from it.
 * Pure functions; storage and messaging live in background.js and the options page.
 *
 * Report shape (stored in chrome.storage.local under "feedback": { version, reports: [] }):
 *   { id, key, type: 'phish'|'safe', at, site, sender: { address, name }, subject,
 *     linkDomains: [], findingIds: [], verdict, score, phrases: [], note, text? }
 *
 * Memory (passed to the analyzer as lists.memory):
 *   { phishSenders: {addr: reportId}, phishDomains: {reg: reportId}, phishLinkDomains: {reg: reportId},
 *     phrases: [string], quiet: {addr: [ruleId]}, reportedKeys: {key: {id, type, at}} }
 */
(function (root, factory) {
  const isNode = typeof module === 'object' && module.exports;
  const deps = isNode
    ? { config: require('./config.js'), domain: require('./domain-utils.js') }
    : root.PhishGuard;
  const mod = factory(deps.config, deps.domain);
  if (isNode) module.exports = mod;
  else root.PhishGuard.feedback = mod;
})(typeof globalThis !== 'undefined' ? globalThis : this, function (CONFIG, D) {
  'use strict';

  const MAX_REPORTS = 2000;
  const MAX_PHRASES = 10;

  // Warnings that a "safe" report can never quiet: they matter most when an account is
  // actually hacked or a message is actively dangerous.
  const NEVER_QUIET = new Set([
    'internal_compromised', 'auth_fail', 'webmail_warning', 'attachment_double_ext', 'link_script_scheme',
    'kw_ai_manipulation', 'reported_sender', 'reported_domain', 'reported_link',
    'spoofed_internal', 'provider_verdict', 'link_blocklisted', 'sender_blocklisted'
  ]);

  // Domains shared by many unrelated senders/sites: never blocked as a whole domain.
  const SHARED_DOMAINS = new Set([
    'onmicrosoft.com', 'sharepoint.com', 'amazonaws.com', 'amazonses.com', 'googleusercontent.com',
    'google.com', 'microsoft.com', 'office.com', 'live.com', 'azurewebsites.net', 'windows.net',
    'cloudfront.net', 'github.io', 'firebaseapp.com', 'web.app', 'pages.dev', 'netlify.app',
    'vercel.app', 'herokuapp.com', 'wixsite.com', 'weebly.com', 'blogspot.com', 'wordpress.com',
    'squarespace.com', 'godaddysites.com', 'notion.site', 'forms.gle', 'docs.google.com',
    'dropbox.com', 'box.com', 'wetransfer.com', 'canva.com', 'adobe.com', 'docusign.net'
  ]);

  // ---- keys / ids ----
  function fnv1a(str, seed) {
    let h = seed >>> 0;
    for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
    return h.toString(16).padStart(8, '0');
  }
  // Identifies "this email" across re-opens without storing its text.
  function reportKey(email) {
    const e = email || {};
    const s = [String((e.from && e.from.address) || '').toLowerCase(), String(e.subject || '').trim(),
      String(e.body || '').replace(/\s+/g, ' ').trim().slice(0, 500)].join('\u0001');
    return fnv1a(s, 2166136261) + fnv1a(s, 0x9747b28c);
  }
  function newId() {
    return 'r_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8);
  }

  const str = (v, max) => (typeof v === 'string' ? v : v == null ? '' : String(v)).slice(0, max);

  function cleanPhrases(list) {
    const out = [];
    for (const p of Array.isArray(list) ? list : []) {
      const t = str(p, 200).replace(/\s+/g, ' ').trim();
      if (t.length >= 3 && t.length <= 120 && !out.some(x => x.toLowerCase() === t.toLowerCase())) out.push(t);
      if (out.length >= MAX_PHRASES) break;
    }
    return out;
  }

  /** Build a report from the open email and its analysis. */
  function makeReport(type, email, result, extras) {
    const x = extras || {};
    const links = (result && result.links) || [];
    const linkDomains = Array.from(new Set(links.map(l => l.domain).filter(Boolean).map(d => D.registrableDomain(D.lower(d))))).slice(0, 30);
    const findingIds = Array.from(new Set(((result && result.findings) || []).concat((result && result.quieted) || []).map(f => f.id)));
    const report = {
      id: newId(),
      key: reportKey(email),
      type: type === 'phish' ? 'phish' : 'safe',
      at: new Date().toISOString(),
      site: str(x.site, 20),
      sender: { address: str(email && email.from && email.from.address, 200).toLowerCase(), name: str(email && email.from && email.from.name, 200) },
      subject: str(email && email.subject, 200),
      linkDomains,
      findingIds,
      verdict: str(result && result.verdict, 20),
      score: Number(result && result.score) || 0,
      phrases: type === 'phish' ? cleanPhrases(x.phrases) : [],
      note: str(x.note, 500)
    };
    if (x.saveText) {
      // With "save text" on, keep what's needed to re-check the email later (scoreboard).
      report.text = str(email && email.body, 20000);
      report.links = ((email && email.links) || []).slice(0, 50).map(l => ({ text: str(l.text, 200), href: str(l.href, 2000) }));
      report.attachments = ((email && email.attachments) || []).slice(0, 20).map(a => str(a, 200));
    }
    return report;
  }

  /** Validate a report coming from storage or an imported file. Returns null if unusable. */
  function sanitizeReport(r) {
    if (!r || typeof r !== 'object') return null;
    const type = r.type === 'phish' ? 'phish' : r.type === 'safe' ? 'safe' : null;
    const address = str(r.sender && r.sender.address, 200).toLowerCase().trim();
    if (!type || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) return null;
    const at = new Date(r.at);
    const out = {
      id: /^r_[a-z0-9_]{4,40}$/.test(r.id) ? r.id : newId(),
      key: /^[0-9a-f]{16}$/.test(r.key) ? r.key : '',
      type,
      at: isNaN(at) ? new Date().toISOString() : at.toISOString(),
      site: str(r.site, 20),
      sender: { address, name: str(r.sender && r.sender.name, 200) },
      subject: str(r.subject, 200),
      linkDomains: (Array.isArray(r.linkDomains) ? r.linkDomains : []).map(d => str(d, 253).toLowerCase()).filter(d => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)).slice(0, 30),
      findingIds: (Array.isArray(r.findingIds) ? r.findingIds : []).map(i => str(i, 60)).filter(i => /^[a-z_]+$/.test(i)).slice(0, 60),
      verdict: str(r.verdict, 20),
      score: Math.max(0, Math.min(100, Number(r.score) || 0)),
      phrases: type === 'phish' ? cleanPhrases(r.phrases) : [],
      note: str(r.note, 500)
    };
    if (typeof r.text === 'string' && r.text) {
      out.text = r.text.slice(0, 20000);
      out.links = (Array.isArray(r.links) ? r.links : []).slice(0, 50)
        .filter(l => l && typeof l.href === 'string').map(l => ({ text: str(l.text, 200), href: str(l.href, 2000) }));
      out.attachments = (Array.isArray(r.attachments) ? r.attachments : []).slice(0, 20).map(a => str(a, 200));
    }
    return out;
  }

  /** Merge reports (dedupe by id), newest last, capped. */
  function mergeReports(existing, incoming) {
    const byId = new Map();
    for (const r of (existing || []).concat(incoming || [])) {
      const s = sanitizeReport(r);
      if (s) byId.set(s.id, s);
    }
    const all = Array.from(byId.values()).sort((a, b) => a.at.localeCompare(b.at));
    return all.slice(-MAX_REPORTS);
  }

  /**
   * Turn reports into the memory the analyzer uses. Later reports override earlier ones
   * (reporting a sender "safe" after "phishing" un-flags it, and vice versa).
   * @param {Array} reports
   * @param {{ companyDomains?: string[], brands?: Array }} ctx  used to avoid blocking shared domains
   */
  function buildMemory(reports, ctx) {
    const c = ctx || {};
    const brands = c.brands || [];
    const company = (c.companyDomains || []).map(d => D.registrableDomain(D.lower(String(d).replace(/^.*@/, ''))));
    const protectedDomain = reg =>
      !reg || SHARED_DOMAINS.has(reg) || CONFIG.FREEMAIL_DOMAINS.includes(reg) || CONFIG.URL_SHORTENERS.includes(reg) ||
      CONFIG.TRACKER_DOMAINS.some(t => D.hostMatches(reg, t) || D.hostMatches(t, reg)) ||
      company.includes(reg) || brands.some(b => D.isOfficial(b, reg, true));

    const mem = { phishSenders: {}, phishDomains: {}, phishLinkDomains: {}, phrases: [], quiet: {}, reportedKeys: {} };
    const sorted = (reports || []).slice().sort((a, b) => String(a.at).localeCompare(String(b.at)));
    for (const r of sorted) {
      const addr = r.sender && r.sender.address;
      if (!addr) continue;
      const reg = D.registrableDomain(D.domainOfEmail(addr));
      if (r.key) mem.reportedKeys[r.key] = { id: r.id, type: r.type, at: r.at };
      if (r.type === 'phish') {
        mem.phishSenders[addr] = r.id;
        delete mem.quiet[addr];
        if (!protectedDomain(reg)) mem.phishDomains[reg] = r.id;
        for (const d of r.linkDomains || []) if (!protectedDomain(d) && d !== reg) mem.phishLinkDomains[d] = r.id;
        if (!protectedDomain(reg)) mem.phishLinkDomains[reg] = r.id;
        for (const p of r.phrases || []) if (!mem.phrases.some(x => x.toLowerCase() === p.toLowerCase())) mem.phrases.push(p);
      } else {
        delete mem.phishSenders[addr];
        delete mem.phishDomains[reg];
        for (const d of r.linkDomains || []) delete mem.phishLinkDomains[d];
        const q = new Set(mem.quiet[addr] || []);
        for (const id of r.findingIds || []) if (!NEVER_QUIET.has(id)) q.add(id);
        mem.quiet[addr] = Array.from(q);
      }
    }
    return mem;
  }

  /** Which of a result's findings a "safe" report would quiet (for the confirmation text). */
  function quietableFindings(result) {
    return ((result && result.findings) || []).filter(f => !NEVER_QUIET.has(f.id));
  }

  return { reportKey, makeReport, sanitizeReport, mergeReports, buildMemory, quietableFindings, NEVER_QUIET, MAX_REPORTS };
});
