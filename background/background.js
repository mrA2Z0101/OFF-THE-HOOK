/*
 * Off the Hook background service worker.
 *
 * - Runs the rule-based analyzer for content scripts (email never leaves the browser).
 * - Downloads public scam-site lists once a day (only the lists; nothing about email is sent).
 * - In AI mode (opt-in), sends a sanitized copy of the email to the user's configured
 *   provider. All AI network calls happen here, never in content scripts.
 * - Keeps a minimal per-tab verdict (no email text) for the toolbar popup and badge.
 */
'use strict';

// Chrome/Edge load this file as a service worker; Firefox loads the shared scripts first
// via manifest "background.scripts" (see scripts/build_firefox.py).
if (typeof importScripts === 'function' && !(self.PhishGuard && self.PhishGuard.analyzer)) {
  importScripts(
    '../shared/config.js',
    '../shared/domain-utils.js',
    '../shared/analyzer.js',
    '../shared/ai-utils.js',
    '../shared/feedback.js',
    '../shared/qr.js',
    '../shared/blocklist.js',
    'providers.js'
  );
}

const PG = self.PhishGuard;
const CONFIG = PG.config;
const VERDICT_COLORS = { safe: '#2e7d32', suspicious: '#e65100', phishing: '#c62828' };
const PROVIDER_LABELS = { openai: 'OpenAI-compatible', anthropic: 'Anthropic', ollama: 'Ollama (local)' };

// ---------- settings ----------
async function getSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  return CONFIG.mergeSettings(settings);
}

async function getSecrets() {
  const { secrets } = await chrome.storage.local.get('secrets');
  return secrets || {};
}

// What content scripts and the popup are allowed to see (never API keys).
function publicSettings(s) {
  return {
    sensitivity: s.sensitivity,
    highlight: s.highlight,
    ui: s.ui,
    replyGuard: s.replyGuard,
    ai: { enabled: aiActive(s), provider: s.ai.provider, providerLabel: PROVIDER_LABELS[s.ai.provider] || s.ai.provider }
  };
}

function aiActive(s) {
  return !!(s.ai && s.ai.enabled && s.ai.privacyAccepted);
}

// ---------- lists ----------
let listsPromise = null;
function getLists() {
  if (!listsPromise) {
    const load = path => fetch(chrome.runtime.getURL(path)).then(r => {
      if (!r.ok) throw new Error('Could not load ' + path);
      return r.json();
    });
    listsPromise = Promise.all([load('data/keywords.json'), load('data/brands.json')])
      .then(([keywords, brands]) => ({ keywords, brands }))
      .catch(err => { listsPromise = null; throw err; });
  }
  return listsPromise;
}

// ---------- feedback reports and the memory built from them ----------
async function getReports() {
  const { feedback } = await chrome.storage.local.get('feedback');
  return (feedback && Array.isArray(feedback.reports)) ? feedback.reports : [];
}
async function saveReports(reports) {
  await chrome.storage.local.set({ feedback: { version: 1, reports: PG.feedback.mergeReports([], reports) } });
  memoryCache = null;
}

let memoryCache = null; // { key, value }
async function getMemory(settings, lists) {
  const reports = await getReports();
  const key = reports.length + '|' + (reports.length ? reports[reports.length - 1].id : '') + '|' + (settings.companyDomains || []).join(',');
  if (memoryCache && memoryCache.key === key) return memoryCache.value;
  const value = PG.feedback.buildMemory(reports, { companyDomains: settings.companyDomains, brands: lists.brands.brands });
  memoryCache = { key, value };
  return value;
}
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && (changes.feedback || changes.settings)) memoryCache = null;
  // A scam-site list was switched on or off in Settings: rebuild the combined list now.
  if (area === 'local' && changes.settings) {
    const pick = v => JSON.stringify(CONFIG.mergeSettings(v).blocklists.sources);
    const was = changes.settings.oldValue, now = changes.settings.newValue;
    if (was && now && pick(was) !== pick(now) && CONFIG.mergeSettings(now).blocklists.enabled) updateBlocklists().catch(() => {});
  }
});

async function analyzeWithMemory(email, settings) {
  const lists = await getLists();
  const memory = await getMemory(settings, lists);
  const blocklist = await getBlocklist(settings);
  const history = settings.history && settings.history.enabled ? await historyFor(email) : null;
  const result = PG.analyzer.analyze(email, settings, Object.assign({ memory, blocklist, history }, lists));
  result.reported = memory.reportedKeys[PG.feedback.reportKey(email)] || null;
  return result;
}

// ---------- known-bad site lists (downloaded daily, checked on this computer) ----------
// Only the public lists are downloaded; nothing about your email is sent. The combined list
// is kept as ~5 MB of fingerprints in the extension's cache storage.
const BL_CACHE = 'off-the-hook-blocklist';
const BL_KEY = 'https://off-the-hook.invalid/blocklist.bin';
const BL_MAX_AGE = 24 * 3600 * 1000;
let blocklist = null, blocklistLoading = null, blocklistUpdating = null;

async function getBlocklist(settings) {
  if (!settings.blocklists || !settings.blocklists.enabled) return null;
  maybeUpdateBlocklists().catch(() => {});
  if (blocklist) return blocklist;
  if (!blocklistLoading) {
    blocklistLoading = (async () => {
      try {
        const hit = await (await caches.open(BL_CACHE)).match(BL_KEY);
        if (hit) blocklist = PG.blocklist.create(PG.blocklist.deserialize(await hit.arrayBuffer()));
      } catch (e) { /* no list yet */ }
      return blocklist;
    })().finally(() => { blocklistLoading = null; });
  }
  return blocklistLoading;
}

async function maybeUpdateBlocklists() {
  if (blocklistUpdating) return;
  const { blocklistMeta } = await chrome.storage.local.get('blocklistMeta');
  if (!blocklistMeta || Date.now() - (blocklistMeta.checked || 0) > BL_MAX_AGE) updateBlocklists().catch(() => {});
}

function updateBlocklists() {
  if (blocklistUpdating) return blocklistUpdating;
  blocklistUpdating = (async () => {
    const { blocklistMeta: old } = await chrome.storage.local.get('blocklistMeta');
    const meta = { checked: Date.now(), updated: old && old.updated, total: old && old.total, sources: [] };
    const settings = await getSettings();
    const on = (settings.blocklists && settings.blocklists.sources) || {};
    // Big shared sites never go in, even when a list names one bad page on them.
    const skip = PG.blocklist.neverMatcher([].concat(CONFIG.BLOCKLIST_NEVER || [], CONFIG.SHARED_PLATFORMS || [], CONFIG.URL_SHORTENERS || []));
    const got = [];
    let wanted = 0;
    for (const src of CONFIG.BLOCKLIST_SOURCES) {
      if (on[src.id] === false) { meta.sources.push({ id: src.id, name: src.name, off: true }); continue; }
      wanted++;
      try {
        const resp = await fetch(src.url, { cache: 'no-store', credentials: 'omit' });
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const text = await resp.text();
        if (text.length > 60 * 1024 * 1024) throw new Error('List too large');
        const hosts = PG.blocklist.parse(text, src.format, skip);
        if (hosts.length < 10) throw new Error('The list came back empty');
        got.push({ name: src.name, hosts });
        meta.sources.push({ id: src.id, name: src.name, ok: true, count: hosts.length });
      } catch (e) {
        meta.sources.push({ id: src.id, name: src.name, ok: false, error: String((e && e.message) || e) });
      }
    }
    if (got.length) {
      const set = PG.blocklist.build(got);
      await (await caches.open(BL_CACHE)).put(BL_KEY, new Response(PG.blocklist.serialize(set)));
      blocklist = PG.blocklist.create(set);
      meta.updated = Date.now();
      meta.total = set.n;
    } else if (!wanted) {
      // Every list switched off: drop the old copy. (If downloads just failed, the old copy is kept.)
      await caches.delete(BL_CACHE).catch(() => {});
      blocklist = null;
      meta.updated = 0;
      meta.total = 0;
    }
    await chrome.storage.local.set({ blocklistMeta: meta });
    return meta;
  })().finally(() => { blocklistUpdating = null; });
  return blocklistUpdating;
}

// ---------- contact memory (who you've had normal email from) ----------
// Addresses and names are stored only as salted fingerprints; the usual *domain* for a name
// is kept in plain text so a warning can say "usually emails you from yourcompany.com".
// An address counts as known after 3 normal emails on different days (or an "It's safe" report),
// so a scammer can't build trust with one harmless first message.
const HISTORY_MAX = 5000;
const ESTABLISH_GAP = 20 * 3600 * 1000;
const ROLE_WORDS = /\b(team|support|service|services|admin|administrator|no-?reply|notifications?|alerts?|billing|security|helpdesk|help desk|department|dept|office|info|sales|accounts?|payroll|hr|it|customer|care|news|newsletter|updates?|mailer|system|bot|staff|desk)\b/i;
let historyCache = null;

function personName(name) {
  const t = String(name || '').replace(/["“”()]/g, '').replace(/\s+/g, ' ').trim().toLowerCase();
  if (t.length < 5 || t.length > 60 || ROLE_WORDS.test(t)) return '';
  return /^[a-zÀ-ɏ][a-zÀ-ɏ.'’-]*(\s[a-zÀ-ɏ][a-zÀ-ɏ.'’-]*){1,3}$/.test(t) ? t : '';
}
async function fingerprint(salt, value) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(salt + '|' + value));
  return Array.from(new Uint8Array(buf).slice(0, 12), b => b.toString(16).padStart(2, '0')).join('');
}
async function loadHistory() {
  if (historyCache) return historyCache;
  const { contacts } = await chrome.storage.local.get('contacts');
  if (contacts && contacts.v === 1) historyCache = contacts;
  else {
    const salt = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
    historyCache = { v: 1, salt, learned: 0, addrs: {}, names: {}, recent: [] };
  }
  return historyCache;
}
const established = rec => !!rec && (!!rec.est || (rec.n >= 3 && rec.l - rec.f > ESTABLISH_GAP));

async function historyFor(email) {
  const addr = String((email && email.from && email.from.address) || '').toLowerCase();
  if (!addr) return null;
  const hist = await loadHistory();
  const aKey = await fingerprint(hist.salt, 'a:' + addr);
  const rec = hist.addrs[aKey];
  const nm = personName(email.from.name);
  const nRec = nm ? hist.names[await fingerprint(hist.salt, 'n:' + nm)] : null;
  return {
    learned: hist.learned, addrSeen: rec ? rec.n : 0, addrEstablished: established(rec),
    nameCount: nRec ? nRec.n : 0, nameAddrKnown: !!nRec && nRec.addrs.includes(aKey), nameDomains: nRec ? nRec.doms : {}
  };
}

async function learnContact(email, trustNow) {
  const addr = String((email && email.from && email.from.address) || '').toLowerCase();
  if (!addr || !addr.includes('@')) return;
  const hist = await loadHistory();
  const key = PG.feedback.reportKey(email);
  if (hist.recent.includes(key) && !trustNow) return; // re-opening the same email doesn't count twice
  hist.recent.push(key);
  if (hist.recent.length > 500) hist.recent.splice(0, hist.recent.length - 500);
  const now = Date.now();
  const aKey = await fingerprint(hist.salt, 'a:' + addr);
  const rec = hist.addrs[aKey] || { n: 0, f: now, l: now };
  rec.n++; rec.l = now;
  if (trustNow) rec.est = true;
  hist.addrs[aKey] = rec;
  hist.learned++;
  const nm = personName(email.from.name);
  if (nm && established(rec)) {
    const nKey = await fingerprint(hist.salt, 'n:' + nm);
    const nRec = hist.names[nKey] || { n: 0, doms: {}, addrs: [] };
    nRec.n++;
    const reg = PG.domain.registrableDomain(PG.domain.domainOfEmail(addr));
    if (reg) nRec.doms[reg] = (nRec.doms[reg] || 0) + 1;
    if (!nRec.addrs.includes(aKey)) nRec.addrs = nRec.addrs.concat(aKey).slice(-10);
    nRec.l = now;
    hist.names[nKey] = nRec;
  }
  for (const map of [hist.addrs, hist.names]) {
    const keys = Object.keys(map);
    if (keys.length > HISTORY_MAX) keys.sort((a, b) => (map[a].l || 0) - (map[b].l || 0)).slice(0, keys.length - HISTORY_MAX).forEach(k => delete map[k]);
  }
  await chrome.storage.local.set({ contacts: hist });
}

async function forgetContact(address) {
  const addr = String(address || '').toLowerCase();
  if (!addr) return;
  const hist = await loadHistory();
  const aKey = await fingerprint(hist.salt, 'a:' + addr);
  delete hist.addrs[aKey];
  for (const n of Object.values(hist.names)) n.addrs = n.addrs.filter(k => k !== aKey);
  await chrome.storage.local.set({ contacts: hist });
}
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.contacts && !changes.contacts.newValue) historyCache = null; // cleared
});

// ---------- per-tab state (verdict only, no email content) ----------
const tabKey = id => 'tab_' + id;

async function setTabState(tabId, state) {
  if (tabId == null || tabId < 0) return;
  try {
    if (state) await chrome.storage.session.set({ [tabKey(tabId)]: state });
    else await chrome.storage.session.remove(tabKey(tabId));
  } catch (e) { /* storage.session unavailable: popup will just show "no data" */ }
  try {
    await chrome.action.setBadgeText({ tabId, text: state ? String(state.score) : '' });
    if (state) await chrome.action.setBadgeBackgroundColor({ tabId, color: VERDICT_COLORS[state.verdict] || '#555' });
    if (state && chrome.action.setBadgeTextColor) await chrome.action.setBadgeTextColor({ tabId, color: '#ffffff' });
    await chrome.action.setTitle({ tabId, title: state ? `Off the Hook: ${state.verdictLabel} (${state.score}/100)` : 'Off the Hook' });
  } catch (e) { /* tab may have closed */ }
}

async function getTabState(tabId) {
  try {
    const r = await chrome.storage.session.get(tabKey(tabId));
    return r[tabKey(tabId)] || null;
  } catch (e) { return null; }
}

function countsOf(findings) {
  const c = { high: 0, medium: 0, low: 0 };
  for (const f of findings || []) c[f.severity] = (c[f.severity] || 0) + 1;
  return c;
}

chrome.tabs.onRemoved.addListener(tabId => {
  chrome.storage.session.remove(tabKey(tabId)).catch(() => {});
});

// ---------- AI ----------
async function hasPermissionFor(provider, cfg) {
  try {
    const pattern = PG.providers.permissionPatternFor(provider, cfg);
    return await chrome.permissions.contains({ origins: [pattern] });
  } catch (e) { return false; }
}

function apiKeyFor(provider, secrets) {
  if (provider === 'anthropic') return secrets.anthropicKey || '';
  if (provider === 'openai') return secrets.openaiKey || '';
  return '';
}

async function runAI(email, ruleResult, settings) {
  const provider = settings.ai.provider;
  const cfg = settings.ai[provider] || {};
  if (!(await hasPermissionFor(provider, cfg))) {
    throw new Error('Off the Hook does not have permission to contact your AI provider yet. Open Off the Hook settings and click Save.');
  }
  const secrets = await getSecrets();
  const payload = PG.ai.buildPayload(email, ruleResult, settings.ai);
  const raw = await PG.providers.complete({
    provider,
    cfg,
    apiKey: apiKeyFor(provider, secrets),
    system: PG.ai.SYSTEM_PROMPT,
    user: PG.ai.buildUserMessage(payload),
    maxTokens: settings.ai.maxTokens,
    timeoutMs: settings.ai.timeoutSec * 1000
  });
  const parsed = PG.ai.parseAIResponse(raw, { subject: email.subject, body: email.body });
  if (!parsed.ok) throw new Error(parsed.error);
  return { ai: parsed.data, combined: PG.ai.blend(ruleResult, parsed.data, settings) };
}

async function testConnection(msg) {
  const provider = msg.provider;
  const cfg = msg.cfg || {};
  if (!(await hasPermissionFor(provider, cfg))) {
    return { ok: false, error: 'Permission to contact this address was not granted.' };
  }
  const secrets = await getSecrets();
  const apiKey = msg.apiKey || apiKeyFor(provider, secrets);
  const t0 = Date.now();
  const raw = await PG.providers.complete({
    provider, cfg, apiKey,
    system: 'You are a connectivity test. Respond with only this JSON object: {"ok": true}',
    user: 'Connectivity test. Reply with {"ok": true}',
    maxTokens: 64,
    timeoutMs: Math.max(10000, (Number(msg.timeoutSec) || 30) * 1000)
  });
  const ms = Date.now() - t0;
  if (!raw || !String(raw).trim()) return { ok: false, error: 'Connected, but the model returned an empty reply. Check the model name.' };
  let jsonOk = true;
  try { PG.ai.extractJson(raw); } catch (e) { jsonOk = false; }
  return {
    ok: true,
    message: `Connected to ${cfg.model} in ${ms} ms.` + (jsonOk ? '' : ' Note: the model did not reply in JSON; analysis may fail with this model.')
  };
}

async function clearAllData() {
  await chrome.storage.local.clear();
  historyCache = null;
  blocklist = null;
  try { await caches.delete(BL_CACHE); } catch (e) { /* ignore */ }
  try { await chrome.storage.session.clear(); } catch (e) { /* ignore */ }
  // Revoke any AI endpoint permissions granted at runtime.
  try {
    const manifest = chrome.runtime.getManifest();
    const fixed = new Set((manifest.content_scripts || []).flatMap(c => c.matches || []).concat(manifest.host_permissions || []));
    const all = await chrome.permissions.getAll();
    const extra = (all.origins || []).filter(o => !fixed.has(o));
    if (extra.length) await chrome.permissions.remove({ origins: extra });
  } catch (e) { /* ignore */ }
  const tabs = await chrome.tabs.query({});
  for (const t of tabs) chrome.action.setBadgeText({ tabId: t.id, text: '' }).catch(() => {});
  return { ok: true };
}

// ---------- QR codes in email pictures ----------
// Webmail serves email pictures from its own image servers, which the page can't read pixel by
// pixel. Only those hosts (listed in manifest host_permissions) are fetched; never the sender's.
const QR_IMAGE_HOSTS = [/(^|\.)googleusercontent\.com$/, /(^|\.)office\.net$/, /^mail\.google\.com$/,
  /^outlook\.(live|office|office365)\.com$/, /^outlook\.cloud\.microsoft$/];
const MAX_QR_IMAGE_BYTES = 8 * 1024 * 1024;

async function qrFromUrl(url) {
  let u;
  try { u = new URL(url); } catch (e) { return { ok: false, error: 'Bad address' }; }
  if (u.protocol !== 'https:' || !QR_IMAGE_HOSTS.some(re => re.test(u.hostname))) return { ok: false, error: 'Not a webmail image server' };
  const resp = await fetch(u.href, { credentials: 'include', cache: 'force-cache' });
  if (!resp.ok) return { ok: false, error: 'HTTP ' + resp.status };
  if (Number(resp.headers.get('content-length') || 0) > MAX_QR_IMAGE_BYTES) return { ok: false, error: 'Too large' };
  const blob = await resp.blob();
  if (blob.size > MAX_QR_IMAGE_BYTES) return { ok: false, error: 'Too large' };
  const bmp = await createImageBitmap(blob);
  const k = Math.min(1, 1600 / Math.max(bmp.width, bmp.height));
  const w = Math.max(1, Math.round(bmp.width * k)), h = Math.max(1, Math.round(bmp.height * k));
  const canvas = new OffscreenCanvas(w, h);
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(bmp, 0, 0, w, h);
  if (bmp.close) bmp.close();
  const r = PG.qr.decode(ctx.getImageData(0, 0, w, h));
  return { ok: true, text: r ? r.text : null };
}

// ---------- messaging ----------
function isExtensionPage(sender) {
  return sender.id === chrome.runtime.id && typeof sender.url === 'string' && sender.url.startsWith(chrome.runtime.getURL(''));
}
function isContentScript(sender) {
  return sender.id === chrome.runtime.id && !!sender.tab && !isExtensionPage(sender);
}

async function handle(msg, sender) {
  switch (msg && msg.type) {
    case 'analyze': {
      if (!isContentScript(sender)) throw new Error('Not allowed');
      const settings = await getSettings();
      const result = await analyzeWithMemory(msg.email, settings);
      const useAI = aiActive(settings) && !msg.email.headersOnly;
      // Normal-looking email from a real address: remember the sender (fingerprints only).
      if (settings.history.enabled && !msg.email.headersOnly && result.verdict === 'safe' &&
          !result.findings.some(f => f.severity === 'high') && !(result.reported && result.reported.type === 'phish')) {
        learnContact(msg.email, false).catch(() => {});
      }
      await setTabState(sender.tab.id, {
        score: result.score, verdict: result.verdict, verdictLabel: result.verdictLabel,
        counts: countsOf(result.findings), alert: result.findings.some(f => f.id === 'internal_compromised') ? 'internal_compromised' : null, mode: useAI ? 'ai' : 'rules',
        aiStatus: useAI ? 'pending' : 'off', site: msg.site || '', updated: Date.now()
      });
      return { ok: true, result, settings: publicSettings(settings), aiEnabled: useAI };
    }
    case 'analyzeList': {
      // Inbox list rows (sender, subject, preview line). Rules only, never sent to AI.
      if (!isContentScript(sender)) throw new Error('Not allowed');
      const settings = await getSettings();
      const lists = await getLists();
      const memory = await getMemory(settings, lists);
      const withMemory = Object.assign({ memory }, lists);
      withMemory.blocklist = await getBlocklist(settings);
      const rows = Array.isArray(msg.rows) ? msg.rows.slice(0, 60) : [];
      const results = [];
      for (const r of rows) {
        const history = settings.history.enabled ? await historyFor(r) : null;
        results.push(PG.analyzer.analyzePreview(r, settings, Object.assign({}, withMemory, { history })));
      }
      return { ok: true, results };
    }
    case 'analyzeAI': {
      if (!isContentScript(sender)) throw new Error('Not allowed');
      const settings = await getSettings();
      if (!aiActive(settings)) return { ok: false, error: 'AI mode is off.' };
      const prev = await getTabState(sender.tab.id);
      try {
        const out = await runAI(msg.email, msg.ruleResult, settings);
        await setTabState(sender.tab.id, Object.assign({}, prev, {
          score: out.combined.score, verdict: out.combined.verdict, verdictLabel: out.combined.verdictLabel,
          ruleScore: out.combined.ruleScore, aiScore: out.combined.aiScore, aiVerdict: out.ai.verdict,
          mode: 'ai', aiStatus: 'done', updated: Date.now()
        }));
        return { ok: true, ai: out.ai, combined: out.combined, providerLabel: PROVIDER_LABELS[settings.ai.provider] };
      } catch (e) {
        if (prev) await setTabState(sender.tab.id, Object.assign({}, prev, { aiStatus: 'failed', aiError: e.message }));
        return { ok: false, error: e.message };
      }
    }
    case 'report': {
      // "It's phishing" / "It's safe" from the on-page panel. Stored only on this computer.
      if (!isContentScript(sender)) throw new Error('Not allowed');
      const settings = await getSettings();
      const result = await analyzeWithMemory(msg.email, settings);
      const report = PG.feedback.makeReport(msg.kind, msg.email, result, {
        site: msg.site, phrases: msg.phrases, note: msg.note, saveText: !!(settings.feedback && settings.feedback.saveText)
      });
      if (!report.sender.address) return { ok: false, error: "Off the Hook couldn't read the sender's address, so this email can't be reported." };
      const reports = (await getReports()).filter(r => r.key !== report.key); // re-reporting replaces
      reports.push(report);
      await saveReports(reports);
      if (settings.history.enabled) {
        if (report.type === 'safe') await learnContact(msg.email, true).catch(() => {});
        else await forgetContact(report.sender.address).catch(() => {});
      }
      return { ok: true, report: { id: report.id, type: report.type, at: report.at } };
    }
    case 'undoReport': {
      if (!isContentScript(sender) && !isExtensionPage(sender)) throw new Error('Not allowed');
      const reports = await getReports();
      await saveReports(reports.filter(r => r.id !== msg.id));
      return { ok: true };
    }
    case 'rememberRisky': {
      // Senders rated Suspicious / Likely Phishing, shared between webmail windows for Reply
      // Guard. Session storage only (cleared when the browser closes); no email text.
      if (!isContentScript(sender)) throw new Error('Not allowed');
      const { risky = {} } = await chrome.storage.session.get('risky');
      const str = (v, n) => String(v == null ? '' : v).slice(0, n);
      for (const [k, v] of (Array.isArray(msg.entries) ? msg.entries : []).slice(0, 10)) {
        if (typeof k !== 'string' || !k || k.length > 300 || !v) continue;
        risky[k] = {
          verdict: v.verdict === 'phishing' ? 'phishing' : 'suspicious', label: str(v.label, 40),
          sender: { name: str(v.sender && v.sender.name, 200), address: str(v.sender && v.sender.address, 200) },
          internal: !!v.internal, at: Date.now()
        };
      }
      const keys = Object.keys(risky);
      if (keys.length > 300) keys.sort((a, b) => risky[a].at - risky[b].at).slice(0, keys.length - 300).forEach(k => delete risky[k]);
      await chrome.storage.session.set({ risky });
      return { ok: true };
    }
    case 'getRisky': {
      if (!isContentScript(sender)) throw new Error('Not allowed');
      const { risky = {} } = await chrome.storage.session.get('risky');
      return { ok: true, risky };
    }
    case 'qrFromUrl': {
      if (!isContentScript(sender)) throw new Error('Not allowed');
      return qrFromUrl(String(msg.url || ''));
    }
    case 'noEmail': {
      if (sender.tab) await setTabState(sender.tab.id, null);
      return { ok: true };
    }
    case 'getPublicSettings':
      return { ok: true, settings: publicSettings(await getSettings()) };
    case 'getTabState': {
      const settings = await getSettings();
      return { ok: true, state: await getTabState(msg.tabId), settings: publicSettings(settings) };
    }
    case 'openOptions':
      await chrome.runtime.openOptionsPage();
      return { ok: true };
    case 'getBlocklistStatus': {
      if (!isExtensionPage(sender)) throw new Error('Not allowed');
      const settings = await getSettings();
      const { blocklistMeta } = await chrome.storage.local.get('blocklistMeta');
      return { ok: true, enabled: !!settings.blocklists.enabled, meta: blocklistMeta || null, updating: !!blocklistUpdating };
    }
    case 'updateBlocklists': {
      if (!isExtensionPage(sender)) throw new Error('Not allowed');
      return { ok: true, meta: await updateBlocklists() };
    }
    case 'checkHosts': {
      // File checker page: which of these hosts are on the lists?
      if (!isExtensionPage(sender)) throw new Error('Not allowed');
      const bl = await getBlocklist(await getSettings());
      const hits = {};
      if (bl) for (const h of (Array.isArray(msg.hosts) ? msg.hosts : []).slice(0, 200)) { const n = bl.has(String(h)); if (n) hits[h] = n; }
      return { ok: true, enabled: !!bl, hits };
    }
    case 'getHistoryStats': {
      if (!isExtensionPage(sender)) throw new Error('Not allowed');
      const hist = await loadHistory();
      const addrs = Object.values(hist.addrs);
      return { ok: true, learned: hist.learned, senders: addrs.length, known: addrs.filter(established).length, people: Object.keys(hist.names).length };
    }
    case 'clearHistory': {
      if (!isExtensionPage(sender)) throw new Error('Not allowed');
      historyCache = null;
      await chrome.storage.local.remove('contacts');
      return { ok: true };
    }
    case 'openFileChecker':
      await chrome.tabs.create({ url: chrome.runtime.getURL('scan/scan.html') });
      return { ok: true };
    case 'testConnection':
      if (!isExtensionPage(sender)) throw new Error('Not allowed');
      return testConnection(msg);
    case 'clearAllData':
      if (!isExtensionPage(sender)) throw new Error('Not allowed');
      return clearAllData();
    default:
      return { ok: false, error: 'Unknown message' };
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handle(msg, sender).then(sendResponse, err => sendResponse({ ok: false, error: (err && err.message) || String(err) }));
  return true; // keep the channel open for the async reply
});

chrome.runtime.onInstalled.addListener(details => {
  if (details.reason === 'install') chrome.runtime.openOptionsPage().catch(() => {});
  getSettings().then(s => { if (s.blocklists.enabled) return maybeUpdateBlocklists(); }).catch(() => {});
});
if (chrome.runtime.onStartup) {
  chrome.runtime.onStartup.addListener(() => {
    getSettings().then(s => { if (s.blocklists.enabled) return maybeUpdateBlocklists(); }).catch(() => {});
  });
}
