'use strict';

const CONFIG = globalThis.PhishGuard.config;
const PROVIDERS = globalThis.PhishGuard.providers;
const $ = id => document.getElementById(id);
const KEY_FIELDS = { openai: 'openaiKey', anthropic: 'anthropicKey' };

let settings = CONFIG.mergeSettings({});
let secrets = {};
let privacyAccepted = false;

const lines = text => text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
const clampNum = (v, min, max, dflt) => { const n = Number(v); return Number.isFinite(n) ? Math.min(max, Math.max(min, Math.round(n))) : dflt; };

// Accepts "yourcompany.com", "@yourcompany.com", "alex@yourcompany.com" or a web address.
const toDomain = s => s.toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/^.*@/, '').replace(/[\/?#].*$/, '').replace(/^www\./, '').replace(/\.$/, '');
const isDomain = d => /^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/.test(d);
function cleanDomains(text) {
  return Array.from(new Set(lines(text).map(toDomain).filter(isDomain)));
}
function badDomainLines(text) {
  return lines(text).filter(l => !isDomain(toDomain(l)));
}

function setStatus(el, text, kind) {
  el.textContent = text || '';
  el.className = kind || '';
}

function currentProvider() {
  const r = document.querySelector('input[name=provider]:checked');
  return r ? r.value : 'ollama';
}

function updateProviderVisibility() {
  const p = currentProvider();
  document.querySelectorAll('.provider').forEach(el => el.classList.toggle('active', el.dataset.provider === p));
  setStatus($('testStatus'), '');
}

function updateAiState() {
  const on = $('aiEnabled').checked;
  $('aiState').textContent = on ? 'On · AI-assisted' : 'Off · rule-based only';
  $('aiState').classList.toggle('on', on);
}

function updateKeyHelp() {
  document.querySelectorAll('.keyhelp').forEach(p => {
    const has = !!secrets[p.dataset.key];
    p.textContent = has ? 'A key is saved on this computer. Leave the box blank to keep it, or type a new one to replace it.' : 'No key saved.';
  });
  document.querySelectorAll('.forget').forEach(b => { b.disabled = !secrets[b.dataset.key]; });
}

function fill() {
  const s = settings;
  $('aiEnabled').checked = !!(s.ai.enabled && s.ai.privacyAccepted);
  privacyAccepted = !!s.ai.privacyAccepted;
  document.querySelectorAll('input[name=provider]').forEach(r => { r.checked = r.value === s.ai.provider; });
  $('ollamaUrl').value = s.ai.ollama.baseUrl;
  $('ollamaModel').value = s.ai.ollama.model;
  $('openaiUrl').value = s.ai.openai.baseUrl;
  $('openaiModel').value = s.ai.openai.model;
  $('anthropicModel').value = s.ai.anthropic.model;
  $('openaiKey').value = '';
  $('anthropicKey').value = '';
  $('redact').checked = s.ai.redact !== false;
  $('fullBody').checked = !!s.ai.sendFullBody;
  $('maxTokens').value = s.ai.maxTokens;
  $('timeoutSec').value = s.ai.timeoutSec;
  $('blend').value = Math.round(s.ai.blendWeight * 100);
  $('blendOut').textContent = $('blend').value + '%';
  document.querySelectorAll('input[name=sensitivity]').forEach(r => { r.checked = r.value === s.sensitivity; });
  $('companyDomains').value = s.companyDomains.join('\n');
  $('companyStatus').textContent = s.companyDomains.length
    ? `Watching for compromised accounts and impersonation of: ${s.companyDomains.join(', ')}` : '';
  $('trustedList').value = s.trustedDomains.join('\n');
  $('customKeywords').value = s.customKeywords.join('\n');
  $('hlEnabled').checked = s.highlight.enabled !== false;
  $('linkBadges').checked = s.highlight.linkBadges !== false;
  $('linkHover').checked = s.highlight.linkHover !== false;
  $('qrRead').checked = s.highlight.qr !== false;
  $('showBadge').checked = s.ui.showBadge !== false;
  $('inboxTags').checked = s.ui.inboxTags !== false;
  $('blEnabled').checked = s.blocklists.enabled !== false;
  buildSourceRows(s);
  $('histEnabled').checked = s.history.enabled !== false;
  $('replyGuard').checked = s.replyGuard.enabled !== false;
  $('pauseSend').checked = s.replyGuard.pauseSend !== false;
  $('pauseSend').disabled = !$('replyGuard').checked;
  $('saveText').checked = !!(s.feedback && s.feedback.saveText);
  $('cHigh').value = s.highlight.colors.high;
  $('cMedium').value = s.highlight.colors.medium;
  $('cLow').value = s.highlight.colors.low;
  $('cAi').value = s.highlight.colors.ai;
  updateProviderVisibility();
  updateAiState();
  updateKeyHelp();
}

function collect() {
  const sens = document.querySelector('input[name=sensitivity]:checked');
  return {
    sensitivity: sens ? sens.value : 'medium',
    companyDomains: cleanDomains($('companyDomains').value),
    trustedDomains: lines($('trustedList').value).map(s => s.toLowerCase()),
    customKeywords: lines($('customKeywords').value),
    highlight: {
      enabled: $('hlEnabled').checked,
      linkBadges: $('linkBadges').checked,
      linkHover: $('linkHover').checked,
      qr: $('qrRead').checked,
      colors: { high: $('cHigh').value, medium: $('cMedium').value, low: $('cLow').value, ai: $('cAi').value }
    },
    ui: { showBadge: $('showBadge').checked, inboxTags: $('inboxTags').checked },
    replyGuard: { enabled: $('replyGuard').checked, pauseSend: $('pauseSend').checked },
    blocklists: {
      enabled: $('blEnabled').checked,
      sources: Object.fromEntries(CONFIG.BLOCKLIST_SOURCES.map(x => [x.id, !$('bl_' + x.id) || $('bl_' + x.id).checked]))
    },
    history: { enabled: $('histEnabled').checked },
    feedback: { saveText: $('saveText').checked },
    ai: {
      enabled: $('aiEnabled').checked,
      privacyAccepted: $('aiEnabled').checked ? privacyAccepted : settings.ai.privacyAccepted,
      provider: currentProvider(),
      openai: { baseUrl: $('openaiUrl').value.trim(), model: $('openaiModel').value.trim() },
      anthropic: { model: $('anthropicModel').value.trim() },
      ollama: { baseUrl: $('ollamaUrl').value.trim() || 'http://localhost:11434', model: $('ollamaModel').value.trim() },
      sendFullBody: $('fullBody').checked,
      redact: $('redact').checked,
      maxTokens: clampNum($('maxTokens').value, 64, 8192, 800),
      timeoutSec: clampNum($('timeoutSec').value, 5, 180, 30),
      blendWeight: clampNum($('blend').value, 0, 100, 50) / 100
    }
  };
}

// Returns an error message, or '' if the provider settings look usable.
function validateProvider(s, typedKey) {
  document.querySelectorAll('[aria-invalid]').forEach(el => el.removeAttribute('aria-invalid'));
  const p = s.ai.provider;
  const bad = (id, msg) => { $(id).setAttribute('aria-invalid', 'true'); $(id).focus(); return msg; };
  const validUrl = u => { try { const x = new URL(u); return /^https?:$/.test(x.protocol); } catch (e) { return false; } };
  if (p === 'ollama') {
    if (!validUrl(s.ai.ollama.baseUrl)) return bad('ollamaUrl', 'Enter a valid Ollama base URL (for example http://localhost:11434).');
    if (!s.ai.ollama.model) return bad('ollamaModel', 'Enter the Ollama model name.');
  } else if (p === 'openai') {
    if (!validUrl(s.ai.openai.baseUrl)) return bad('openaiUrl', 'Enter a valid base URL (for example https://api.openai.com/v1).');
    if (!s.ai.openai.model) return bad('openaiModel', 'Enter the model name.');
    if (/^http:/i.test(s.ai.openai.baseUrl) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/i.test(s.ai.openai.baseUrl) && (typedKey || secrets.openaiKey)) {
      return bad('openaiUrl', 'Use https:// for remote providers so your API key and email are encrypted in transit.');
    }
  } else if (p === 'anthropic') {
    if (!s.ai.anthropic.model) return bad('anthropicModel', 'Enter the Claude model name.');
    if (!typedKey && !secrets.anthropicKey) return bad('anthropicKey', 'Enter your Anthropic API key.');
  }
  return '';
}

// Must be called synchronously from a click handler (browsers require a user gesture).
function requestProviderPermission(s) {
  const p = s.ai.provider;
  const pattern = PROVIDERS.permissionPatternFor(p, s.ai[p]);
  return chrome.permissions.request({ origins: [pattern] });
}

async function persist(s) {
  const newSecrets = Object.assign({}, secrets);
  for (const field of Object.values(KEY_FIELDS)) {
    const v = $(field).value.trim();
    if (v) newSecrets[field] = v;
  }
  await chrome.storage.local.set({ settings: s, secrets: newSecrets });
  settings = CONFIG.mergeSettings(s);
  secrets = newSecrets;
  $('openaiKey').value = '';
  $('anthropicKey').value = '';
  updateKeyHelp();
  renderReports();
}

function onSave() {
  const bad = badDomainLines($('companyDomains').value);
  if (bad.length) {
    $('companyDomains').setAttribute('aria-invalid', 'true');
    setStatus($('saveStatus'), `"${bad[0]}" doesn't look like an email domain. Use something like yourcompany.com.`, 'err');
    $('companyDomains').focus();
    return;
  }
  $('companyDomains').removeAttribute('aria-invalid');
  const s = collect();
  $('companyDomains').value = s.companyDomains.join('\n');
  $('companyStatus').textContent = s.companyDomains.length
    ? `Watching for compromised accounts and impersonation of: ${s.companyDomains.join(', ')}`
    : '';
  const typedKey = KEY_FIELDS[s.ai.provider] ? $(KEY_FIELDS[s.ai.provider]).value.trim() : '';
  const status = $('saveStatus');
  if (s.ai.enabled) {
    const err = validateProvider(s, typedKey);
    if (err) { setStatus(status, err, 'err'); return; }
    let req;
    try { req = requestProviderPermission(s); } catch (e) { setStatus(status, e.message, 'err'); return; }
    req.then(async granted => {
      await persist(s);
      setStatus(status, granted ? 'Saved. AI analysis is on.' : 'Saved, but access to the AI provider was not granted, so AI analysis will fall back to rules. Click Save again to allow it.', granted ? 'ok' : 'err');
    }).catch(e => setStatus(status, 'Could not save: ' + e.message, 'err'));
  } else {
    persist(s).then(() => setStatus(status, 'Saved.', 'ok')).catch(e => setStatus(status, 'Could not save: ' + e.message, 'err'));
  }
}

function onTest() {
  const s = collect();
  const p = s.ai.provider;
  const typedKey = KEY_FIELDS[p] ? $(KEY_FIELDS[p]).value.trim() : '';
  const status = $('testStatus');
  const err = validateProvider(s, typedKey);
  if (err) { setStatus(status, err, 'err'); return; }
  let req;
  try { req = requestProviderPermission(s); } catch (e) { setStatus(status, e.message, 'err'); return; }
  $('testBtn').disabled = true;
  setStatus(status, 'Testing…');
  req.then(granted => {
    if (!granted) throw new Error('Access to that address was not granted.');
    return chrome.runtime.sendMessage({ type: 'testConnection', provider: p, cfg: s.ai[p], apiKey: typedKey || undefined, timeoutSec: s.ai.timeoutSec });
  }).then(r => {
    if (r && r.ok) setStatus(status, '✓ ' + r.message, 'ok');
    else setStatus(status, '✗ ' + ((r && r.error) || 'Test failed.'), 'err');
  }).catch(e => setStatus(status, '✗ ' + e.message, 'err'))
    .finally(() => { $('testBtn').disabled = false; });
}

function wire() {
  document.querySelectorAll('input[name=provider]').forEach(r => r.addEventListener('change', updateProviderVisibility));
  $('replyGuard').addEventListener('change', e => { $('pauseSend').disabled = !e.target.checked; });

  // Turning AI on requires explicit confirmation.
  $('aiEnabled').addEventListener('change', e => {
    if (e.target.checked && !privacyAccepted) {
      e.target.checked = false;
      $('privacyDialog').showModal();
    }
    updateAiState();
  });
  $('pdCancel').addEventListener('click', () => { $('privacyDialog').close(); $('aiEnabled').focus(); });
  $('pdOk').addEventListener('click', () => {
    privacyAccepted = true;
    $('aiEnabled').checked = true;
    $('privacyDialog').close();
    updateAiState();
    setStatus($('saveStatus'), 'Choose a provider, then click Save settings.', '');
    $('aiEnabled').focus();
  });

  $('blend').addEventListener('input', () => { $('blendOut').textContent = $('blend').value + '%'; });

  document.querySelectorAll('.reveal').forEach(b => b.addEventListener('click', () => {
    const input = $(b.dataset.for);
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    b.textContent = show ? 'Hide' : 'Show';
    b.setAttribute('aria-pressed', String(show));
  }));
  document.querySelectorAll('.forget').forEach(b => b.addEventListener('click', async () => {
    delete secrets[b.dataset.key];
    await chrome.storage.local.set({ secrets });
    updateKeyHelp();
    setStatus($('saveStatus'), 'Saved key removed.', 'ok');
  }));

  $('resetColors').addEventListener('click', () => {
    const c = CONFIG.DEFAULT_SETTINGS.highlight.colors;
    $('cHigh').value = c.high; $('cMedium').value = c.medium; $('cLow').value = c.low; $('cAi').value = c.ai;
  });

  $('testBtn').addEventListener('click', onTest);
  $('saveBtn').addEventListener('click', onSave);

  $('clearAll').addEventListener('click', () => $('clearDialog').showModal());
  $('cdCancel').addEventListener('click', () => $('clearDialog').close());
  $('cdOk').addEventListener('click', async () => {
    $('clearDialog').close();
    const r = await chrome.runtime.sendMessage({ type: 'clearAllData' }).catch(e => ({ ok: false, error: e.message }));
    settings = CONFIG.mergeSettings({});
    secrets = {};
    fill();
    renderReports();
    setStatus($('saveStatus'), r && r.ok ? 'All Off the Hook data was cleared.' : 'Could not clear everything: ' + (r && r.error), r && r.ok ? 'ok' : 'err');
  });
}

// ---------------- Your reports ----------------
const FEEDBACK = globalThis.PhishGuard.feedback;
let brandList = [];

async function loadReports() {
  const { feedback } = await chrome.storage.local.get('feedback');
  return (feedback && Array.isArray(feedback.reports)) ? feedback.reports : [];
}
async function storeReports(reports) {
  await chrome.storage.local.set({ feedback: { version: 1, reports: FEEDBACK.mergeReports([], reports) } });
}

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c != null && c !== false) e.append(c);
  return e;
}

async function renderReports() {
  const reports = await loadReports();
  const phish = reports.filter(r => r.type === 'phish').length;
  $('reportStats').textContent = reports.length
    ? `${reports.length} report${reports.length === 1 ? '' : 's'}: ${phish} phishing, ${reports.length - phish} safe.`
    : 'No reports yet. Use "It\'s phishing" or "It\'s safe" in the Off the Hook panel on an email.';

  // What Off the Hook learned (same logic the background worker uses).
  const mem = FEEDBACK.buildMemory(reports, { companyDomains: settings.companyDomains, brands: brandList });
  const learned = $('learned');
  learned.replaceChildren();
  const row = (label, items) => {
    if (!items.length) return;
    learned.append(el('div', {}, el('strong', { text: label + ` (${items.length})` }), items.slice(0, 40).map(i => el('code', { text: i })),
      items.length > 40 ? ` …and ${items.length - 40} more` : null));
  };
  row('Flagged senders', Object.keys(mem.phishSenders));
  row('Flagged domains', Object.keys(mem.phishDomains));
  row('Flagged link sites', Object.keys(mem.phishLinkDomains));
  row('Learned phrases', mem.phrases);
  row('Quieted for senders', Object.entries(mem.quiet).filter(([, ids]) => ids.length).map(([a, ids]) => `${a} (${ids.length} warning${ids.length === 1 ? '' : 's'})`));

  const table = $('reportTable');
  const tbody = table.querySelector('tbody');
  tbody.replaceChildren();
  table.hidden = !reports.length;
  for (const r of reports.slice().reverse().slice(0, 300)) {
    const details = [];
    if (r.phrases && r.phrases.length) details.push('Phrases: ' + r.phrases.map(p => `"${p}"`).join(', '));
    if (r.note) details.push('Note: ' + r.note);
    if (r.text) details.push('Email text saved');
    tbody.append(el('tr', {},
      el('td', { text: new Date(r.at).toLocaleDateString() }),
      el('td', {}, el('span', { class: 'tag ' + r.type, text: r.type === 'phish' ? 'Phishing' : 'Safe' })),
      el('td', { class: 'sub' }, r.sender.name ? el('span', { text: r.sender.name }) : null, el('span', { class: 'meta', text: r.sender.address })),
      el('td', { class: 'sub' }, el('span', { text: r.subject || '(no subject)' }), details.map(d => el('span', { class: 'meta', text: d }))),
      el('td', {}, el('button', { type: 'button', class: 'small', text: 'Delete', 'aria-label': `Delete report about ${r.sender.address}`, onclick: async () => {
        await storeReports((await loadReports()).filter(x => x.id !== r.id));
        setStatus($('reportsStatus'), 'Report deleted. Off the Hook no longer uses it.', 'ok');
      } }))
    ));
  }
  if (reports.length > 300) tbody.append(el('tr', {}, el('td', { colspan: '5', class: 'meta', text: `Showing the newest 300 of ${reports.length}. Export to see all.` })));
}

function wireReports() {
  fetch(chrome.runtime.getURL('data/brands.json')).then(r => r.json()).then(j => { brandList = j.brands || []; renderReports(); }).catch(() => {});
  chrome.storage.onChanged.addListener((changes, area) => { if (area === 'local' && changes.feedback) renderReports(); });

  $('exportReports').addEventListener('click', async () => {
    const reports = await loadReports();
    if (!reports.length) { setStatus($('reportsStatus'), 'There are no reports to export yet.', 'err'); return; }
    const blob = new Blob([JSON.stringify({ app: 'Off the Hook', version: 1, exportedAt: new Date().toISOString(), reports }, null, 2)], { type: 'application/json' });
    const a = el('a', { href: URL.createObjectURL(blob), download: `off-the-hook-reports-${new Date().toISOString().slice(0, 10)}.json` });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    setStatus($('reportsStatus'), `Exported ${reports.length} report(s).`, 'ok');
  });

  $('importReports').addEventListener('click', () => $('importFile').click());
  $('importFile').addEventListener('change', async e => {
    const file = e.target.files && e.target.files[0];
    e.target.value = '';
    if (!file) return;
    try {
      if (file.size > 20 * 1024 * 1024) throw new Error('That file is too large.');
      const data = JSON.parse(await file.text());
      const incoming = Array.isArray(data) ? data : data && data.reports;
      if (!Array.isArray(incoming)) throw new Error("That file doesn't contain Off the Hook reports.");
      const valid = incoming.map(FEEDBACK.sanitizeReport).filter(Boolean);
      const existing = await loadReports();
      const known = new Set(existing.map(r => r.id));
      const added = valid.filter(r => !known.has(r.id)).length;
      await storeReports(existing.concat(valid));
      const skipped = incoming.length - valid.length;
      setStatus($('reportsStatus'), `Imported ${added} new report(s)` + (skipped ? `; skipped ${skipped} unreadable entr${skipped === 1 ? 'y' : 'ies'}.` : '.'), 'ok');
    } catch (err) {
      setStatus($('reportsStatus'), 'Could not import: ' + (err instanceof SyntaxError ? "the file isn't valid JSON." : err.message), 'err');
    }
  });

  $('deleteAllReports').addEventListener('click', async () => {
    const n = (await loadReports()).length;
    if (!n) { setStatus($('reportsStatus'), 'There are no reports to delete.', ''); return; }
    if (!confirm(`Delete all ${n} reports? Off the Hook will forget everything it learned from them. Consider exporting first.`)) return;
    await chrome.storage.local.remove('feedback');
    setStatus($('reportsStatus'), 'All reports deleted.', 'ok');
  });
}

// ---- known scam-site lists ----
const fmtWhen = t => (t ? new Date(t).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'never');
// One switch per list (shared/config.js BLOCKLIST_SOURCES), with its last download result.
function buildSourceRows(s) {
  const on = (s.blocklists && s.blocklists.sources) || {};
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text) e.textContent = text; return e; };
  $('blSources').replaceChildren(...CONFIG.BLOCKLIST_SOURCES.map(src => {
    const box = el('input'); box.type = 'checkbox'; box.id = 'bl_' + src.id; box.checked = on[src.id] !== false;
    const link = el('a', null, src.name); link.href = src.home; link.target = '_blank'; link.rel = 'noopener';
    const about = el('span', 'about', src.about + '. ');
    if (src.terms) about.append(el('span', 'terms', src.terms + '.'));
    const label = el('label', 'check'); label.append(box, el('strong'), el('span', 'count'), about);
    label.querySelector('strong').append(link);
    const li = el('li'); li.dataset.src = src.id; li.append(label);
    return li;
  }));
}

async function renderBlocklists() {
  const r = await chrome.runtime.sendMessage({ type: 'getBlocklistStatus' }).catch(() => null);
  const status = $('blStatus');
  if (!r || !r.ok) { status.textContent = "Couldn't read the list status."; return; }
  const m = r.meta;
  if (r.updating) status.textContent = 'Downloading the lists…';
  else if (!m || !m.updated) status.textContent = r.enabled ? 'Not downloaded yet. Click Update now (or it will happen automatically within a day).' : 'Off.';
  else status.textContent = `${(m.total || 0).toLocaleString()} known scam sites in total · updated ${fmtWhen(m.updated)}`;
  const bySrc = Object.fromEntries(((m && m.sources) || []).map(x => [x.id, x]));
  for (const li of $('blSources').children) {
    const res = bySrc[li.dataset.src], count = li.querySelector('.count');
    count.classList.toggle('err', !!(res && res.ok === false));
    count.textContent = !res || res.off ? '' : res.ok ? `${res.count.toLocaleString()} sites` : `couldn't download (${res.error})`;
  }
}
function wireBlocklists() {
  $('blUpdate').addEventListener('click', async () => {
    const b = $('blUpdate');
    b.disabled = true;
    $('blStatus').textContent = 'Downloading the lists… (about 15 MB)';
    await chrome.runtime.sendMessage({ type: 'updateBlocklists' }).catch(() => null);
    b.disabled = false;
    renderBlocklists();
  });
}

// ---- contact memory ----
async function renderHistory() {
  const r = await chrome.runtime.sendMessage({ type: 'getHistoryStats' }).catch(() => null);
  $('histStats').textContent = r && r.ok
    ? `Learned from ${r.learned.toLocaleString()} normal emails · ${r.known.toLocaleString()} known senders (${r.senders.toLocaleString()} seen) · ${r.people.toLocaleString()} names`
    : "Couldn't read contact memory.";
}
function wireHistory() {
  $('histClear').addEventListener('click', async () => {
    if (!confirm('Forget every sender Off the Hook has learned? It will start learning again from the next normal email.')) return;
    await chrome.runtime.sendMessage({ type: 'clearHistory' }).catch(() => null);
    renderHistory();
  });
}

async function init() {
  const stored = await chrome.storage.local.get(['settings', 'secrets']);
  settings = CONFIG.mergeSettings(stored.settings);
  secrets = stored.secrets || {};
  fill();
  wire();
  wireReports();
  renderReports();
  wireBlocklists();
  renderBlocklists();
  wireHistory();
  renderHistory();
}

init();
