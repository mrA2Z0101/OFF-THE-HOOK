/*
 * DEV ONLY. A tiny stand-in for the chrome.* APIs so dev/demo.html can run the real
 * content scripts on a regular web page. Not part of the extension.
 */
(function () {
  'use strict';
  const PG = window.PhishGuard;
  const listeners = [];
  let saved = undefined;
  let lists = null;
  let reports = []; // in-memory stand-in for the "feedback" storage key
  const sessionRisky = {}; // stand-in for chrome.storage.session "risky"
  async function analyzeWithMemory(email, s) {
    const l = await getLists();
    const memory = PG.feedback.buildMemory(reports, { companyDomains: s.companyDomains, brands: l.brands.brands });
    const result = PG.analyzer.analyze(email, s, Object.assign({ memory }, l));
    result.reported = memory.reportedKeys[PG.feedback.reportKey(email)] || null;
    return result;
  }

  async function getLists() {
    if (!lists) {
      const load = f => fetch('../data/' + f, { cache: 'no-store' }).then(r => r.json());
      lists = { keywords: await load('keywords.json'), brands: await load('brands.json') };
    }
    return lists;
  }
  const current = () => PG.config.mergeSettings(saved);
  const pub = s => ({
    sensitivity: s.sensitivity, highlight: s.highlight, ui: s.ui, replyGuard: s.replyGuard,
    ai: { enabled: !!window.DEMO_AI, provider: 'demo', providerLabel: 'Demo (simulated)' }
  });
  const sleep = ms => new Promise(r => setTimeout(r, ms));

  window.chrome = {
    runtime: {
      id: 'phishguard-demo',
      async sendMessage(msg) {
        const s = current();
        switch (msg.type) {
          case 'analyze': {
            const result = await analyzeWithMemory(msg.email, s);
            window.DEMO_LAST_RESULT = result;
            return { ok: true, result, settings: pub(s), aiEnabled: !!window.DEMO_AI };
          }
          case 'analyzeList': {
            const l = await getLists();
            const memory = PG.feedback.buildMemory(reports, { companyDomains: s.companyDomains, brands: l.brands.brands });
            const withMemory = Object.assign({ memory }, l);
            window.DEMO_LIST_CALLS = (window.DEMO_LIST_CALLS || 0) + 1;
            return { ok: true, results: msg.rows.slice(0, 60).map(r => PG.analyzer.analyzePreview(r, s, withMemory)) };
          }
          case 'analyzeAI': {
            await sleep(900);
            const raw = window.DEMO_AI_RESPONSE ? window.DEMO_AI_RESPONSE(msg.email) : '';
            if (raw === null) return { ok: false, error: 'The AI request timed out after 30 seconds. (simulated)' };
            const parsed = PG.ai.parseAIResponse(raw, { subject: msg.email.subject, body: msg.email.body });
            if (!parsed.ok) return { ok: false, error: parsed.error };
            return { ok: true, ai: parsed.data, combined: PG.ai.blend(msg.ruleResult, parsed.data, s), providerLabel: 'Demo (simulated)' };
          }
          case 'report': {
            const result = await analyzeWithMemory(msg.email, s);
            const report = PG.feedback.makeReport(msg.kind, msg.email, result, { site: msg.site, phrases: msg.phrases, note: msg.note });
            reports = reports.filter(r => r.key !== report.key).concat([report]);
            window.DEMO_REPORTS = reports;
            return { ok: true, report: { id: report.id, type: report.type, at: report.at } };
          }
          case 'undoReport':
            reports = reports.filter(r => r.id !== msg.id);
            window.DEMO_REPORTS = reports;
            return { ok: true };
          case 'getPublicSettings': return { ok: true, settings: pub(s) };
          case 'rememberRisky': for (const [k, v] of msg.entries) sessionRisky[k] = v; return { ok: true };
          case 'getRisky': return { ok: true, risky: Object.assign({}, sessionRisky, window.DEMO_OTHER_WINDOW_RISKY || {}) };
          case 'noEmail': return { ok: true };
          case 'openOptions': window.open('../options/options.html', '_blank'); return { ok: true };
          case 'openFileChecker': window.open('../scan/scan.html', '_blank'); return { ok: true };
          default: return { ok: false, error: 'unknown' };
        }
      },
      onMessage: { addListener() {} }
    },
    storage: { onChanged: { addListener(fn) { listeners.push(fn); } } }
  };

  window.demoSetSettings = s => {
    saved = s;
    listeners.forEach(fn => fn({ settings: { newValue: s } }, 'local'));
  };
})();
