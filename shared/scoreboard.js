/*
 * Scoreboard: runs the analyzer over emails you've labelled (phishing / normal) and counts how
 * many phish it catches and how many normal emails it wrongly flags. This is how every change
 * to the checks can be measured instead of guessed.
 *
 *   run(items, deps) -> { rows, stats }
 *     items: [{ label: 'phish'|'legit', name, source, email }]
 *     deps:  { analyzer, settings, lists }   (lists without report memory or contact history,
 *            so the result shows what the checks catch on their own)
 */
(function (root, factory) {
  const mod = factory();
  if (typeof module === 'object' && module.exports) module.exports = mod;
  else { root.PhishGuard = root.PhishGuard || {}; root.PhishGuard.scoreboard = mod; }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const pct = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : 0);

  function run(items, deps) {
    const rows = items.map(item => {
      const r = deps.analyzer.analyze(item.email, Object.assign({ sensitivity: 'medium' }, deps.settings || {}), deps.lists || {});
      const flagged = r.verdict !== 'safe';
      const outcome = item.label === 'phish' ? (flagged ? 'caught' : 'missed') : (flagged ? 'false_alarm' : 'ok');
      return {
        name: item.name, source: item.source, label: item.label, outcome,
        verdict: r.verdict, verdictLabel: r.verdictLabel, score: r.score,
        from: item.email.from, subject: item.email.subject,
        reasons: r.findings.slice(0, 4).map(f => ({ id: f.id, severity: f.severity, title: f.title }))
      };
    });
    const phish = rows.filter(r => r.label === 'phish'), legit = rows.filter(r => r.label === 'legit');
    const stats = {
      phish: phish.length,
      caught: phish.filter(r => r.outcome === 'caught').length,
      strict: phish.filter(r => r.verdict === 'phishing').length,
      legit: legit.length,
      falseAlarms: legit.filter(r => r.outcome === 'false_alarm').length,
      strictFalse: legit.filter(r => r.verdict === 'phishing').length
    };
    stats.catchRate = pct(stats.caught, stats.phish);
    stats.falseRate = pct(stats.falseAlarms, stats.legit);
    // Misses and false alarms first: they're what to work on.
    const order = { missed: 0, false_alarm: 1, caught: 2, ok: 3 };
    rows.sort((a, b) => order[a.outcome] - order[b.outcome] || (a.label === 'phish' ? a.score - b.score : b.score - a.score));
    return { rows, stats };
  }

  function summary(stats, when) {
    const lines = [`Off the Hook scoreboard${when ? ' (' + when + ')' : ''}`];
    if (stats.phish) lines.push(`Phishing caught: ${stats.caught} of ${stats.phish} (${stats.catchRate}%), ${stats.strict} rated Likely Phishing`);
    if (stats.legit) lines.push(`False alarms: ${stats.falseAlarms} of ${stats.legit} normal emails (${stats.falseRate}%), ${stats.strictFalse} rated Likely Phishing`);
    return lines.join('\n');
  }

  return { run, summary };
});
