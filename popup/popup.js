'use strict';

const ICONS = { safe: '✓', suspicious: '!', phishing: '✕' };
const $ = id => document.getElementById(id);

async function main() {
  $('settings').addEventListener('click', () => { chrome.runtime.openOptionsPage(); window.close(); });
  $('filecheck').addEventListener('click', () => { chrome.tabs.create({ url: chrome.runtime.getURL('scan/scan.html') }); window.close(); });
  $('learn').addEventListener('click', () => { chrome.tabs.create({ url: chrome.runtime.getURL('learn/learn.html') }); window.close(); });
  showNewPosts();
  const word = document.querySelector('.ot-wordmark');
  word.addEventListener('error', () => word.closest('.ot-title').classList.add('no-img'));

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  const resp = await chrome.runtime.sendMessage({ type: 'getTabState', tabId: tab.id }).catch(() => null);
  if (!resp || !resp.ok) return;

  const aiOn = resp.settings && resp.settings.ai && resp.settings.ai.enabled;
  const mode = $('mode');
  mode.textContent = aiOn ? 'AI-assisted' : 'Rule-based';
  mode.classList.toggle('ai', !!aiOn);
  mode.title = aiOn ? 'AI analysis is on (' + resp.settings.ai.providerLabel + ')' : 'AI analysis is off. Your email never leaves your browser.';

  const s = resp.state;
  if (!s) return;

  $('verdict').className = 'verdict v-' + s.verdict;
  document.querySelector('.vicon').textContent = ICONS[s.verdict] || '?';
  $('vlabel').textContent = s.verdictLabel;
  $('vdetail').textContent = `Risk score ${s.score} / 100 for the open email`;
  $('meter').hidden = false;
  $('meterFill').style.width = Math.max(0, Math.min(100, s.score)) + '%';

  $('alert').hidden = s.alert !== 'internal_compromised';
  const c = s.counts || {};
  const parts = [];
  if (c.high) parts.push(`${c.high} high`);
  if (c.medium) parts.push(`${c.medium} medium`);
  if (c.low) parts.push(`${c.low} low`);
  $('counts').hidden = false;
  $('counts').textContent = parts.length ? `Rule findings: ${parts.join(', ')}.` : 'No rule-based warning signs found.';

  if (s.mode === 'ai') {
    $('aistatus').hidden = false;
    $('aistatus').textContent =
      s.aiStatus === 'done' ? `Rules ${s.ruleScore} + AI ${s.aiScore} (AI verdict: ${s.aiVerdict}).`
      : s.aiStatus === 'pending' ? 'AI analysis in progress…'
      : s.aiStatus === 'failed' ? 'AI analysis failed; showing the rule-based result.'
      : '';
  }

  for (const [id, type] of [['toggle', 'toggleHighlights'], ['rescan', 'rescan']]) {
    const b = $(id);
    b.disabled = false;
    b.addEventListener('click', () => {
      chrome.tabs.sendMessage(tab.id, { type }).catch(() => {});
      if (type === 'rescan') window.close();
    });
  }
}

// "Learn 2 new": posts listed in learn/posts/index.json that haven't been opened yet.
async function showNewPosts() {
  try {
    const index = await fetch(chrome.runtime.getURL('learn/posts/index.json')).then(r => r.json());
    const seen = new Set((await chrome.storage.local.get('learnSeen')).learnSeen || []);
    const slug = f => String(f).replace(/\.md$/i, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    const fresh = (index.posts || []).filter(f => !seen.has(slug(f))).length;
    if (fresh) { $('learnNew').textContent = fresh + ' new'; $('learnNew').hidden = false; }
  } catch (e) { /* no badge */ }
}

main();
