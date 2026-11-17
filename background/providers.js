/*
 * AI provider adapters. Only ever called from the background service worker.
 * API keys are passed in as arguments, sent only in request headers, and never logged
 * or included in error messages or URLs.
 */
(function (root) {
  'use strict';

  function trimSlash(u) { return String(u || '').trim().replace(/\/+$/, ''); }

  // Permission pattern for an endpoint, e.g. "http://localhost/*" (ports are ignored by match patterns).
  function originPattern(baseUrl) {
    const u = new URL(baseUrl);
    if (!/^https?:$/.test(u.protocol)) throw new Error('The URL must start with http:// or https://');
    return u.protocol + '//' + u.hostname + '/*';
  }

  function endpointFor(provider, cfg) {
    if (provider === 'anthropic') return 'https://api.anthropic.com/v1/messages';
    if (provider === 'ollama') return trimSlash(cfg.baseUrl || 'http://localhost:11434') + '/api/chat';
    let base = trimSlash(cfg.baseUrl);
    base = base.replace(/\/chat\/completions$/, '');
    return base + '/chat/completions';
  }

  function permissionPatternFor(provider, cfg) {
    if (provider === 'anthropic') return 'https://api.anthropic.com/*';
    return originPattern(provider === 'ollama' ? (cfg.baseUrl || 'http://localhost:11434') : cfg.baseUrl);
  }

  function friendlyHttpError(status, provider, detail) {
    const who = provider === 'anthropic' ? 'Anthropic' : provider === 'ollama' ? 'Ollama' : 'The AI provider';
    if (status === 401 || status === 403) {
      if (provider === 'ollama') return `${who} refused the request (HTTP ${status}). Start Ollama with OLLAMA_ORIGINS set to allow browser extensions (see README).`;
      return `${who} rejected the API key (HTTP ${status}). Check the key in Off the Hook settings.`;
    }
    if (status === 404) return `${who} returned "not found" (HTTP 404). Check the base URL and model name.${detail ? ' ' + detail : ''}`;
    if (status === 429) return `${who} is rate-limiting requests or the account is out of credit (HTTP 429).`;
    if (status >= 500) return `${who} had a server error (HTTP ${status}). Try again later.`;
    return `${who} returned HTTP ${status}.${detail ? ' ' + detail : ''}`;
  }

  async function safeErrorDetail(res) {
    try {
      const j = await res.json();
      const msg = (j && (j.error && (j.error.message || j.error)) || j.message) || '';
      return typeof msg === 'string' ? msg.slice(0, 200) : '';
    } catch (e) { return ''; }
  }

  async function postJson(url, headers, body, timeoutMs, provider) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    let res;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: Object.assign({ 'content-type': 'application/json' }, headers),
        body: JSON.stringify(body),
        signal: ctrl.signal,
        credentials: 'omit',
        cache: 'no-store',
        referrerPolicy: 'no-referrer'
      });
    } catch (e) {
      clearTimeout(timer);
      if (e && e.name === 'AbortError') throw new Error(`The AI request timed out after ${Math.round(timeoutMs / 1000)} seconds.`);
      throw new Error(provider === 'ollama'
        ? 'Could not reach Ollama. Is it running, and is the base URL correct?'
        : 'Could not reach the AI provider. Check the base URL, your connection, and that Off the Hook was granted access to that site.');
    }
    clearTimeout(timer);
    if (!res.ok) throw new Error(friendlyHttpError(res.status, provider, await safeErrorDetail(res)));
    try { return await res.json(); } catch (e) { throw new Error('The AI provider returned a response Off the Hook could not read.'); }
  }

  /**
   * Send one system + user message and return the model's text output.
   * @param {object} opts { provider, cfg: {baseUrl, model}, apiKey, system, user, maxTokens, timeoutMs }
   */
  async function complete(opts) {
    const { provider, cfg, apiKey, system, user } = opts;
    const maxTokens = Math.max(64, Math.min(8192, Number(opts.maxTokens) || 800));
    const timeoutMs = Math.max(3000, Math.min(180000, Number(opts.timeoutMs) || 30000));
    if (!cfg || !cfg.model) throw new Error('No model name is configured.');

    if (provider === 'anthropic') {
      if (!apiKey) throw new Error('No Anthropic API key is saved.');
      const data = await postJson(endpointFor(provider, cfg), {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        // Required by Anthropic for calls made directly from a browser extension.
        'anthropic-dangerous-direct-browser-access': 'true'
      }, {
        model: cfg.model,
        max_tokens: maxTokens,
        temperature: 0,
        system,
        messages: [{ role: 'user', content: user }]
      }, timeoutMs, provider);
      const parts = Array.isArray(data.content) ? data.content : [];
      return parts.filter(p => p && p.type === 'text').map(p => p.text).join('\n');
    }

    if (provider === 'ollama') {
      const data = await postJson(endpointFor(provider, cfg), {}, {
        model: cfg.model,
        stream: false,
        format: 'json',
        options: { temperature: 0, num_predict: maxTokens },
        messages: [{ role: 'system', content: system }, { role: 'user', content: user }]
      }, timeoutMs, provider);
      return (data && data.message && data.message.content) || '';
    }

    // OpenAI-compatible (OpenAI, OpenRouter, LM Studio, vLLM, Groq, Together, etc.)
    if (!cfg.baseUrl) throw new Error('No base URL is configured.');
    const headers = {};
    if (apiKey) headers.authorization = 'Bearer ' + apiKey;
    const data = await postJson(endpointFor('openai', cfg), headers, {
      model: cfg.model,
      temperature: 0,
      max_tokens: maxTokens,
      messages: [{ role: 'system', content: system }, { role: 'user', content: user }]
    }, timeoutMs, 'openai');
    const choice = data && Array.isArray(data.choices) && data.choices[0];
    const content = choice && choice.message && choice.message.content;
    if (Array.isArray(content)) return content.map(c => (c && c.text) || '').join('');
    return content || '';
  }

  const api = { complete, endpointFor, permissionPatternFor, originPattern };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else (root.PhishGuard = root.PhishGuard || {}).providers = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
