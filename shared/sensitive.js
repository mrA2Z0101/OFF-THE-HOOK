/*
 * Finds personal or secret information in text you are typing (Reply Guard): phone numbers,
 * card numbers, Social Security numbers, bank details, passwords, sign-in codes and gift card
 * codes. Pure function, no network. Results are masked so the warning never repeats the secret.
 *
 *   findSensitive(text) -> [{ kind, label, masked }]
 */
(function (root, factory) {
  const mod = factory();
  if (typeof module === 'object' && module.exports) module.exports = mod;
  else { root.PhishGuard = root.PhishGuard || {}; root.PhishGuard.sensitive = mod; }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const LABELS = {
    phone: 'A phone number',
    card: 'A payment card number',
    ssn: 'A Social Security number',
    bank: 'Bank account or routing details',
    password: 'A password',
    code: 'A sign-in or verification code',
    giftcard: 'Gift card codes'
  };

  // Keep only the last few characters so the warning itself never shows the secret.
  function mask(s, keep) {
    const t = String(s).trim();
    let left = keep;
    let out = '';
    for (let i = t.length - 1; i >= 0; i--) {
      const c = t[i];
      if (/[A-Za-z0-9]/.test(c)) { out = (left > 0 ? c : '•') + out; left--; } else out = c + out;
    }
    return out;
  }

  function luhn(digits) {
    let sum = 0, dbl = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = digits.charCodeAt(i) - 48;
      if (dbl) { d *= 2; if (d > 9) d -= 9; }
      sum += d; dbl = !dbl;
    }
    return sum % 10 === 0;
  }

  const PHONE_WORDS = /\b(cell|mobile|phone|number|num|call|text|reach|contact|tel|whatsapp|direct)\b/i;

  function findSensitive(text) {
    const t = String(text || '').slice(0, 50000);
    const out = [];
    const seen = new Set();
    const push = (kind, value) => {
      const key = kind + ':' + value.replace(/\D/g, '') + value.toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ kind, label: LABELS[kind], masked: mask(value, kind === 'password' ? 0 : kind === 'giftcard' ? 3 : 4) });
    };
    let m;

    // Payment cards: 13-19 digits (spaces/dashes allowed) that pass the Luhn check.
    const cardRe = /(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])/g;
    const cardSpans = [];
    while ((m = cardRe.exec(t))) {
      const d = m[0].replace(/\D/g, '');
      if (d.length >= 13 && d.length <= 19 && luhn(d) && !/^(\d)\1+$/.test(d)) { push('card', m[0]); cardSpans.push([m.index, m.index + m[0].length]); }
    }
    const inCard = i => cardSpans.some(([a, b]) => i >= a && i < b);

    // Social Security numbers.
    const ssnRe = /(?<!\d)(\d{3})-(\d{2})-(\d{4})(?!\d)/g;
    while ((m = ssnRe.exec(t))) if (m[1] !== '000' && m[1] !== '666' && m[1][0] !== '9') push('ssn', m[0]);
    const ssnWord = /\b(ssn|social security( number| #| no\.?)?)\b\D{0,20}(\d{3}[ -]?\d{2}[ -]?\d{4})(?!\d)/gi;
    while ((m = ssnWord.exec(t))) push('ssn', m[3]);

    // Phone numbers: formatted ones anywhere; 10 bare digits only near a phone word.
    const phoneRe = /(?<![\d-])(?:\+?1[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?![\d-])/g;
    while ((m = phoneRe.exec(t))) if (!inCard(m.index)) push('phone', m[0]);
    const bareRe = /(?<![\d-])(?:\+?1)?\d{10}(?![\d-])/g;
    while ((m = bareRe.exec(t))) {
      if (inCard(m.index)) continue;
      if (PHONE_WORDS.test(t.slice(Math.max(0, m.index - 30), m.index))) push('phone', m[0]);
    }
    const intlRe = /(?<![\d])\+(?!1[\s.-]?\d{3})\d{1,3}[\s.-]?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?!\d)/g;
    while ((m = intlRe.exec(t))) push('phone', m[0]);

    // Bank details: a bank word followed by an account-like number or IBAN.
    const swiftRe = /\b(?:swift|bic)\b(?:\s*code)?\s*(?:is|:|=|-)?\s*([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b/gi;
    while ((m = swiftRe.exec(t))) if (/^[A-Z0-9]+$/.test(m[1])) push('bank', m[1]);
    const bankRe = /\b(routing|aba|account|acct|a\/c|iban|sort code)\b(?:\s*(?:number|no\.?|#|num))?\s*(?:is|:|=|-)?\s*([A-Z]{2}\d{2}[A-Z0-9 ]{10,30}|\d[\d -]{4,20}\d)/gi;
    while ((m = bankRe.exec(t))) {
      const v = m[2].trim();
      if (inCard(m.index + m[0].length - 1)) continue;
      if (/^\d/.test(v) && (v.replace(/\D/g, '').length < 6 || /^\d{4}-\d{1,2}-\d{1,2}$/.test(v))) continue; // dates, short numbers
      push('bank', v);
    }

    // Passwords and PINs given away.
    const pwRe = /\b(password|passcode|passwd|pwd|pw|pin)\b\s*(?:is|was|=|:|-)\s*["“']?([^\s"”']{3,})/gi;
    while ((m = pwRe.exec(t))) push('password', m[2]);
    const pwRe2 = /\b(my|the)\s+(password|passcode|pin)\b[^.\n]{0,20}?\b(is|was)\s+["“']?([^\s"”']{3,})/gi;
    while ((m = pwRe2.exec(t))) push('password', m[4]);

    // One-time codes (MFA): a code word near 4-8 digits.
    const codeRe = /(?<!\b(?:zip|postal|area|promo|discount|coupon|country|dress|tax|error|status|product|item|part)\s)\b(code|verification|verify|otp|one[- ]time|2fa|mfa|authenticator)\b[^\n\d]{0,25}(\d{4,8})(?!\d)/gi;
    while ((m = codeRe.exec(t))) push('code', m[2]);

    // Gift card codes: dashed blocks of letters+digits, or long mixed codes near gift-card words.
    const gcRe = /\b(?=[A-Z0-9-]*\d)(?=[A-Z0-9-]*[A-Z])[A-Z0-9]{4,6}(?:-[A-Z0-9]{4,6}){2,4}\b/g;
    while ((m = gcRe.exec(t))) push('giftcard', m[0]);
    if (/\bgift\s*cards?\b|\bclaim\s+code|\bcard\s+(number|code)s?\b|\bredemption\s+code/i.test(t)) {
      const mixed = /\b(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{10,20}\b/g;
      while ((m = mixed.exec(t))) if (!/^(https?|www)/i.test(m[0])) push('giftcard', m[0]);
    }
    return out;
  }

  return { findSensitive, LABELS, _internal: { luhn, mask } };
});
