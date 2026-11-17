/*
 * Reply Guard tests: what counts as personal or secret information in a reply, and what
 * doesn't (so ordinary replies to a flagged email aren't nagged).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory;
  else root.PhishGuardReplyCases = factory;
})(typeof globalThis !== 'undefined' ? globalThis : this, function defineReplyCases(env) {
  'use strict';
  const { test, assert, PG } = env;
  const find = t => PG.sensitive.findSensitive(t);
  const kinds = t => find(t).map(f => f.kind);

  test('Reply Guard: phone numbers in any common format', () => {
    for (const t of ['Ok +1 (123) 456-7890 here you go', 'Sure, it\'s (555) 010-0147', 'call me at 555-010-0147', 'cell: 555.010.0147', '+1 555 010 0147', 'my cell is 5550100147', '+44 20 7946 0958']) {
      assert.ok(kinds(t).includes('phone'), t);
    }
  });

  test('Reply Guard: the warning never repeats the number', () => {
    const f = find('my number is 555-010-0147')[0];
    assert.equal(f.masked, '•••-•••-0147');
    assert.ok(!/555/.test(f.masked));
    const pw = find('password: Hunter2!')[0];
    assert.equal(pw.kind, 'password');
    assert.ok(!/Hunter/.test(pw.masked));
  });

  test('Reply Guard: cards, SSNs, bank details, passwords, codes and gift cards', () => {
    assert.ok(kinds('card 4111 1111 1111 1111 exp 04/28').includes('card'));
    assert.ok(!kinds('order 4111 1111 1111 1112').includes('card'), 'fails the card checksum');
    assert.ok(kinds('SSN 078-05-1120').includes('ssn'));
    assert.ok(kinds('routing 021000021, account number 483920117').includes('bank'));
    assert.ok(kinds('the password is Summer2026').includes('password'));
    assert.ok(kinds('The verification code is 482913').includes('code'));
    assert.ok(kinds('Here are the gift card codes: X7KQ-9PLM-2ZTW-44RA').includes('giftcard'));
    assert.ok(kinds('Got the gift cards, claim codes below: AQ4JDKW92LPZ').includes('giftcard'));
  });

  test('Reply Guard: ordinary replies are not flagged', () => {
    for (const t of [
      'Thanks, I\'ll take a look this afternoon.',
      'The meeting is on 2026-10-13 at 2:30 PM in bay 3.',
      'PO 4500123456 shipped yesterday.',
      'Our zip code 77449 is on the label.',
      'Please update the account for 2026-10-13.',
      'I need the account information for the supplier order.',
      'Invoice INV-2026-0042 is attached.',
      'Who is this? I don\'t recognize your address.'
    ]) assert.deepEqual(kinds(t), [], t);
  });
});
