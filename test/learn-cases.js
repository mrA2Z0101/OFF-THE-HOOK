/*
 * Learn post tests: the small Markdown reader behind the Learn page (shared/learnmd.js).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory;
  else root.PhishGuardLearnCases = factory;
})(typeof globalThis !== 'undefined' ? globalThis : this, function defineLearnCases(env) {
  'use strict';
  const { test, assert, PG } = env;
  const MD = PG.learnmd;

  test('Learn posts: front matter, headings, lists and reading time', () => {
    const post = MD.parse([
      '---', 'title: The 10-second check: who, what, where', 'date: 2026-10-13', 'summary: Three questions.', 'tags: basics, links', 'draft: yes', '---',
      '', 'Intro **bold** and *italic* and `code`.', '', '## Who', '- one', '- two', '  continued', '', '1. first', '2. second', '', '---'
    ].join('\n'));
    assert.equal(post.meta.title, 'The 10-second check: who, what, where');
    assert.deepEqual(post.meta.tags, ['basics', 'links']);
    assert.equal(post.meta.draft, true);
    assert.deepEqual(post.blocks.map(b => b.t), ['p', 'h', 'ul', 'ol', 'hr']);
    assert.equal(post.blocks[1].level, 2, '# and ## are section headings: the post title is the only h1');
    assert.equal(MD.plain(post.blocks[2].items[1]), 'two continued');
    assert.deepEqual(post.blocks[0].c.map(n => n.t), ['text', 'b', 'text', 'i', 'text', 'code', 'text']);
    assert.equal(post.minutes, 1);
  });

  test('Learn posts: only safe links and local pictures', () => {
    const nodes = MD.inline('[a](https://example.com) [b](javascript:alert(1)) [c](#/other-post) [d](data:text/html,x) <script>x</script>');
    assert.deepEqual(nodes.filter(n => n.t === 'a').map(n => n.href), ['https://example.com', '#/other-post']);
    assert.ok(MD.plain(nodes).includes('<script>x</script>'), 'HTML stays as text');
    const pics = MD.parse('![ok](img/flag.png)\n\n![remote](https://tracker.example/p.png)\n\n![up](../secret.png)').blocks;
    assert.deepEqual(pics.map(b => b.src), ['img/flag.png']);
  });

  test('Learn posts: call-outs, quotes and red-flag highlights', () => {
    const post = MD.parse('> [!TIP] Grade the request\n> Ask what it wants.\n\n> Just a quote\n\nSee ==98% full|A reason to sign in== and ==this==.');
    assert.equal(post.blocks[0].t, 'callout');
    assert.equal(post.blocks[0].kind, 'tip');
    assert.equal(post.blocks[0].title, 'Grade the request');
    assert.equal(post.blocks[1].t, 'quote');
    const marks = post.blocks[2].c.filter(n => n.t === 'mark');
    assert.equal(marks[0].note, 'A reason to sign in');
    assert.equal(MD.plain(marks[0].c), '98% full');
    assert.equal(marks[1].note, undefined);
  });

  test('Learn posts: tables and quoted titles', () => {
    const post = MD.parse('---\ntitle: "Please sign": fake DocuSign\nsummary: "Quoted summary"\n---\n\n| Looks like | Is really |\n|:--|:--|\n| `paypal.com` | `paypa1.com` |\n| a \\| b | c |\n\nAfter.');
    assert.equal(post.meta.title, '"Please sign": fake DocuSign', 'quotes inside the title stay');
    assert.equal(post.meta.summary, 'Quoted summary', 'quotes around the whole value go');
    assert.deepEqual(post.blocks.map(b => b.t), ['table', 'p']);
    assert.deepEqual(post.blocks[0].head.map(MD.plain), ['Looks like', 'Is really']);
    assert.deepEqual(post.blocks[0].rows.map(r => r.map(MD.plain)), [['paypal.com', 'paypa1.com'], ['a | b', 'c']]);
  });

  test('Learn posts: practice emails and quizzes', () => {
    const post = MD.parse([
      '```email', 'From: IT <it@helpdesk-mail.com>', 'Subject: Password expires', 'Verdict: phishing', 'Attachment: a.pdf, b.zip', '',
      'Your password ==expires today|Rushing you==.', '', 'Regards,', 'IT Team', '```', '',
      '```quiz', 'What do you do?', '- [ ] Click', '- [x] Check another way', 'Why: Links can lie.', '```'
    ].join('\n'));
    const [email, quiz] = post.blocks;
    assert.equal(email.t, 'email');
    assert.equal(email.from, 'IT <it@helpdesk-mail.com>');
    assert.equal(email.verdict, 'phishing');
    assert.deepEqual(email.attachments, ['a.pdf', 'b.zip']);
    assert.equal(email.body.length, 2);
    assert.equal(MD.plain(email.body[1]), 'Regards,\nIT Team', 'sign-off lines stay on their own lines');
    assert.equal(quiz.t, 'quiz');
    assert.deepEqual(quiz.options.map(o => o.correct), [false, true]);
    assert.equal(MD.plain(quiz.why), 'Links can lie.');
    assert.equal(MD.slug('Spot-the-Fake Boss.md'), 'spot-the-fake-boss');
  });
});
