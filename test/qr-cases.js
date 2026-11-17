/*
 * QR reader tests. The fixtures are real QR codes made by an independent encoder (segno), so
 * these check shared/qr.js against the standard, not against itself.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory;
  else root.PhishGuardQrCases = factory;
})(typeof globalThis !== 'undefined' ? globalThis : this, function defineQrCases(env) {
  'use strict';
  const { test, assert, PG, qrFixtures: FIX } = env;
  const QR = PG.qr;
  const I = QR._internal;

  // Draw a module matrix as RGBA pixels. opts: scale, quiet (modules), invert, transparent,
  // angle (degrees), mirror, flips: [[x, y]] modules to damage.
  function render(rows, opts) {
    const o = Object.assign({ scale: 4, quiet: 4, angle: 0 }, opts);
    const n = rows.length;
    const flips = new Set((o.flips || []).map(([x, y]) => y * n + x));
    const dark = (mx, my) => {
      if (mx < 0 || my < 0 || mx >= n || my >= n) return false;
      if (o.mirror) mx = n - 1 - mx;
      const v = rows[my][mx] === '1';
      return flips.has(my * n + mx) ? !v : v;
    };
    const side = Math.ceil((n + 2 * o.quiet) * o.scale * (o.angle ? 1.5 : 1));
    const data = new Uint8ClampedArray(side * side * 4);
    const rad = o.angle * Math.PI / 180, cos = Math.cos(rad), sin = Math.sin(rad), c = side / 2;
    for (let y = 0; y < side; y++) {
      for (let x = 0; x < side; x++) {
        // inverse-rotate the pixel back into code space
        const rx = cos * (x + 0.5 - c) + sin * (y + 0.5 - c) + c, ry = -sin * (x + 0.5 - c) + cos * (y + 0.5 - c) + c;
        const off = (side - (n + 2 * o.quiet) * o.scale) / 2;
        const mx = Math.floor((rx - off) / o.scale) - o.quiet, my = Math.floor((ry - off) / o.scale) - o.quiet;
        let d = dark(mx, my);
        if (o.invert) d = !d;
        const i = (y * side + x) * 4;
        const v = d ? 0 : 255;
        data[i] = data[i + 1] = data[i + 2] = v;
        data[i + 3] = o.transparent && !d ? 0 : 255;
      }
    }
    return { data, width: side, height: side };
  }
  const read = (fx, opts) => { const r = QR.decode(render(fx.rows, opts)); return r && r.text; };

  test('QR: error-correction tables match the size of every version', () => {
    for (let v = 1; v <= 40; v++) {
      const dim = 17 + 4 * v;
      const fn = I.functionMask(v);
      let free = 0;
      for (let i = 0; i < fn.length; i++) if (!fn[i]) free++;
      const total = Math.floor(free / 8);
      I.EC_BLOCKS[v - 1].forEach((spec, li) => {
        let sum = 0;
        for (let g = 1; g < spec.length; g += 2) sum += spec[g] * (spec[g + 1] + spec[0]);
        assert.equal(sum, total, `version ${v} level ${'LMQH'[li]} (${dim}x${dim})`);
      });
    }
  });

  test('QR: format and version codes are the standard ones', () => {
    assert.equal(I.FORMAT_CODES[0], 0x5412);
    assert.equal(I.FORMAT_CODES[8], 0x77c4);   // L, mask 0
    assert.equal(I.VERSION_CODES[7], 0x07c94);
    assert.equal(I.VERSION_CODES[40], 0x28c69);
  });

  test('QR: Reed-Solomon matches the standard\'s example and fixes up to half the EC codewords', () => {
    const mul = (a, b) => (a && b ? I.EXP[I.LOG[a] + I.LOG[b]] : 0);
    const encode = (data, ec) => {
      let gen = [1];
      for (let i = 0; i < ec; i++) {
        const next = new Array(gen.length + 1).fill(0);
        for (let j = 0; j < gen.length; j++) { next[j] ^= gen[j]; next[j + 1] ^= mul(gen[j], I.EXP[i]); }
        gen = next;
      }
      const rem = data.concat(new Array(ec).fill(0));
      for (let i = 0; i < data.length; i++) { const c = rem[i]; if (c) for (let j = 0; j < gen.length; j++) rem[i + j] ^= mul(gen[j], c); }
      return data.concat(rem.slice(data.length));
    };
    // ISO/IEC 18004 worked example: "01234567", version 1-M.
    const data = [16, 32, 12, 86, 97, 128, 236, 17, 236, 17, 236, 17, 236, 17, 236, 17];
    const block = encode(data, 10);
    assert.deepEqual(block.slice(16), [165, 36, 212, 193, 237, 54, 199, 135, 44, 85], 'EC codewords from the standard');
    const damaged = block.slice();
    [0, 5, 9, 17, 24].forEach(i => { damaged[i] ^= 0x5a; });
    assert.ok(I.rsCorrect(damaged, 10), 'corrects 5 errors with 10 EC codewords');
    assert.deepEqual(damaged, block);
    const clean = block.slice();
    assert.ok(I.rsCorrect(clean, 10) && JSON.stringify(clean) === JSON.stringify(block), 'clean block untouched');
  });

  test('QR: reads every fixture (versions 1-40, all levels and masks)', () => {
    const misses = [];
    for (const fx of FIX) {
      const scale = fx.rows.length > 120 ? 3 : 4;
      const got = read(fx, { scale });
      if (got !== fx.text) misses.push(`v${fx.version}-${fx.error} mask ${fx.mask} ${fx.mode}: got ${JSON.stringify(got && got.slice(0, 40))}`);
    }
    assert.equal(misses.length, 0, misses.join('\n'));
  });

  test('QR: numeric, alphanumeric, UTF-8 and kanji text decode exactly', () => {
    for (const mode of ['numeric', 'alphanumeric', 'kanji']) {
      const fx = FIX.find(f => f.mode === mode);
      assert.equal(read(fx), fx.text, mode);
    }
    const utf = FIX.find(f => /ü/.test(f.text));
    assert.equal(read(utf), utf.text);
  });

  test('QR: tiny, odd-sized and huge renderings', () => {
    const fx = FIX.find(f => f.version === 3 && f.error === 'M');
    assert.equal(read(fx, { scale: 1 }), fx.text, 'one pixel per module');
    assert.equal(read(fx, { scale: 2.6 }), fx.text, 'non-integer scale');
    assert.equal(read(fx, { scale: 9 }), fx.text, 'large modules');
    const big = FIX.find(f => f.version === 20);
    assert.equal(read(big, { scale: 14 }), big.text, 'image larger than 1200px is shrunk first');
  });

  test('QR: rotated, mirrored, inverted, transparent and borderless codes', () => {
    const fx = FIX.find(f => f.version === 5 && f.error === 'Q');
    assert.equal(read(fx, { angle: 90 }), fx.text, '90 degrees');
    assert.equal(read(fx, { angle: 17, scale: 6 }), fx.text, '17 degrees');
    assert.equal(read(fx, { mirror: true }), fx.text, 'mirror image');
    assert.equal(read(fx, { invert: true }), fx.text, 'light on dark');
    assert.equal(read(fx, { transparent: true }), fx.text, 'transparent background');
    assert.equal(read(fx, { quiet: 0 }), fx.text, 'no white border');
  });

  test('QR: damaged codes are repaired by error correction', () => {
    const fx = FIX.find(f => f.version === 4 && f.error === 'H');
    // Flip a cluster of modules in the data area (H level recovers ~30%).
    const flips = [];
    for (let y = 12; y < 18; y++) for (let x = 12; x < 18; x++) flips.push([x, y]);
    assert.equal(read(fx, { flips }), fx.text);
  });

  test('QR: images without a QR code return nothing', () => {
    const w = 120, h = 90, data = new Uint8ClampedArray(w * h * 4);
    let seed = 7;
    for (let i = 0; i < data.length; i += 4) { seed = (seed * 1103515245 + 12345) & 0x7fffffff; const v = seed % 256; data[i] = data[i + 1] = data[i + 2] = v; data[i + 3] = 255; }
    assert.equal(QR.decode({ data, width: w, height: h }), null, 'noise');
    assert.equal(QR.decode({ data: new Uint8ClampedArray(100 * 100 * 4).fill(255), width: 100, height: 100 }), null, 'blank');
    assert.equal(QR.decode({ data: new Uint8ClampedArray(16), width: 2, height: 2 }), null, 'tiny');
  });
});
