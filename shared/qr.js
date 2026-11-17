/*
 * QR code reader with no dependencies. Finds and decodes one QR code in an image so the link
 * inside can go through the same checks as any other link. Nothing is sent anywhere.
 *
 * Built for digital images (pictures in emails, PDFs, screenshots): it handles any size,
 * rotation, slight skew, light-on-dark codes and missing quiet zones, not photos of crumpled paper.
 *
 *   decode({ data: RGBA bytes, width, height }) -> { text, version, ecLevel } | null
 *
 * Pipeline: grayscale -> black/white -> find the three corner squares -> map the module grid
 * (perspective transform) -> read format/version info -> unmask -> Reed-Solomon correct -> parse.
 */
(function (root, factory) {
  const mod = factory();
  if (typeof module === 'object' && module.exports) module.exports = mod;
  else { root.PhishGuard = root.PhishGuard || {}; root.PhishGuard.qr = mod; }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const MAX_SIDE = 1200; // larger images are shrunk first (QR modules stay several pixels wide)

  // ---------- Galois field GF(256), primitive polynomial x^8+x^4+x^3+x^2+1 ----------
  const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
  (function () {
    let x = 1;
    for (let i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  })();
  const mul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);
  const div = (a, b) => (a ? EXP[(LOG[a] + 255 - LOG[b]) % 255] : 0);
  const pow = (a, n) => (a ? EXP[(LOG[a] * n) % 255] : 0);

  /** Correct a block in place (data codewords followed by EC codewords). Returns false if beyond repair. */
  function rsCorrect(cw, ecCount) {
    const n = cw.length;
    const S = new Array(ecCount);
    let errors = false;
    for (let j = 0; j < ecCount; j++) {
      let s = 0;
      const a = EXP[j];
      for (let k = 0; k < n; k++) s = mul(s, a) ^ cw[k];
      S[j] = s;
      if (s) errors = true;
    }
    if (!errors) return true;
    // Berlekamp-Massey: error locator polynomial C (ascending powers).
    let C = [1], B = [1], L = 0, m = 1, b = 1;
    for (let r = 0; r < ecCount; r++) {
      let d = S[r];
      for (let i = 1; i <= L; i++) d ^= mul(C[i] || 0, S[r - i]);
      if (d === 0) { m++; continue; }
      const coef = div(d, b);
      const T = C.slice();
      while (C.length < B.length + m) C.push(0);
      for (let i = 0; i < B.length; i++) C[i + m] ^= mul(coef, B[i]);
      if (2 * L <= r) { L = r + 1 - L; B = T; b = d; m = 1; } else m++;
    }
    while (C.length < L + 1) C.push(0);
    C.length = L + 1;
    if (2 * L > ecCount) return false;
    // Chien search: error at power p when C(alpha^-p) = 0.
    const powers = [];
    for (let p = 0; p < n; p++) {
      const xi = EXP[(255 - (p % 255)) % 255];
      let v = 0;
      for (let i = C.length - 1; i >= 0; i--) v = mul(v, xi) ^ C[i];
      if (v === 0) powers.push(p);
    }
    if (powers.length !== L) return false;
    // Forney: magnitudes from the evaluator polynomial.
    const O = new Array(ecCount).fill(0);
    for (let i = 0; i < ecCount; i++) for (let j = 0; j < C.length && i + j < ecCount; j++) O[i + j] ^= mul(S[i], C[j]);
    for (const p of powers) {
      const X = EXP[p % 255];
      const Xi = EXP[(255 - (p % 255)) % 255];
      let num = 0;
      for (let i = O.length - 1; i >= 0; i--) num = mul(num, Xi) ^ O[i];
      let den = 0;
      for (let i = 1; i < C.length; i += 2) den ^= mul(C[i], pow(Xi, i - 1));
      if (!den) return false;
      cw[n - 1 - p] ^= mul(X, div(num, den));
    }
    return true;
  }

  // ---------- version tables ----------
  // Error correction per version, levels in order L, M, Q, H: [ecPerBlock, count1, data1, count2?, data2?]
  const EC_BLOCKS = [
    [[7, 1, 19], [10, 1, 16], [13, 1, 13], [17, 1, 9]],
    [[10, 1, 34], [16, 1, 28], [22, 1, 22], [28, 1, 16]],
    [[15, 1, 55], [26, 1, 44], [18, 2, 17], [22, 2, 13]],
    [[20, 1, 80], [18, 2, 32], [26, 2, 24], [16, 4, 9]],
    [[26, 1, 108], [24, 2, 43], [18, 2, 15, 2, 16], [22, 2, 11, 2, 12]],
    [[18, 2, 68], [16, 4, 27], [24, 4, 19], [28, 4, 15]],
    [[20, 2, 78], [18, 4, 31], [18, 2, 14, 4, 15], [26, 4, 13, 1, 14]],
    [[24, 2, 97], [22, 2, 38, 2, 39], [22, 4, 18, 2, 19], [26, 4, 14, 2, 15]],
    [[30, 2, 116], [22, 3, 36, 2, 37], [20, 4, 16, 4, 17], [24, 4, 12, 4, 13]],
    [[18, 2, 68, 2, 69], [26, 4, 43, 1, 44], [24, 6, 19, 2, 20], [28, 6, 15, 2, 16]],
    [[20, 4, 81], [30, 1, 50, 4, 51], [28, 4, 22, 4, 23], [24, 3, 12, 8, 13]],
    [[24, 2, 92, 2, 93], [22, 6, 36, 2, 37], [26, 4, 20, 6, 21], [28, 7, 14, 4, 15]],
    [[26, 4, 107], [22, 8, 37, 1, 38], [24, 8, 20, 4, 21], [22, 12, 11, 4, 12]],
    [[30, 3, 115, 1, 116], [24, 4, 40, 5, 41], [20, 11, 16, 5, 17], [24, 11, 12, 5, 13]],
    [[22, 5, 87, 1, 88], [24, 5, 41, 5, 42], [30, 5, 24, 7, 25], [24, 11, 12, 7, 13]],
    [[24, 5, 98, 1, 99], [28, 7, 45, 3, 46], [24, 15, 19, 2, 20], [30, 3, 15, 13, 16]],
    [[28, 1, 107, 5, 108], [28, 10, 46, 1, 47], [28, 1, 22, 15, 23], [28, 2, 14, 17, 15]],
    [[30, 5, 120, 1, 121], [26, 9, 43, 4, 44], [28, 17, 22, 1, 23], [28, 2, 14, 19, 15]],
    [[28, 3, 113, 4, 114], [26, 3, 44, 11, 45], [26, 17, 21, 4, 22], [26, 9, 13, 16, 14]],
    [[28, 3, 107, 5, 108], [26, 3, 41, 13, 42], [30, 15, 24, 5, 25], [28, 15, 15, 10, 16]],
    [[28, 4, 116, 4, 117], [26, 17, 42], [28, 17, 22, 6, 23], [30, 19, 16, 6, 17]],
    [[28, 2, 111, 7, 112], [28, 17, 46], [30, 7, 24, 16, 25], [24, 34, 13]],
    [[30, 4, 121, 5, 122], [28, 4, 47, 14, 48], [30, 11, 24, 14, 25], [30, 16, 15, 14, 16]],
    [[30, 6, 117, 4, 118], [28, 6, 45, 14, 46], [30, 11, 24, 16, 25], [30, 30, 16, 2, 17]],
    [[26, 8, 106, 4, 107], [28, 8, 47, 13, 48], [30, 7, 24, 22, 25], [30, 22, 15, 13, 16]],
    [[28, 10, 114, 2, 115], [28, 19, 46, 4, 47], [28, 28, 22, 6, 23], [30, 33, 16, 4, 17]],
    [[30, 8, 122, 4, 123], [28, 22, 45, 3, 46], [30, 8, 23, 26, 24], [30, 12, 15, 28, 16]],
    [[30, 3, 117, 10, 118], [28, 3, 45, 23, 46], [30, 4, 24, 31, 25], [30, 11, 15, 31, 16]],
    [[30, 7, 116, 7, 117], [28, 21, 45, 7, 46], [30, 1, 23, 37, 24], [30, 19, 15, 26, 16]],
    [[30, 5, 115, 10, 116], [28, 19, 47, 10, 48], [30, 15, 24, 25, 25], [30, 23, 15, 25, 16]],
    [[30, 13, 115, 3, 116], [28, 2, 46, 29, 47], [30, 42, 24, 1, 25], [30, 23, 15, 28, 16]],
    [[30, 17, 115], [28, 10, 46, 23, 47], [30, 10, 24, 35, 25], [30, 19, 15, 35, 16]],
    [[30, 17, 115, 1, 116], [28, 14, 46, 21, 47], [30, 29, 24, 19, 25], [30, 11, 15, 46, 16]],
    [[30, 13, 115, 6, 116], [28, 14, 46, 23, 47], [30, 44, 24, 7, 25], [30, 59, 16, 1, 17]],
    [[30, 12, 121, 7, 122], [28, 12, 47, 26, 48], [30, 39, 24, 14, 25], [30, 22, 15, 41, 16]],
    [[30, 6, 121, 14, 122], [28, 6, 47, 34, 48], [30, 46, 24, 10, 25], [30, 2, 15, 64, 16]],
    [[30, 17, 122, 4, 123], [28, 29, 46, 14, 47], [30, 49, 24, 10, 25], [30, 24, 15, 46, 16]],
    [[30, 4, 122, 18, 123], [28, 13, 46, 32, 47], [30, 48, 24, 14, 25], [30, 42, 15, 32, 16]],
    [[30, 20, 117, 4, 118], [28, 40, 47, 7, 48], [30, 43, 24, 22, 25], [30, 10, 15, 67, 16]],
    [[30, 19, 118, 6, 119], [28, 18, 47, 31, 48], [30, 34, 24, 34, 25], [30, 20, 15, 61, 16]]
  ];
  const LEVELS = ['L', 'M', 'Q', 'H'];
  const LEVEL_FROM_BITS = ['M', 'L', 'H', 'Q']; // format info's 2 EC bits

  // Alignment pattern centre coordinates per version (version 1 has none).
  const ALIGN = [[], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
    [6, 30, 54], [6, 32, 58], [6, 34, 62], [6, 26, 46, 66], [6, 26, 48, 70], [6, 26, 50, 74], [6, 30, 54, 78],
    [6, 30, 56, 82], [6, 30, 58, 86], [6, 34, 62, 90], [6, 28, 50, 72, 94], [6, 26, 50, 74, 98], [6, 30, 54, 78, 102],
    [6, 28, 54, 80, 106], [6, 32, 58, 84, 110], [6, 30, 58, 86, 114], [6, 34, 62, 90, 118], [6, 26, 50, 74, 98, 122],
    [6, 30, 54, 78, 102, 126], [6, 26, 52, 78, 104, 130], [6, 30, 56, 82, 108, 134], [6, 34, 60, 86, 112, 138],
    [6, 30, 58, 86, 114, 142], [6, 34, 62, 90, 118, 146], [6, 30, 54, 78, 102, 126, 150], [6, 24, 50, 76, 102, 128, 154],
    [6, 28, 54, 80, 106, 132, 158], [6, 32, 58, 84, 110, 136, 162], [6, 26, 54, 82, 110, 138, 166], [6, 30, 58, 86, 114, 142, 170]];

  // BCH codes for the format (15,5) and version (18,6) information, computed rather than typed in.
  const msb = v => 31 - Math.clz32(v);
  function bchRemainder(value, poly) {
    let v = value << msb(poly);
    while (v && msb(v) >= msb(poly)) v ^= poly << (msb(v) - msb(poly));
    return v;
  }
  const FORMAT_CODES = Array.from({ length: 32 }, (_, d) => ((d << 10) | bchRemainder(d, 0x537)) ^ 0x5412);
  const VERSION_CODES = Array.from({ length: 41 }, (_, v) => (v >= 7 ? (v << 12) | bchRemainder(v, 0x1f25) : -1));
  const popcount = v => { let c = 0; while (v) { v &= v - 1; c++; } return c; };

  // Function patterns (finders, timing, alignment, format/version areas) per version.
  const functionCache = new Map();
  function functionMask(version) {
    if (functionCache.has(version)) return functionCache.get(version);
    const dim = 17 + 4 * version;
    const f = new Uint8Array(dim * dim);
    const region = (left, top, w, h) => {
      for (let y = top; y < top + h; y++) for (let x = left; x < left + w; x++) f[y * dim + x] = 1;
    };
    region(0, 0, 9, 9);
    region(dim - 8, 0, 8, 9);
    region(0, dim - 8, 9, 8);
    const a = ALIGN[version - 1];
    const max = a.length;
    for (let i = 0; i < max; i++) {
      for (let j = 0; j < max; j++) {
        if ((i === 0 && (j === 0 || j === max - 1)) || (i === max - 1 && j === 0)) continue;
        region(a[i] - 2, a[j] - 2, 5, 5);
      }
    }
    region(6, 9, 1, dim - 17);
    region(9, 6, dim - 17, 1);
    if (version > 6) { region(dim - 11, 0, 3, 6); region(0, dim - 11, 6, 3); }
    functionCache.set(version, f);
    return f;
  }

  const MASKS = [
    (i, j) => (i + j) % 2 === 0,
    i => i % 2 === 0,
    (i, j) => j % 3 === 0,
    (i, j) => (i + j) % 3 === 0,
    (i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0,
    (i, j) => ((i * j) % 2) + ((i * j) % 3) === 0,
    (i, j) => (((i * j) % 2) + ((i * j) % 3)) % 2 === 0,
    (i, j) => (((i + j) % 2) + ((i * j) % 3)) % 2 === 0
  ];

  // ---------- reading a sampled module grid ----------
  // M[y * dim + x] = 1 for dark.
  function readFormat(M, dim) {
    const g = (x, y) => M[y * dim + x];
    let a = 0, b = 0;
    const push = (v, bit) => (v << 1) | bit;
    for (let x = 0; x < 6; x++) a = push(a, g(x, 8));
    a = push(a, g(7, 8)); a = push(a, g(8, 8)); a = push(a, g(8, 7));
    for (let y = 5; y >= 0; y--) a = push(a, g(8, y));
    for (let y = dim - 1; y >= dim - 7; y--) b = push(b, g(8, y));
    for (let x = dim - 8; x < dim; x++) b = push(b, g(x, 8));
    let best = 99, bestD = -1;
    for (let d = 0; d < 32; d++) {
      const dist = Math.min(popcount(a ^ FORMAT_CODES[d]), popcount(b ^ FORMAT_CODES[d]));
      if (dist < best) { best = dist; bestD = d; }
    }
    return best <= 3 ? { level: LEVEL_FROM_BITS[(bestD >> 3) & 3], mask: bestD & 7 } : null;
  }

  function readVersion(M, dim) {
    const g = (x, y) => M[y * dim + x];
    let a = 0, b = 0;
    for (let y = 5; y >= 0; y--) for (let x = dim - 9; x >= dim - 11; x--) a = (a << 1) | g(x, y);
    for (let x = 5; x >= 0; x--) for (let y = dim - 9; y >= dim - 11; y--) b = (b << 1) | g(x, y);
    let best = 99, bestV = -1;
    for (let v = 7; v <= 40; v++) {
      const dist = Math.min(popcount(a ^ VERSION_CODES[v]), popcount(b ^ VERSION_CODES[v]));
      if (dist < best) { best = dist; bestV = v; }
    }
    return best <= 3 ? bestV : 0;
  }

  function readCodewords(M, dim, version, mask) {
    const fn = functionMask(version);
    const maskFn = MASKS[mask];
    const out = [];
    let up = true, cur = 0, bits = 0;
    for (let j = dim - 1; j > 0; j -= 2) {
      if (j === 6) j--;
      for (let count = 0; count < dim; count++) {
        const i = up ? dim - 1 - count : count;
        for (let col = 0; col < 2; col++) {
          const x = j - col;
          if (fn[i * dim + x]) continue;
          cur = (cur << 1) | (M[i * dim + x] ^ (maskFn(i, x) ? 1 : 0));
          if (++bits === 8) { out.push(cur); cur = 0; bits = 0; }
        }
      }
      up = !up;
    }
    return out;
  }

  // Split interleaved codewords into blocks, correct each, return the data codewords.
  function correctedData(raw, version, level) {
    const spec = EC_BLOCKS[version - 1][LEVELS.indexOf(level)];
    const ec = spec[0];
    const blocks = [];
    for (let g = 1; g < spec.length; g += 2) {
      for (let k = 0; k < spec[g]; k++) blocks.push({ data: spec[g + 1], cw: new Array(spec[g + 1] + ec) });
    }
    const total = blocks.reduce((s, b) => s + b.cw.length, 0);
    if (raw.length < total) return null;
    const shortLen = blocks[0].cw.length;
    let longStart = blocks.length;
    while (longStart > 0 && blocks[longStart - 1].cw.length !== shortLen) longStart--;
    const shortData = shortLen - ec;
    let o = 0;
    for (let i = 0; i < shortData; i++) for (const b of blocks) b.cw[i] = raw[o++];
    for (let j = longStart; j < blocks.length; j++) blocks[j].cw[shortData] = raw[o++];
    const maxLen = blocks[0].cw.length > blocks[blocks.length - 1].cw.length ? blocks[0].cw.length : blocks[blocks.length - 1].cw.length;
    for (let i = shortData; i < maxLen; i++) {
      for (let j = 0; j < blocks.length; j++) {
        const at = j < longStart ? i : i + 1;
        if (at < blocks[j].cw.length) blocks[j].cw[at] = raw[o++];
      }
    }
    const data = [];
    for (const b of blocks) {
      if (!rsCorrect(b.cw, ec)) return null;
      for (let i = 0; i < b.data; i++) data.push(b.cw[i]);
    }
    return data;
  }

  // ---------- bit stream -> text ----------
  const ALNUM = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
  function decodeBytes(bytes, eci) {
    const u8 = Uint8Array.from(bytes);
    const tryDecode = (label, fatal) => { try { return new TextDecoder(label, { fatal }).decode(u8); } catch (e) { return null; } };
    if (eci === 20) { const s = tryDecode('shift_jis', true); if (s != null) return s; }
    if (eci === 3 || eci === 1) return bytes.map(b => String.fromCharCode(b)).join('');
    const utf8 = tryDecode('utf-8', true);
    return utf8 != null ? utf8 : bytes.map(b => String.fromCharCode(b)).join('');
  }

  function parseData(data, version) {
    let pos = 0;
    const left = () => data.length * 8 - pos;
    const read = n => {
      let v = 0;
      for (let i = 0; i < n; i++) { v = (v << 1) | ((data[(pos >> 3)] >> (7 - (pos & 7))) & 1); pos++; }
      return v;
    };
    const sizeIdx = version <= 9 ? 0 : version <= 26 ? 1 : 2;
    let text = '', eci = null;
    while (left() >= 4) {
      const mode = read(4);
      if (mode === 0) break;
      if (mode === 7) { // ECI
        const first = read(8);
        eci = (first & 0x80) === 0 ? first : (first & 0xc0) === 0x80 ? ((first & 0x3f) << 8) | read(8) : ((first & 0x1f) << 16) | read(16);
        continue;
      }
      if (mode === 3) { read(16); continue; } // structured append header
      if (mode === 5) continue;               // FNC1 (first position)
      if (mode === 9) { read(8); continue; }  // FNC1 (second position)
      if (mode === 1) {
        let n = read([10, 12, 14][sizeIdx]);
        if (left() < Math.floor(n / 3) * 10) return null;
        while (n >= 3) { const v = read(10); if (v > 999) return null; text += String(v).padStart(3, '0'); n -= 3; }
        if (n === 2) { const v = read(7); if (v > 99) return null; text += String(v).padStart(2, '0'); }
        else if (n === 1) { const v = read(4); if (v > 9) return null; text += String(v); }
      } else if (mode === 2) {
        let n = read([9, 11, 13][sizeIdx]);
        while (n >= 2) { const v = read(11); if (v >= 45 * 45) return null; text += ALNUM[Math.floor(v / 45)] + ALNUM[v % 45]; n -= 2; }
        if (n === 1) { const v = read(6); if (v >= 45) return null; text += ALNUM[v]; }
      } else if (mode === 4) {
        const n = read([8, 16, 16][sizeIdx]);
        if (left() < n * 8) return null;
        const bytes = [];
        for (let i = 0; i < n; i++) bytes.push(read(8));
        text += decodeBytes(bytes, eci);
      } else if (mode === 8) {
        const n = read([8, 10, 12][sizeIdx]);
        if (left() < n * 13) return null;
        const bytes = [];
        for (let i = 0; i < n; i++) {
          const v = read(13);
          let w = (Math.floor(v / 0xc0) << 8) | (v % 0xc0);
          w += w < 0x1f00 ? 0x8140 : 0xc140;
          bytes.push(w >> 8, w & 0xff);
        }
        text += decodeBytes(bytes, 20);
      } else {
        return null; // unknown mode: not a valid stream
      }
    }
    return text;
  }

  function decodeMatrix(M, dim) {
    if (dim < 21 || dim > 177 || (dim - 17) % 4) return null;
    const format = readFormat(M, dim);
    if (!format) return null;
    const version = (dim - 17) / 4;
    if (version >= 7) {
      const v = readVersion(M, dim);
      if (v && v !== version) return { retryDim: 17 + 4 * v };
    }
    const raw = readCodewords(M, dim, version, format.mask);
    const data = correctedData(raw, version, format.level);
    if (!data) return null;
    const text = parseData(data, version);
    return text == null ? null : { text, version, ecLevel: format.level };
  }

  // ---------- image -> black/white ----------
  function toGray(img) {
    const { data, width, height } = img;
    let w = width, h = height, step = 1;
    if (Math.max(w, h) > MAX_SIDE) { step = Math.ceil(Math.max(w, h) / MAX_SIDE); w = Math.floor(width / step); h = Math.floor(height / step); }
    const g = new Uint8Array(w * h);
    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        let sum = 0;
        for (let dy = 0; dy < step; dy++) {
          for (let dx = 0; dx < step; dx++) {
            const i = ((y * step + dy) * width + (x * step + dx)) * 4;
            const a = data[i + 3];
            const l = (data[i] * 77 + data[i + 1] * 150 + data[i + 2] * 29) >> 8;
            sum += a === 255 ? l : (l * a + 255 * (255 - a)) / 255; // transparent = white paper
          }
        }
        g[y * w + x] = sum / (step * step);
      }
    }
    return { g, w, h };
  }

  function otsu(g) {
    const hist = new Float64Array(256);
    for (let i = 0; i < g.length; i++) hist[g[i]]++;
    let sum = 0;
    for (let i = 0; i < 256; i++) sum += i * hist[i];
    let sumB = 0, wB = 0, best = 0, t = 128;
    for (let i = 0; i < 256; i++) {
      wB += hist[i];
      if (!wB) continue;
      const wF = g.length - wB;
      if (!wF) break;
      sumB += i * hist[i];
      const mB = sumB / wB, mF = (sum - sumB) / wF;
      const between = wB * wF * (mB - mF) * (mB - mF);
      if (between > best) { best = between; t = i; }
    }
    const bits = new Uint8Array(g.length);
    for (let i = 0; i < g.length; i++) bits[i] = g[i] <= t ? 1 : 0;
    return bits;
  }

  // Local-average threshold for uneven backgrounds (gradients, shadows in screenshots).
  function adaptive(g, w, h) {
    const I = new Float64Array((w + 1) * (h + 1));
    for (let y = 0; y < h; y++) {
      let row = 0;
      for (let x = 0; x < w; x++) { row += g[y * w + x]; I[(y + 1) * (w + 1) + x + 1] = I[y * (w + 1) + x + 1] + row; }
    }
    const r = Math.max(7, Math.min(60, Math.round(Math.min(w, h) / 10)));
    const bits = new Uint8Array(g.length);
    for (let y = 0; y < h; y++) {
      const y0 = Math.max(0, y - r), y1 = Math.min(h, y + r + 1);
      for (let x = 0; x < w; x++) {
        const x0 = Math.max(0, x - r), x1 = Math.min(w, x + r + 1);
        const mean = (I[y1 * (w + 1) + x1] - I[y0 * (w + 1) + x1] - I[y1 * (w + 1) + x0] + I[y0 * (w + 1) + x0]) / ((x1 - x0) * (y1 - y0));
        const v = g[y * w + x];
        bits[y * w + x] = v < mean - 4 && v < mean * 0.94 ? 1 : 0;
      }
    }
    return bits;
  }

  // ---------- finder patterns (the three big corner squares, 1:1:3:1:1) ----------
  function ratioOk(c) {
    const total = c[0] + c[1] + c[2] + c[3] + c[4];
    if (total < 7) return false;
    const m = total / 7, v = m / 2;
    return Math.abs(m - c[0]) < v && Math.abs(m - c[1]) < v && Math.abs(3 * m - c[2]) < 3 * v && Math.abs(m - c[3]) < v && Math.abs(m - c[4]) < v;
  }

  // Run lengths along a line through (x, y); returns the pattern centre offset or NaN.
  function crossCheck(bits, w, h, x, y, dx, dy, maxCount, origTotal) {
    const get = i => {
      const px = x + dx * i, py = y + dy * i;
      return px < 0 || py < 0 || px >= w || py >= h ? -1 : bits[py * w + px];
    };
    const c = [0, 0, 0, 0, 0];
    let i = 0;
    if (get(0) !== 1) return NaN;
    while (get(i) === 1) { c[2]++; i--; }
    while (get(i) === 0 && c[1] <= maxCount) { c[1]++; i--; }
    if (get(i) !== 1 || c[1] > maxCount) return NaN;
    while (get(i) === 1 && c[0] <= maxCount) { c[0]++; i--; }
    if (c[0] > maxCount) return NaN;
    i = 1;
    while (get(i) === 1) { c[2]++; i++; }
    while (get(i) === 0 && c[3] <= maxCount) { c[3]++; i++; }
    if (get(i) !== 1 || c[3] > maxCount) return NaN;
    while (get(i) === 1 && c[4] <= maxCount) { c[4]++; i++; }
    if (c[4] > maxCount) return NaN;
    const total = c[0] + c[1] + c[2] + c[3] + c[4];
    if (5 * Math.abs(total - origTotal) >= 2 * origTotal || !ratioOk(c)) return NaN;
    return i - c[4] - c[3] - c[2] / 2;
  }

  function findFinders(bits, w, h) {
    const centers = [];
    const add = (x, y, size) => {
      for (const c of centers) {
        if (Math.abs(c.x - x) <= c.size * 1.5 && Math.abs(c.y - y) <= c.size * 1.5 && Math.abs(c.size - size) <= Math.max(1, c.size * 0.5)) {
          const n = c.count;
          c.x = (c.x * n + x) / (n + 1); c.y = (c.y * n + y) / (n + 1); c.size = (c.size * n + size) / (n + 1); c.count++;
          return;
        }
      }
      centers.push({ x, y, size, count: 1 });
    };
    const lens = [], starts = [];
    for (let y = 0; y < h && centers.length < 200; y++) {
      lens.length = 0; starts.length = 0;
      const row = y * w;
      let first = bits[row];
      let x = 0;
      while (x < w) {
        const c = bits[row + x];
        const s = x;
        while (x < w && bits[row + x] === c) x++;
        starts.push(s); lens.push(x - s);
      }
      // runs alternate colours; find black-starting windows of five
      for (let i = first === 1 ? 0 : 1; i + 4 < lens.length; i += 2) {
        const c = [lens[i], lens[i + 1], lens[i + 2], lens[i + 3], lens[i + 4]];
        if (!ratioOk(c)) continue;
        const total = c[0] + c[1] + c[2] + c[3] + c[4];
        const cx = Math.floor(starts[i + 2] + lens[i + 2] / 2);
        const offY = crossCheck(bits, w, h, cx, y, 0, 1, c[2], total);
        if (isNaN(offY)) continue;
        const cy = Math.floor(y + offY);
        const offX = crossCheck(bits, w, h, cx, cy, 1, 0, c[2], total);
        if (isNaN(offX)) continue;
        add(cx + offX, y + offY, total / 7);
      }
    }
    return centers;
  }

  // Module size measured along the line between two finder centres (robust to rotation).
  function moduleAlong(bits, w, h, a, b) {
    const dx = b.x - a.x, dy = b.y - a.y;
    const len = Math.hypot(dx, dy);
    const ux = dx / len, uy = dy / len;
    const runTo = sign => {
      // centre (black) -> white ring -> black ring -> stop at next white
      let state = 0, t = 0;
      const limit = a.size * 12;
      while (t < limit) {
        const px = Math.floor(a.x + ux * t * sign), py = Math.floor(a.y + uy * t * sign);
        if (px < 0 || py < 0 || px >= w || py >= h) return state === 2 ? t : NaN;
        const v = bits[py * w + px];
        if (state === 0 && v === 0) state = 1;
        else if (state === 1 && v === 1) state = 2;
        else if (state === 2 && v === 0) return t;
        t += 0.5;
      }
      return NaN;
    };
    const s = runTo(1) + runTo(-1);
    return isNaN(s) ? a.size : s / 7;
  }

  function chooseTriples(centers) {
    let pool = centers.filter(c => c.count >= 2);
    if (pool.length < 3) pool = centers.slice();
    pool.sort((p, q) => q.count - p.count);
    pool = pool.slice(0, 12);
    const out = [];
    const d2 = (p, q) => (p.x - q.x) ** 2 + (p.y - q.y) ** 2;
    for (let i = 0; i < pool.length; i++) {
      for (let j = i + 1; j < pool.length; j++) {
        for (let k = j + 1; k < pool.length; k++) {
          const P = [pool[i], pool[j], pool[k]];
          const sizes = P.map(p => p.size);
          if (Math.max(...sizes) / Math.min(...sizes) > 1.6) continue;
          const pairs = [[0, 1, 2], [0, 2, 1], [1, 2, 0]].map(([a, b, c]) => ({ a, b, c, d: d2(P[a], P[b]) }));
          pairs.sort((p, q) => q.d - p.d);
          const hyp = pairs[0];
          const A = P[hyp.c];
          let B = P[hyp.a], C = P[hyp.b];
          const l1 = Math.sqrt(d2(A, B)), l2 = Math.sqrt(d2(A, C));
          const legDiff = Math.abs(l1 - l2) / Math.max(l1, l2);
          const angle = Math.abs(hyp.d - (l1 * l1 + l2 * l2)) / hyp.d;
          const avgSize = (sizes[0] + sizes[1] + sizes[2]) / 3;
          if (legDiff > 0.3 || angle > 0.25 || Math.min(l1, l2) < avgSize * 12) continue;
          if ((B.x - A.x) * (C.y - A.y) - (B.y - A.y) * (C.x - A.x) < 0) { const t = B; B = C; C = t; }
          out.push({ A, B, C, score: legDiff + angle + (Math.max(...sizes) - Math.min(...sizes)) / avgSize });
        }
      }
    }
    out.sort((p, q) => p.score - q.score);
    return out.slice(0, 4);
  }

  // ---------- perspective transform (unit square <-> quadrilateral) ----------
  function squareToQuad(x0, y0, x1, y1, x2, y2, x3, y3) {
    const dx3 = x0 - x1 + x2 - x3, dy3 = y0 - y1 + y2 - y3;
    if (Math.abs(dx3) < 1e-9 && Math.abs(dy3) < 1e-9) return [x1 - x0, x2 - x1, x0, y1 - y0, y2 - y1, y0, 0, 0, 1];
    const dx1 = x1 - x2, dx2 = x3 - x2, dy1 = y1 - y2, dy2 = y3 - y2;
    const den = dx1 * dy2 - dx2 * dy1;
    const a13 = (dx3 * dy2 - dx2 * dy3) / den, a23 = (dx1 * dy3 - dx3 * dy1) / den;
    return [x1 - x0 + a13 * x1, x3 - x0 + a23 * x3, x0, y1 - y0 + a13 * y1, y3 - y0 + a23 * y3, y0, a13, a23, 1];
  }
  function adjoint(m) {
    const [a11, a21, a31, a12, a22, a32, a13, a23, a33] = m;
    return [a22 * a33 - a23 * a32, a23 * a31 - a21 * a33, a21 * a32 - a22 * a31,
      a13 * a32 - a12 * a33, a11 * a33 - a13 * a31, a12 * a31 - a11 * a32,
      a12 * a23 - a13 * a22, a13 * a21 - a11 * a23, a11 * a22 - a12 * a21];
  }
  function times(m, o) {
    const [a11, a21, a31, a12, a22, a32, a13, a23, a33] = m;
    const [b11, b21, b31, b12, b22, b32, b13, b23, b33] = o;
    return [a11 * b11 + a21 * b12 + a31 * b13, a11 * b21 + a21 * b22 + a31 * b23, a11 * b31 + a21 * b32 + a31 * b33,
      a12 * b11 + a22 * b12 + a32 * b13, a12 * b21 + a22 * b22 + a32 * b23, a12 * b31 + a22 * b32 + a32 * b33,
      a13 * b11 + a23 * b12 + a33 * b13, a13 * b21 + a23 * b22 + a33 * b23, a13 * b31 + a23 * b32 + a33 * b33];
  }
  function quadToQuad(src, dst) {
    return times(squareToQuad(...dst), adjoint(squareToQuad(...src)));
  }
  function apply(m, x, y) {
    const d = m[6] * x + m[7] * y + m[8];
    return [(m[0] * x + m[1] * y + m[2]) / d, (m[3] * x + m[4] * y + m[5]) / d];
  }

  function sample(bits, w, h, m, dim) {
    const M = new Uint8Array(dim * dim);
    for (let y = 0; y < dim; y++) {
      for (let x = 0; x < dim; x++) {
        const [px, py] = apply(m, x + 0.5, y + 0.5);
        const ix = Math.floor(px), iy = Math.floor(py);
        M[y * dim + x] = ix >= 0 && iy >= 0 && ix < w && iy < h ? bits[iy * w + ix] : 0;
      }
    }
    return M;
  }

  // Look for the bottom-right alignment pattern (dark centre, light ring, dark ring) near its
  // expected spot; used to correct perspective on skewed images.
  function findAlignment(bits, w, h, ex, ey, ms) {
    const at = (x, y) => {
      const ix = Math.floor(x), iy = Math.floor(y);
      return ix >= 0 && iy >= 0 && ix < w && iy < h ? bits[iy * w + ix] : -1;
    };
    const ring = [[-1, -1], [0, -1], [1, -1], [-1, 0], [1, 0], [-1, 1], [0, 1], [1, 1]];
    let best = null, bestScore = 0;
    const radius = ms * 6, step = Math.max(1, ms / 4);
    for (let y = ey - radius; y <= ey + radius; y += step) {
      for (let x = ex - radius; x <= ex + radius; x += step) {
        if (at(x, y) !== 1) continue;
        let score = 1;
        for (const [dx, dy] of ring) { if (at(x + dx * ms, y + dy * ms) === 0) score++; if (at(x + dx * ms * 2, y + dy * ms * 2) === 1) score++; }
        const dist = Math.hypot(x - ex, y - ey) / ms;
        const s = score - dist * 0.05;
        if (score >= 15 && s > bestScore) { bestScore = s; best = [x, y]; }
      }
    }
    return best;
  }

  function decodeBits(bits, w, h) {
    const triples = chooseTriples(findFinders(bits, w, h));
    for (const { A, B, C } of triples) {
      const ms = (moduleAlong(bits, w, h, A, B) + moduleAlong(bits, w, h, A, C) + moduleAlong(bits, w, h, B, A) + moduleAlong(bits, w, h, C, A)) / 4;
      const rawDim = (Math.hypot(B.x - A.x, B.y - A.y) + Math.hypot(C.x - A.x, C.y - A.y)) / 2 / ms + 7;
      const dims = [];
      for (let d = 21; d <= 177; d += 4) if (Math.abs(d - rawDim) <= 8.5) dims.push(d);
      dims.sort((p, q) => Math.abs(p - rawDim) - Math.abs(q - rawDim));
      const tried = new Set();
      while (dims.length) {
        const dim = dims.shift();
        if (tried.has(dim)) continue;
        tried.add(dim);
        const src = [3.5, 3.5, dim - 3.5, 3.5, dim - 3.5, dim - 3.5, 3.5, dim - 3.5];
        const dst = [A.x, A.y, B.x, B.y, B.x + C.x - A.x, B.y + C.y - A.y, C.x, C.y];
        const transforms = [quadToQuad(src, dst)];
        if (dim > 21) {
          const [ex, ey] = apply(transforms[0], dim - 6.5, dim - 6.5);
          const al = findAlignment(bits, w, h, ex, ey, ms);
          if (al) transforms.push(quadToQuad([3.5, 3.5, dim - 3.5, 3.5, dim - 6.5, dim - 6.5, 3.5, dim - 3.5], [A.x, A.y, B.x, B.y, al[0], al[1], C.x, C.y]));
        }
        for (const m of transforms) {
          const M = sample(bits, w, h, m, dim);
          for (const grid of [M, transpose(M, dim)]) { // transposed = mirror-image code
            const r = decodeMatrix(grid, dim);
            if (r && r.retryDim) { if (!tried.has(r.retryDim)) dims.unshift(r.retryDim); continue; }
            if (r) return r;
          }
        }
      }
    }
    return null;
  }

  function transpose(M, dim) {
    const T = new Uint8Array(dim * dim);
    for (let y = 0; y < dim; y++) for (let x = 0; x < dim; x++) T[x * dim + y] = M[y * dim + x];
    return T;
  }

  /**
   * Decode the QR code in an image. Returns null when there is none (or it can't be read).
   * @param {{ data: Uint8ClampedArray|Uint8Array, width: number, height: number }} img RGBA pixels
   */
  function decode(img) {
    if (!img || !img.width || !img.height || img.width < 21 || img.height < 21) return null;
    const { g, w, h } = toGray(img);
    for (const binarize of [otsu, adaptive]) {
      const bits = binarize(g, w, h);
      let r = decodeBits(bits, w, h);
      if (r) return r;
      for (let i = 0; i < bits.length; i++) bits[i] ^= 1; // light code on a dark background
      r = decodeBits(bits, w, h);
      if (r) return r;
    }
    return null;
  }

  /** What a QR code says, as a link the link checks understand (or null if it isn't one). */
  function toLink(text) {
    const t = String(text || '').trim();
    if (!t || t.length > 2000) return null;
    if (/^https?:\/\/\S+$/i.test(t)) return t;
    if (/^(mailto|tel|sms):/i.test(t)) return t;
    if (/^smsto:/i.test(t)) return 'sms:' + t.slice(6);
    if (/^www\.\S+$/i.test(t)) return 'https://' + t;
    if (/^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}(\/\S*)?$/i.test(t)) return 'https://' + t;
    return null;
  }

  return { decode, toLink, _internal: { rsCorrect, decodeMatrix, functionMask, EC_BLOCKS, ALIGN, FORMAT_CODES, VERSION_CODES, EXP, LOG } };
});
