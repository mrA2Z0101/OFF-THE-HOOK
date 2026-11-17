/*
 * DEV ONLY. Builds the Chrome Web Store images in store/ at the exact sizes the store asks for:
 *
 *   screenshot-1..5-*.png      1280x800   (store listing > Screenshots)
 *   promo-small-440x280.png    440x280    (store listing > Small promo tile)
 *   promo-marquee-1400x560.png 1400x560   (store listing > Marquee promo tile)
 *
 * Every picture of the product is the real UI: the on-page parts come from dev/demo.html (the
 * real content scripts on fictional emails), and the file checker and settings come from the
 * extension itself, loaded unpacked. dev/store.html lays them out.
 *
 * Needs Playwright, which is not a dependency of the extension:
 *     npm install --no-save playwright && npx playwright install chromium
 *     node scripts/store_assets.js
 *
 * The UI uses Impact for its headings. Where Impact isn't installed (Linux), the free look-alike
 * Anton is fetched from Google Fonts for the photos; nothing is added to the extension.
 */
'use strict';
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { chromium } = require('playwright');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'store');
const ART = [
  { id: 'shot-1', file: 'screenshot-1-catches-phishing.png', w: 1280, h: 800 },
  { id: 'shot-2', file: 'screenshot-2-link-check.png', w: 1280, h: 800 },
  { id: 'shot-3', file: 'screenshot-3-inbox-tags.png', w: 1280, h: 800 },
  { id: 'shot-4', file: 'screenshot-4-file-checker.png', w: 1280, h: 800 },
  { id: 'shot-5', file: 'screenshot-5-privacy.png', w: 1280, h: 800 },
  { id: 'promo-small', file: 'promo-small-440x280.png', w: 440, h: 280 },
  { id: 'promo-marquee', file: 'promo-marquee-1400x560.png', w: 1400, h: 560 }
];

// ---------- tiny static server for the repo (the demo page loads its scripts over http) ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg' };
function serve() {
  const server = http.createServer((req, res) => {
    const file = path.join(ROOT, decodeURIComponent(new URL(req.url, 'http://x').pathname));
    if (!file.startsWith(ROOT + path.sep)) { res.writeHead(403).end(); return; }
    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(404).end(); return; }
      res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
      res.end(data);
    });
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)));
}

// ---------- Impact stand-in for machines without it ----------
async function impactScript(browser) {
  // Only this page goes online, so only it uses the machine's proxy (if there is one).
  const ctx = await browser.newContext(process.env.HTTPS_PROXY ? { proxy: { server: process.env.HTTPS_PROXY } } : {});
  const page = await ctx.newPage();
  const dataUrl = await page.evaluate(async () => {
    const c = document.createElement('canvas').getContext('2d');
    const width = font => { c.font = '72px ' + font; return c.measureText('OFF THE HOOK').width; };
    if (width('Impact, monospace') !== width('monospace')) return 'installed';
    const css = await (await fetch('https://fonts.googleapis.com/css2?family=Anton')).text();
    const url = [...css.matchAll(/url\((https:[^)]+\.woff2)\)/g)].pop()[1]; // last block is Latin
    const bytes = new Uint8Array(await (await fetch(url)).arrayBuffer());
    let bin = ''; for (const b of bytes) bin += String.fromCharCode(b);
    return 'data:font/woff2;base64,' + btoa(bin);
  }).catch(() => null);
  await ctx.close();
  if (dataUrl === 'installed') { console.log('Headings use the installed Impact.'); return null; }
  if (!dataUrl) { console.log('Impact is not installed and Anton could not be fetched: headings use a fallback font.'); return null; }
  console.log('Impact is not installed: headings use Anton.');
  // One weight covering 100-900 so the browser doesn't smear on a fake bold.
  return `{ const f = new FontFace('Impact', 'url(${dataUrl})', { weight: '100 900' }); document.fonts.add(f); f.load(); }`;
}

// ---------- photographing the real UI ----------
// The demo page with its dev toolbar hidden, so it reads as a plain webmail page.
const DEMO_CSS = `
  .bar { display: none !important; }
  body { background: #1f1f1f !important; }
  .nH { max-width: none !important; margin: 14px 14px 0 !important; padding: 0 !important; }
  .inbox { max-height: none !important; }
`;
const ONLY_EMAIL = '.nH:has(#list) { display: none !important; }';
const ONLY_INBOX = '#view { display: none !important; }';
const NO_BADGE = '#phishguard-root { display: none !important; }';

function shooter(browser, base, font) {
  // Opens dev/demo.html at `scale` device pixels per CSS pixel, so photos are sharp at their final size.
  return async function demo({ scale, width, height, sample, css }) {
    const ctx = await browser.newContext({ viewport: { width, height }, deviceScaleFactor: scale, colorScheme: 'dark' });
    if (font) await ctx.addInitScript(font);
    const page = await ctx.newPage();
    await page.goto(base + '/dev/demo.html');
    await page.selectOption('#sample', sample); // before the toolbar that holds it is hidden
    await page.addStyleTag({ content: DEMO_CSS + (css || '') });
    await page.waitForTimeout(1500); // scan + highlights + inbox tags
    return { page, scale, close: () => ctx.close() };
  };
}

// Top-left corner of an element, in photo pixels, nudged into the element by (dx, dy) CSS pixels.
async function spot(shot, locator, dx, dy) {
  const b = await locator.boundingBox();
  return { x: Math.round((b.x + dx) * shot.scale), y: Math.round((b.y + dy) * shot.scale) };
}

async function takePhotos(browser, base, font) {
  const demo = shooter(browser, base, font);
  const caps = {}, marks = {};
  const png = buf => 'data:image/png;base64,' + buf.toString('base64');
  let s;

  // 1. The open email with its highlights, and the verdict panel.
  s = await demo({ scale: 1.25, width: 568, height: 300, sample: 'Phishing: paypalLookalike', css: ONLY_EMAIL + NO_BADGE });
  caps['mail-hero'] = png(await s.page.screenshot());
  await s.close();
  for (const [name, scale] of [['panel', 1.15], ['panel-2x', 2]]) {
    s = await demo({ scale, width: 1000, height: 1000, sample: 'Phishing: paypalLookalike', css: ONLY_EMAIL });
    await s.page.locator('#phishguard-root .badge').click();
    await s.page.waitForTimeout(300);
    caps[name] = png(await s.page.locator('#phishguard-root .panel').screenshot());
    await s.close();
  }
  s = await demo({ scale: 2, width: 470, height: 300, sample: 'Phishing: paypalLookalike', css: ONLY_EMAIL + NO_BADGE });
  caps['mail-2x'] = png(await s.page.screenshot());
  await s.close();

  // 2. Hovering a link: the email, and the link check card.
  s = await demo({ scale: 1.25, width: 568, height: 300, sample: 'Phishing: microsoftLinks', css: ONLY_EMAIL + NO_BADGE });
  caps['mail-links'] = png(await s.page.screenshot());
  marks['mail-links.link'] = await spot(s, s.page.locator('.a3s a').first(), 96, 9);
  await s.close();
  s = await demo({ scale: 1.3, width: 1000, height: 1000, sample: 'Phishing: microsoftLinks', css: ONLY_EMAIL });
  await s.page.locator('.a3s a').first().hover();
  await s.page.waitForTimeout(900);
  caps.linkcard = png(await s.page.locator('#phishguard-linkcard .card').screenshot());
  await s.close();

  // 3. The inbox list with its tags, and the card that explains a tag.
  s = await demo({ scale: 1.3, width: 896, height: 300, sample: 'Phishing: paypalLookalike', css: ONLY_INBOX + NO_BADGE });
  caps.inbox = png(await s.page.screenshot());
  marks['inbox.tag'] = await spot(s, s.page.locator('.phishguard-row-tag').first(), 66, 11);
  await s.close();
  s = await demo({ scale: 1.25, width: 1000, height: 1000, sample: 'Phishing: paypalLookalike', css: ONLY_INBOX });
  await s.page.locator('.phishguard-row-tag').first().hover();
  await s.page.waitForTimeout(900);
  caps.rowcard = png(await s.page.locator('#phishguard-linkcard .card').screenshot());
  await s.close();

  // 4. An email whose QR code hides a fake sign-in page.
  s = await demo({ scale: 1.1, width: 420, height: 600, sample: 'Phishing: qrOnly', css: ONLY_EMAIL + NO_BADGE });
  await s.page.waitForTimeout(800); // the QR picture is decoded after the scan
  caps.qr = png(await s.page.locator('#view .card').screenshot());
  await s.close();

  return { caps, marks };
}

// A small PDF that does what phishing PDFs do: runs a script when opened and exists only to
// send the reader to a look-alike sign-in page. Same recipe as test/file-cases.js.
function lurePdf() {
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Annots [5 0 R] >>',
    { data: 'BT /F1 18 Tf (You have received a secure document.) Tj 0 -30 Td [(Click here) -250 (to view the document)] TJ ET' },
    '<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://micros0ft-online.docs-share.top/view?id=42) >> >>',
    '<< /S /JavaScript /JS (app.alert\\(1\\)) >>'
  ];
  let out = '%PDF-1.7\n%\xe2\xe3\xcf\xd3\n';
  objects.forEach((o, i) => {
    out += typeof o === 'string' ? `${i + 1} 0 obj\n${o}\nendobj\n` : `${i + 1} 0 obj\n<< /Length ${o.data.length} >>\nstream\n${o.data}\nendstream\nendobj\n`;
  });
  return Buffer.from(out + 'trailer\n<< /Root 1 0 R >>\n%%EOF\n', 'latin1');
}

// Scrolls an element to the top of the window (leaving the page's own margin above it) and
// photographs what the window then shows.
async function atTop(page, selector) {
  await page.locator(selector).first().evaluate(el => window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - 9, behavior: 'instant' }));
  await page.waitForTimeout(400);
  return page.screenshot();
}

// The file checker and the settings page, from the extension itself (loaded unpacked).
async function takeExtensionPhotos(font) {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'off-the-hook-store-'));
  const ctx = await chromium.launchPersistentContext(profile, {
    channel: 'chromium', headless: true, colorScheme: 'dark', deviceScaleFactor: 1.25, viewport: { width: 570, height: 430 },
    args: [`--disable-extensions-except=${ROOT}`, `--load-extension=${ROOT}`]
  });
  try {
    if (font) await ctx.addInitScript(font);
    const worker = ctx.serviceWorkers()[0] || await ctx.waitForEvent('serviceworker', { timeout: 20000 });
    const home = 'chrome-extension://' + worker.url().split('/')[2];
    const caps = {};
    const png = buf => 'data:image/png;base64,' + buf.toString('base64');
    const page = await ctx.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));

    await page.goto(home + '/scan/scan.html');
    await page.setInputFiles('#file', [{ name: 'Invoice_INV-20391.pdf', mimeType: 'application/pdf', buffer: lurePdf() }]);
    await page.locator('#results > *').first().waitFor({ timeout: 10000 });
    caps.scan = png(await atTop(page, '#results > *'));

    await page.setViewportSize({ width: 620, height: 430 });
    await page.goto(home + '/options/options.html');
    await page.waitForTimeout(600);
    caps.privacy = png(await atTop(page, '#privacy'));

    if (errors.length) throw new Error('Extension page errors: ' + errors.join(' | '));
    return caps;
  } finally {
    await ctx.close();
    fs.rmSync(profile, { recursive: true, force: true });
  }
}

// ---------- PNG checks: exact size, and no alpha channel (the store rejects transparency) ----------
function pngInfo(buf) {
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20), depth: buf[24], colorType: buf[25] };
}
const CRC = (() => { const t = []; for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function crc32(buf) { let c = 0xffffffff; for (const b of buf) c = CRC[(c ^ b) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}
// Rewrites an 8-bit RGBA PNG as 24-bit RGB. Every pixel is opaque already, so nothing is lost.
function dropAlpha(buf) {
  const { width, height, depth, colorType } = pngInfo(buf);
  if (colorType === 2) return buf;
  if (colorType !== 6 || depth !== 8) throw new Error('Unexpected PNG format: color type ' + colorType + ', depth ' + depth);
  const idat = [];
  for (let at = 8; at < buf.length;) {
    const len = buf.readUInt32BE(at), type = buf.toString('latin1', at + 4, at + 8);
    if (type === 'IDAT') idat.push(buf.subarray(at + 8, at + 8 + len));
    at += 12 + len;
  }
  const raw = zlib.inflateSync(Buffer.concat(idat));
  const stride = width * 4, rgb = Buffer.alloc(height * (1 + width * 3));
  let prev = Buffer.alloc(stride);
  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)], line = Buffer.from(raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1)));
    for (let x = 0; x < stride; x++) {
      const a = x >= 4 ? line[x - 4] : 0, b = prev[x], c = x >= 4 ? prev[x - 4] : 0;
      let add = 0;
      if (filter === 1) add = a;
      else if (filter === 2) add = b;
      else if (filter === 3) add = (a + b) >> 1;
      else if (filter === 4) { const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c); add = pa <= pb && pa <= pc ? a : pb <= pc ? b : c; }
      line[x] = (line[x] + add) & 255;
    }
    const row = y * (1 + width * 3);
    for (let x = 0; x < width; x++) {
      if (line[x * 4 + 3] !== 255) throw new Error('Image has transparent pixels');
      line.copy(rgb, row + 1 + x * 3, x * 4, x * 4 + 3);
    }
    prev = line;
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0); ihdr.writeUInt32BE(height, 4); ihdr[8] = 8; ihdr[9] = 2;
  return Buffer.concat([buf.subarray(0, 8), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(rgb, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

// ---------- lay each piece out in dev/store.html and save it ----------
async function build() {
  const server = await serve();
  const base = 'http://127.0.0.1:' + server.address().port;
  const browser = await chromium.launch();
  try {
    const font = await impactScript(browser);
    const { caps, marks } = await takePhotos(browser, base, font);
    Object.assign(caps, await takeExtensionPhotos(font));

    fs.mkdirSync(OUT, { recursive: true });
    for (const art of ART) {
      const ctx = await browser.newContext({ viewport: { width: art.w, height: art.h }, deviceScaleFactor: 1, colorScheme: 'dark' });
      if (font) await ctx.addInitScript(font);
      const page = await ctx.newPage();
      await page.goto(base + '/dev/store.html?only=' + art.id);
      await page.evaluate(([c, m]) => window.fillArt(c, m), [caps, marks]);
      await page.waitForTimeout(200);
      const shot = dropAlpha(await page.screenshot({ type: 'png', clip: { x: 0, y: 0, width: art.w, height: art.h } }));
      await ctx.close();
      const info = pngInfo(shot);
      if (info.width !== art.w || info.height !== art.h || info.colorType !== 2) throw new Error(art.file + ' came out wrong: ' + JSON.stringify(info));
      fs.writeFileSync(path.join(OUT, art.file), shot);
      console.log(`${art.file}  ${info.width}x${info.height}  24-bit RGB  ${(shot.length / 1024).toFixed(0)} KB`);
    }
  } finally {
    await browser.close();
    server.close();
  }
}

build().catch(err => { console.error(err); process.exit(1); });
