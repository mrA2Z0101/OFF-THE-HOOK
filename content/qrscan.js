/*
 * Reads QR codes in the open email's pictures so the link inside gets the normal link checks.
 *
 * Each picture is read once (cached by its address). Pictures the page can hand over directly
 * are decoded right here. Gmail and Outlook serve most email pictures from their own image
 * servers, which a web page isn't allowed to read pixel by pixel, so for those hosts only the
 * background worker fetches the picture again and decodes it. The sender's own servers are
 * never contacted.
 */
(function () {
  'use strict';

  const MAX_IMAGES = 15;
  const MIN_SIDE = 40;      // smaller pictures are icons, spacers or tracking pixels
  const MAX_DRAW = 1600;    // larger pictures are shrunk before decoding

  function create(opts) {
    const { send, onFound } = opts;
    const cache = new Map(); // image address -> { state: 'pending'|'done', link }
    const QR = globalThis.PhishGuard.qr;
    const decodeQR = img => QR.decode(img);
    const toLink = QR.toLink;

    function candidates(bodyEl) {
      if (!bodyEl) return [];
      const out = [];
      for (const img of bodyEl.querySelectorAll('img')) {
        const src = img.currentSrc || img.src;
        if (!src || /^data:image\/svg/i.test(src)) continue;
        const w = img.naturalWidth || img.width, h = img.naturalHeight || img.height;
        if (img.complete && (w < MIN_SIDE || h < MIN_SIDE)) continue;
        out.push({ img, src });
        if (out.length >= MAX_IMAGES) break;
      }
      return out;
    }

    // Pixels straight from the page (fails with a SecurityError for other sites' pictures).
    function localPixels(img) {
      const w = img.naturalWidth, h = img.naturalHeight;
      if (!w || !h) return null;
      const k = Math.min(1, MAX_DRAW / Math.max(w, h));
      const canvas = document.createElement('canvas');
      canvas.width = Math.max(1, Math.round(w * k));
      canvas.height = Math.max(1, Math.round(h * k));
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      return ctx.getImageData(0, 0, canvas.width, canvas.height);
    }

    async function read(img, src) {
      let text = null;
      try {
        const px = localPixels(img);
        const r = px && decodeQR(px);
        text = r ? r.text : null;
      } catch (e) {
        if (/^https:/i.test(src)) {
          try {
            const resp = await send({ type: 'qrFromUrl', url: src });
            text = resp && resp.ok ? resp.text : null;
          } catch (err) { text = null; }
        }
      }
      const link = toLink(text);
      cache.set(src, { state: 'done', link });
      if (link) onFound();
    }

    return {
      /** Start reading any new pictures in the email (results arrive later through onFound). */
      scan(bodyEl) {
        for (const { img, src } of candidates(bodyEl)) {
          if (cache.has(src)) continue;
          cache.set(src, { state: 'pending', link: null });
          const go = () => setTimeout(() => read(img, src), 0);
          if (img.complete && img.naturalWidth) go();
          else img.addEventListener('load', go, { once: true });
        }
      },
      /** QR links already read for this email's pictures: [{ img, href }] in page order. */
      linksFor(bodyEl) {
        const out = [];
        for (const { img, src } of candidates(bodyEl)) {
          const c = cache.get(src);
          if (c && c.link) out.push({ img, href: c.link });
        }
        return out;
      }
    };
  }

  globalThis.PhishGuardQrScan = { create };
})();
