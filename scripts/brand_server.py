"""Dev helper: serves the PhishGuard folder and lets dev/brand.html save the generated
icon and wordmark PNGs into icons/.

    python scripts/brand_server.py
    then open http://localhost:8770/dev/brand.html and click "Save PNGs to icons/".

Only accepts the fixed file names below and only listens on localhost.
"""
import base64
import http.server
import os
import re

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
ICONS = os.path.join(ROOT, 'icons')
DOCS = os.path.join(ROOT, 'docs')
ALLOWED = re.compile(r'^(icon(16|32|48|128)|logo512|wordmark|banner|social-preview)\.png$')
TO_DOCS = {'banner.png', 'social-preview.png'}  # README art lives in docs/, not icons/


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()

    def do_POST(self):
        name = self.path.rsplit('/', 1)[-1]
        if not self.path.startswith('/save/') or not ALLOWED.match(name):
            self.send_error(403)
            return
        length = int(self.headers.get('Content-Length', 0))
        if length > 15_000_000:
            self.send_error(413)
            return
        data = base64.b64decode(self.rfile.read(length))
        if not data.startswith(b'\x89PNG'):
            self.send_error(400)
            return
        folder = DOCS if name in TO_DOCS else ICONS
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, name), 'wb') as f:
            f.write(data)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')


if __name__ == '__main__':
    print('Serving on http://localhost:8770/dev/brand.html')
    http.server.ThreadingHTTPServer(('127.0.0.1', 8770), Handler).serve_forever()
