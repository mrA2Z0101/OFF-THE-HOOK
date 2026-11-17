"""Build a Firefox copy of PhishGuard in dist/firefox.

Chrome and Edge load the PhishGuard folder directly. Firefox (MV3) does not support a
background service worker, so this script copies the extension and rewrites the
manifest to use an event page that loads the shared scripts first.

Run from the PhishGuard folder:  python scripts/build_firefox.py
Then in Firefox: about:debugging > This Firefox > Load Temporary Add-on > dist/firefox/manifest.json
"""
import json
import os
import shutil

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
DEST = os.path.join(ROOT, 'dist', 'firefox')
INCLUDE = ['background', 'content', 'data', 'icons', 'learn', 'options', 'popup', 'scan', 'score', 'shared']

with open(os.path.join(ROOT, 'manifest.json'), encoding='utf-8') as f:
    manifest = json.load(f)

manifest.pop('minimum_chrome_version', None)
manifest['background'] = {
    'scripts': [
        'shared/config.js',
        'shared/domain-utils.js',
        'shared/analyzer.js',
        'shared/ai-utils.js',
        'shared/feedback.js',
        'shared/qr.js',
        'shared/blocklist.js',
        'background/providers.js',
        'background/background.js',
    ]
}
origins = manifest.get('optional_host_permissions', [])
manifest['optional_permissions'] = sorted(set(manifest.get('optional_permissions', []) + origins))
manifest['browser_specific_settings'] = {
    'gecko': {'id': 'phishguard@local.extension', 'strict_min_version': '115.0'}
}

if os.path.isdir(DEST):
    shutil.rmtree(DEST)
os.makedirs(DEST)
for name in INCLUDE:
    shutil.copytree(os.path.join(ROOT, name), os.path.join(DEST, name))
with open(os.path.join(DEST, 'manifest.json'), 'w', encoding='utf-8') as f:
    json.dump(manifest, f, indent=2)

print('Firefox build written to', DEST)
