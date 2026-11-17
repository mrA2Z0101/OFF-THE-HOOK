"""Build the Chrome Web Store upload in dist/off-the-hook-<version>.zip.

The zip holds only what the extension runs: manifest.json plus the folders below. The dev
tools, tests, README art and store images stay out of it.

Run from the extension folder:  python scripts/build_zip.py
Then upload the zip at https://chrome.google.com/webstore/devconsole (see store/LISTING.md).

Before zipping, it checks what the store checks first: the manifest's limits, and that every
file the manifest points at is there.
"""
import json
import os
import struct
import sys
import zipfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
DIST = os.path.join(ROOT, 'dist')
# Same folders as scripts/build_firefox.py.
INCLUDE = ['background', 'content', 'data', 'icons', 'learn', 'options', 'popup', 'scan', 'score', 'shared']
SKIP_FILES = {'HOW-TO-WRITE.md', 'Thumbs.db', '.DS_Store'}  # notes for people editing the repo, OS clutter


def png_size(path):
    with open(path, 'rb') as f:
        head = f.read(24)
    if head[:8] != b'\x89PNG\r\n\x1a\n':
        return None
    return struct.unpack('>II', head[16:24])


def check(manifest):
    """Returns a list of problems that would get the upload rejected."""
    problems = []
    if manifest.get('manifest_version') != 3:
        problems.append('manifest_version must be 3')
    name, desc, version = manifest.get('name', ''), manifest.get('description', ''), manifest.get('version', '')
    if not 0 < len(name) <= 75:
        problems.append('name must be 1-75 characters (it is %d)' % len(name))
    if not 0 < len(desc) <= 132:
        problems.append('description must be 1-132 characters (it is %d)' % len(desc))
    parts = version.split('.')
    if not 1 <= len(parts) <= 4 or not all(p.isdigit() and int(p) <= 65535 and (p == '0' or not p.startswith('0')) for p in parts):
        problems.append('version must be 1-4 numbers (0-65535) separated by dots (it is "%s")' % version)

    icons = manifest.get('icons', {})
    if '128' not in icons:
        problems.append('icons must include a 128x128 PNG (the store shows it)')
    for size, rel in icons.items():
        path = os.path.join(ROOT, rel)
        if os.path.isfile(path) and png_size(path) != (int(size), int(size)):
            problems.append('%s should be a %sx%s PNG, but is %s' % (rel, size, size, png_size(path)))

    # Every file the manifest names must be in the zip.
    files = list(icons.values())
    action = manifest.get('action', {})
    files += list(action.get('default_icon', {}).values()) + [action.get('default_popup')]
    files += [manifest.get('options_ui', {}).get('page'), manifest.get('background', {}).get('service_worker')]
    for script in manifest.get('content_scripts', []):
        files += script.get('js', []) + script.get('css', [])
    for group in manifest.get('web_accessible_resources', []):
        files += group.get('resources', [])
    for rel in files:
        if not rel:
            continue
        if not os.path.isfile(os.path.join(ROOT, rel)):
            problems.append('missing file: ' + rel)
        elif rel.split('/')[0] not in INCLUDE:
            problems.append('%s is outside the folders that get zipped (%s)' % (rel, ', '.join(INCLUDE)))
    return problems


def main():
    with open(os.path.join(ROOT, 'manifest.json'), encoding='utf-8') as f:
        manifest = json.load(f)
    problems = check(manifest)
    if problems:
        print('Not ready for the Chrome Web Store:')
        for p in problems:
            print('  - ' + p)
        return 1

    os.makedirs(DIST, exist_ok=True)
    out = os.path.join(DIST, 'off-the-hook-%s.zip' % manifest['version'])
    count = 0
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.write(os.path.join(ROOT, 'manifest.json'), 'manifest.json')
        for folder in INCLUDE:
            for base, dirs, names in os.walk(os.path.join(ROOT, folder)):
                dirs.sort()
                for name in sorted(names):
                    if name in SKIP_FILES:
                        continue
                    path = os.path.join(base, name)
                    z.write(path, os.path.relpath(path, ROOT).replace(os.sep, '/'))
                    count += 1
    print('%s  (%d files, %.0f KB)' % (os.path.relpath(out, ROOT), count + 1, os.path.getsize(out) / 1024))
    print('Name: %s  |  Version: %s  |  Description: %d/132 characters' % (manifest['name'], manifest['version'], len(manifest['description'])))
    return 0


if __name__ == '__main__':
    sys.exit(main())
