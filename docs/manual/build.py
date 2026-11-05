#!/usr/bin/env python3
"""Build docs/manual/index.html from shell.html and one fragment per chapter.

Chapters are HTML fragments in chapters/<key>.html, each one <section id="<key>"
data-title="..."> with one <h2> and <h3 id="..."> sections, in the vocabulary
shell.html styles (no <script>, <style> or style= attributes). The build refuses a
fragment that breaks those rules, a duplicate id, or an internal link to an id
that does not exist, so the published page never has a dead cross-reference.

    python3 docs/manual/build.py            # writes docs/manual/index.html
    python3 docs/manual/build.py --check    # validates only
    python3 docs/manual/build.py --out PATH # writes the page to PATH instead (index.html untouched)
    python3 docs/manual/build.py --out PATH --standalone
                                            # the same page as a complete document for a
                                            # plain web server: doctype, html, charset, viewport

--out is how the portal gets its copy (infra/lib-manual.sh): built from the chapters at
deploy time into a temporary file, never the committed index.html, which may be stale.
shell.html has no doctype or <html> because the artifact host wraps it; served as it is
by the portal's nginx it would render in quirks mode, hence --standalone.

Edition details live in EDITION below: bump them when a phase updates the manual,
and add a row to chapters/revisions.html.
"""
import html
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CHAPTERS = ['overview', 'access', 'apps', 'devices', 'compliance', 'admin', 'training', 'reference', 'revisions']
EDITION = {
    'EDITION': '5',
    'COVERS': 'IAM phases 0 to 4: access policy versions, approved and applied on the host',
    'DATE': '5 Nov 2026',
    'COMMIT': '6520ceb (branch iam/phase-4.5)',
}

# What --standalone puts before shell.html's own <title>, <link> and <style> (which the
# HTML parser then places in the head, as it does inside the artifact host's skeleton).
STANDALONE_HEAD = ('<!DOCTYPE html>\n<html lang="en">\n<meta charset="utf-8">\n'
                   '<meta name="viewport" content="width=device-width, initial-scale=1">\n')

SECTION = re.compile(r'<section\s+id="([a-z0-9-]+)"\s+data-title="([^"]+)"\s*>')
H3 = re.compile(r'<h3\s+id="([a-z0-9-]+)"\s*>(.*?)</h3>', re.S)
IDS = re.compile(r'\sid="([^"]+)"')
HREFS = re.compile(r'href="#([^"]+)"')
FORBIDDEN = re.compile(r'<script|<style|\sstyle="|<html|<head|<body', re.I)
TAGS = re.compile(r'<[^>]+>')


def text(fragment):
    return html.unescape(TAGS.sub('', fragment)).strip()


def load():
    out, errors = [], []
    for key in CHAPTERS:
        path = os.path.join(HERE, 'chapters', key + '.html')
        if not os.path.exists(path):
            errors.append(f'{key}: chapters/{key}.html is missing')
            continue
        src = open(path, encoding='utf-8').read()
        m = SECTION.search(src)
        if not m or m.group(1) != key:
            errors.append(f'{key}: needs <section id="{key}" data-title="...">')
            continue
        if FORBIDDEN.search(src):
            errors.append(f'{key}: contains a script, style or page tag')
        if src.count('<h2') != 1:
            errors.append(f'{key}: needs exactly one <h2>')
        out.append({'key': key, 'title': html.unescape(m.group(2)), 'src': src.strip(),
                    'sections': [(i, text(t)) for i, t in H3.findall(src)]})
    every = [i for c in out for i in IDS.findall(c['src'])]
    dupes = sorted({i for i in every if every.count(i) > 1})
    if dupes:
        errors.append('duplicate ids: ' + ', '.join(dupes))
    known = set(every)
    for c in out:
        for ref in HREFS.findall(c['src']):
            if ref not in known:
                errors.append(f'{c["key"]}: link to #{ref}, which no chapter defines')
    return out, errors


def toc(chapters):
    items = []
    for n, c in enumerate(chapters, 1):
        subs = ''.join(f'<li><a href="#{i}">{html.escape(t)}</a></li>' for i, t in c['sections'])
        items.append(f'<li><a href="#{c["key"]}"><span class="n">{n}</span>{html.escape(c["title"])}</a>'
                     + (f'<ol>{subs}</ol>' if subs else '') + '</li>')
    return '<nav class="toc" aria-label="Contents"><p>Contents</p><ol>' + ''.join(items) + '</ol></nav>'


def out_path(argv):
    """The --out PATH (or --out=PATH) argument, else docs/manual/index.html; None if malformed."""
    for i, a in enumerate(argv):
        if a.startswith('--out='):
            return a[len('--out='):] or None
        if a == '--out':
            nxt = argv[i + 1] if i + 1 < len(argv) else ''
            return nxt if nxt and not nxt.startswith('--') else None
    return os.path.join(HERE, 'index.html')


def main():
    out = out_path(sys.argv[1:])
    if out is None:
        print('build: --out needs a file path', file=sys.stderr)
        return 2
    chapters, errors = load()
    if errors:
        print('\n'.join('build: ' + e for e in errors), file=sys.stderr)
        return 1
    if '--check' in sys.argv:
        print(f'build: {len(chapters)} chapters OK')
        return 0
    page = open(os.path.join(HERE, 'shell.html'), encoding='utf-8').read()
    nav = toc(chapters)
    page = page.replace('{{TOC_SIDE}}', nav).replace('{{TOC}}', nav.replace('class="toc"', 'class="toc" aria-label="Contents (menu)"', 1))
    page = page.replace('{{CHAPTERS}}', '\n'.join(c['src'] for c in chapters))
    for k, v in EDITION.items():
        page = page.replace('{{' + k + '}}', html.escape(v))
    if '--standalone' in sys.argv:
        page = STANDALONE_HEAD + page.rstrip('\n') + '\n</html>\n'
    left = re.findall(r'\{\{[A-Z_]+\}\}', page)
    if left:
        print('build: unfilled placeholders ' + ', '.join(left), file=sys.stderr)
        return 1
    with open(out, 'w', encoding='utf-8') as f:
        f.write(page)
    shown = 'docs/manual/index.html' if os.path.abspath(out) == os.path.join(HERE, 'index.html') else out
    print(f'build: wrote {shown} ({len(chapters)} chapters, {len(page) // 1024} KiB)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
