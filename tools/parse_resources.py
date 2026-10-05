#!/usr/bin/env python3
"""Parse the Control Validation Compass technique pages into structured JSON.

Source: a checkout of https://github.com/ControlCompass/ControlCompass.github.io
  <upstream>/resources/*.md      one markdown page per technique
  <upstream>/cvc.json            technique x provider coverage matrix

Outputs (into this repo's data/):
  technique_pages.json  full detail: descriptions + every mapped resource URL
  technique_index.json  light index for the boot payload
  controls.json         the provider matrix

Usage:  python3 tools/parse_resources.py [/path/to/ControlCompass.github.io]
"""
import json, os, re, glob, html, sys

UPSTREAM = sys.argv[1] if len(sys.argv) > 1 else '../ControlCompass.github.io'
SRC = os.path.join(UPSTREAM, 'resources')
OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
TECH_OUT = os.path.join(OUT_DIR, 'technique_pages.json')
CTRL_OUT = os.path.join(OUT_DIR, 'controls.json')

H2_SECTION = re.compile(r'^##\s+(.+?)\s*$', re.M)
H3_PROVIDER = re.compile(r'^###\s+\[([^\]]+)\]\(([^)]+)\)\s*$')
LAST_ACCESSED = re.compile(r'^\*\*Last accessed:\*\*\s*(.+?)\s*$')
TOTAL_MAPPED = re.compile(r'^\*\*Total ATT&CK-mapped (resources|rules|tests):\*\*\s*([\d,]+)')
FOR_THIS = re.compile(r'^\*\*ATT&CK-mapped resources for this \(sub\)technique:\*\*\s*([\d,]+)')
HEADER = re.compile(r'^#\s+(T[\d.]+):\s*(.+?)\s*$')
TACTICS = re.compile(r'^\*\*MITRE ATT&CK Tactic\(s\):\*\*\s*(.+?)\s*$')
DESC_LINK = re.compile(r'^\*\*\[MITRE ATT&CK Description\]\(([^)]+)\)\*\*\s*$')
BULLET = re.compile(r'^\*\s+(.*)$')
MD_LINK = re.compile(r'\[([^\]]*)\]\(([^)]+)\)')
BOLD_LINK = re.compile(r'\*\*\[([^\]]+)\]\(([^)]+)\)\*\*')
# "can be located in [the file here](url)" / "[this page](url)" style pointers
FILE_REF = re.compile(r'\[(?:the file here|this page|this repository|'
                      r'the following file|the file)\]\(([^)]+)\)')

# ---- ATT&CK-internal link -> technique id -----------------------------
TECH_IN_LINK = re.compile(
    r'attack\.mitre\.org/techniques/(T\d{4})(?:/(\d{3}))?')
SOFT_IN_LINK = re.compile(
    r'attack\.mitre\.org/software/(S\d{4})')


def strip_md(text):
    """Turn a markdown fragment into plain text, keeping link labels readable."""
    text = BOLD_LINK.sub(r'\1', text)
    text = MD_LINK.sub(r'\1', text)
    text = re.sub(r'<[^>]+>', '', text)
    text = html.unescape(text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def ids_in(text):
    """ATT&CK technique / software ids referenced inside a markdown fragment."""
    techniques = set()
    for parent, sub in TECH_IN_LINK.findall(text):
        techniques.add(f'{parent}.{sub}' if sub else parent)
    return techniques, set(SOFT_IN_LINK.findall(text))


def parse_file(path):
    raw = open(path, encoding='utf-8', errors='replace').read()
    lines = raw.split('\n')

    m = HEADER.match(lines[0]) if lines else None
    tid = m.group(1) if m else os.path.basename(path)[:-3]
    tname = m.group(2) if m else tid

    tactics = []
    desc = None
    desc_raw = None
    desc_url = None
    sections = {}          # section title -> [provider blocks]
    provider = None
    section = None
    in_desc = False
    desc_buf = []

    def flush():
        nonlocal provider
        if section and provider:
            sections.setdefault(section, []).append(provider)
        provider = None

    for line in lines[1:]:
        m3 = H3_PROVIDER.match(line)
        if m3:
            flush()
            provider = {
                'name': m3.group(1),
                'url': m3.group(2),
                'lastAccessed': None,
                'totalMapped': None,
                'kind': None,
                'forThis': None,
                'fileUrl': None,
                'note': None,
                'items': [],
            }
            continue

        if provider is not None:
            if LAST_ACCESSED.match(line):
                provider['lastAccessed'] = LAST_ACCESSED.match(line).group(1)
                continue
            m = TOTAL_MAPPED.match(line)
            if m:
                provider['kind'] = m.group(1)
                provider['totalMapped'] = int(m.group(2).replace(',', ''))
                continue
            m = FOR_THIS.match(line)
            if m:
                provider['forThis'] = int(m.group(1).replace(',', ''))
                continue
            m = DESC_LINK.match(line)
            if m:
                provider['fileUrl'] = m.group(1)
                continue
            mf = FILE_REF.search(line)
            if mf and not provider['fileUrl']:
                provider['fileUrl'] = mf.group(1)
                continue
            mb = BULLET.match(line)
            if mb:
                add_bullet(provider, mb.group(1))
                continue
            if not line.strip():
                continue

        h2 = H2_SECTION.match(line)
        if h2:
            flush()
            section = h2.group(1)
            continue

        m = TACTICS.match(line)
        if m:
            tactics = [t.strip() for t in m.group(1).split(',') if t.strip()]
            continue

        m = DESC_LINK.match(line)
        if m:
            desc_url = m.group(1)
            in_desc = True
            desc_buf = []
            continue

        if in_desc:
            if '</blockquote>' in line:
                in_desc = False
                body = line.split('</blockquote>')[0]
                desc_buf.append(body)
                desc_raw = '\n'.join(desc_buf)
                desc = html.unescape(strip_md(desc_raw)).strip()
                continue
            desc_buf.append(line)

    flush()

    refs = sorted({f'{a}.{b}' if b else a
                   for a, b in TECH_IN_LINK.findall(desc_raw or '')}
                  - {tid})
    return {
        'id': tid,
        'name': tname,
        'tactics': tactics,
        'refs': refs,
        'url': desc_url or f'https://attack.mitre.org/techniques/{tid.replace(".", "/")}',
        'description': desc,
        'sections': sections,
    }


def add_bullet(p, raw):
    """Record one bullet. Three shapes exist in the corpus."""
    body = raw.strip()
    suffix = None
    ms = re.search(r':\s*([\d,]+)\s+unit tests?\s*$', body)
    if ms:
        suffix = int(ms.group(1).replace(',', ''))
        body = body[:ms.start()].strip()

    # shape 1: breadcrumb path ending in a bolded link -> that link is the item
    mb = BOLD_LINK.findall(body)
    if mb:
        name, url = mb[-1]
    else:
        links = MD_LINK.findall(body)
        if links:
            name, url = links[-1]
        else:
            name, url = strip_md(body), None   # plain-text test name

    if not name and not url:
        return
    techniques, software = ids_in(body)
    p['items'].append({
        'name': strip_md(name),
        'url': url,
        'tests': suffix,
        'techniques': sorted(techniques),
        'software': sorted(software),
    })


def main():
    files = sorted(glob.glob(os.path.join(SRC, 'T*.md')))
    pages = []
    for p in files:
        try:
            pages.append(parse_file(p))
        except Exception as e:
            print(f'  WARN {os.path.basename(p)}: {e}', file=sys.stderr)

    pages.sort(key=lambda d: (d['id'].split('.')[0], d['id']))
    json.dump(pages, open(TECH_OUT, 'w'), separators=(',', ':'))

    # ---- provider coverage matrix (from the repo's own cvc.json) --------
    src = json.load(open(os.path.join(UPSTREAM, 'cvc.json')))
    META = ('techID', 'techName', 'technique', 'tactics', 'url', 'lowestLevel',
            'policy_process_volume', 'detect_volume', 'test_volume', 'validate_potential')
    providers = [k for k in src[0] if k not in META]
    matrix = [{
        'id': x['techID'],
        'name': x['techName'],
        'tactics': x['tactics'],
        'level': x['lowestLevel'],
        'url': x['url'],
        'v': [x[p] or 0 for p in providers],
        'scores': [x['policy_process_volume'], x['detect_volume'],
                   x['test_volume'], x['validate_potential']],
    } for x in src]
    json.dump({'providers': providers, 'techniques': matrix}, open(CTRL_OUT, 'w'),
              separators=(',', ':'))

    print(f'technique_pages.json : {len(pages)} techniques, '
          f'{os.path.getsize(TECH_OUT)/1024:.0f} KB')
    print(f'controls.json        : {len(matrix)} x {len(providers)} matrix, '
          f'{os.path.getsize(CTRL_OUT)/1024:.0f} KB')

    withdesc = sum(1 for p in pages if p['description'])
    prov_blocks = sum(len(v) for p in pages for v in p['sections'].values())
    items = sum(len(b['items']) for p in pages for v in p['sections'].values() for b in v)
    print(f'  with description : {withdesc}/{len(pages)}')
    print(f'  provider blocks  : {prov_blocks}')
    print(f'  linked items     : {items}')


if __name__ == '__main__':
    if not os.path.isdir(SRC):
        sys.exit(f'resource directory not found: {SRC}\n'
                 'clone https://github.com/ControlCompass/ControlCompass.github.io first')
    main()