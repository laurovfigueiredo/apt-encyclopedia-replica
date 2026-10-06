#!/usr/bin/env python3
import html
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

FIELDS = [
    ("url", ["URL:"]),
    ("repoUpdated", ["Repository last updated:"]),
    ("accessed", ["Last accessed by CVC:"]),
    ("overview", ["Overview:", "Description:"]),
    ("navigate", ["How to navigate:", "Navigation:"]),
]
LABEL = {lab: field for field, labs in FIELDS for lab in labs}
MARKER = re.compile(r"^\[\[([^|\]]*)\|([^|\]]*)\]\]$")

BLOCK = re.compile(
    r"<h3[^>]*>(?P<h3>.*?)</h3>|<h4[^>]*>(?P<h4>.*?)</h4>|<h5[^>]*>(?P<h5>.*?)</h5>|<p[^>]*>(?P<p>.*?)</p>",
    re.S,
)
IFRAME = re.compile(r'src="https://www\.youtube-nocookie\.com/embed/([^"]+)"')
LINK = re.compile(r'<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S)
TAGS = re.compile(r"<[^>]+>")

def flatten(fragment):
    def sub(m):
        href, label = m.group(1).strip(), TAGS.sub("", m.group(2))
        label = html.unescape(re.sub(r"\s+", " ", label)).strip()
        return "[[%s|%s]]" % (label or href, href)
    out = LINK.sub(sub, fragment)
    out = TAGS.sub("", out)
    return html.unescape(re.sub(r"\s+", " ", out)).strip()

def h4_id(inner):
    m = re.search(r'id="([^"]+)"', inner)
    return m.group(1) if m else None

def walk(markup):
    for m in BLOCK.finditer(markup):
        tag = m.lastgroup
        if tag == "h3":
            yield "h3", flatten(m.group("h3"))
        elif tag == "h4":
            yield "h4", (h4_id(m.group("h4")), flatten(m.group("h4")))
        elif tag == "h5":
            href = LINK.search(m.group("h5"))
            if href:
                yield "link", (flatten(href.group(2)), href.group(1).strip())
        elif tag == "p":
            vid = IFRAME.search(m.group("p"))
            if vid:
                yield "video", vid.group(1)
            else:
                txt = flatten(m.group("p"))
                if txt:
                    yield "p", txt

def bare(text):
    m = MARKER.match(text.strip())
    return m.group(2) if m and m.group(1) == m.group(2) else text

GROUPS = {
    "Policy & Process Control Resources",
    "Technical Control / Detection Resources",
    "Offensive Security / Red Team Testing Resources",
}
FAQ = "Frequently Asked Questions (FAQ)"

def parse_page(markup):
    tutorials, general, faq, groups = [], [], [], []
    sec, item, group, prov = None, None, None, None
    for tag, val in walk(markup):
        if tag == "h3":
            sec = val
            item, group, prov = None, None, None
            if sec in GROUPS:
                group = {"title": sec, "updated": None, "providers": []}
                groups.append(group)
            continue
        if sec == "Tutorials":
            if tag == "video":
                tutorials.append({"label": "Video", "url": "https://www.youtube-nocookie.com/embed/" + val})
            elif tag == "link":
                tutorials.append({"label": val[0], "url": val[1]})
            continue
        if sec == "General Knowledge":
            if tag == "link":
                general.append({"label": val[0], "url": val[1]})
            continue
        if sec == FAQ:
            if tag == "h4":
                item = {"q": val[1], "a": []}
                faq.append(item)
            elif tag == "p" and item is not None:
                item["a"].append(val)
            continue
        if group is None:
            continue
        if tag == "h4":
            prov = {"id": val[0], "name": val[1]}
            for f, _ in FIELDS:
                prov[f] = ""
            group["providers"].append(prov)
        elif tag == "p":
            if prov is None:
                if val.startswith("This section"):
                    group["updated"] = val.rstrip(".").split("updated in")[-1].strip()
                continue
            for lab, field in LABEL.items():
                if val.startswith(lab):
                    body = bare(val[len(lab):].strip())
                    if not prov[field] or lab in ("Overview:", "Description:"):
                        prov[field] = body
                    break
    return tutorials, general, faq, [g for g in groups if g["providers"]]

def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    src = os.path.join(os.path.abspath(sys.argv[1]), "resources.html")
    markup = re.sub(r"<script[\s\S]*?</script>", "", open(src, encoding="utf-8").read())
    intro = ""
    m = re.search(r'id="main"[\s\S]{0,400}?<p[^>]*>([\s\S]*?)</p>', markup)
    if m:
        intro = flatten(m.group(1))
    tutorials, general, faq, groups = parse_page(markup)
    out = {
        "intro": intro,
        "tutorials": {"kind": "tutorials", "items": tutorials},
        "general": {"kind": "general", "items": general},
        "faq": faq,
        "groups": groups,
    }
    p = os.path.join(ROOT, "data", "resources_guide.json")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print("resources_guide.json  %6.1f KB" % (os.path.getsize(p) / 1024))

if __name__ == "__main__":
    main()
