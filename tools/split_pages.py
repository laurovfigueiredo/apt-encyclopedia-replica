#!/usr/bin/env python3
"""Split the single-page index.html into one .html file per theme.

Each page keeps the same header/nav/footer/modal/scripts, with the nav
pointing at *.html files (URL per theme) and aria-current on the active
link. index.html becomes the Overview hub with cards linking to the rest.

Usage: python3 tools/split_pages.py   (run from the repo root)
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = os.path.join(ROOT, "index.html")

PAGES = [
    ("index.html", "overview", "Overview"),
    ("categorized.html", "categorized", "Categorized Threats"),
    ("heatmap.html", "navigator", "ATT&CK Heatmap"),
    ("intel.html", "intel", "Recent Intelligence"),
    ("research.html", "knowledge", "TTP Research & Search"),
    ("controls.html", "controls", "Lookup by Controls"),
    ("alignment.html", "risk", "Threat Alignment"),
    ("resources.html", "resources", "Knowledge Center"),
    ("groups.html", "groups", "APT Groups"),
    ("techniques.html", "techniques", "ATT&CK"),
    ("model.html", "model", "Threat Model"),
]

HUB_CARDS = [
    ("categorized.html", "Categorized Threats", "Filter 117 adversaries by motive, industry, base and victim location."),
    ("heatmap.html", "ATT&CK Heatmap", "Navigator layer generated from the selected threat scope."),
    ("intel.html", "Recent Intelligence", "11 pre-computed report layers from the Compass authors."),
    ("research.html", "TTP Research & Search", "578 techniques with mapped controls, detections and tests."),
    ("controls.html", "Lookup by Controls", "Align your 27-provider control stack against ATT&CK."),
    ("alignment.html", "Threat Alignment", "Threat model vs control stack: technique-level gaps."),
    ("resources.html", "Knowledge Center", "Upstream projects, guide, and the dataset updater."),
    ("groups.html", "APT Groups", "Searchable threat-actor profiles with Diamond Model."),
    ("techniques.html", "ATT&CK", "Searchable technique catalog (MITRE ATT&CK)."),
    ("model.html", "Threat Model", "Diamond Model of Intrusion Analysis + sources."),
]

NAV_RE = re.compile(r'<nav class="nav">.*?</nav>', re.S)
SECTION_RE = re.compile(r'<section id="([^"]+)" class="section">(.*?)</section>', re.S)


def nav_html(active_file):
    links = []
    for fname, _sec, label in PAGES:
        act = ' class="active" aria-current="page"' if fname == active_file else ""
        links.append(f'<a href="{fname}"{act}>{label}</a>')
    return "<nav class=\"nav\">\n      " + "\n      ".join(links) + "\n    </nav>"


def main():
    src = open(INDEX, encoding="utf-8").read()

    sections = dict(SECTION_RE.findall(src))
    missing = [sec for _, sec, _ in PAGES if sec not in sections]
    if missing:
        raise SystemExit(f"missing sections in index.html: {missing}")

    head, rest = src.split("<main class=\"container\">", 1)
    head = NAV_RE.sub("NAVPLACEHOLDER", head)
    main_open = "<main class=\"container\">"
    footer = rest.split("</main>", 1)[1]
    # bump asset versions so browsers pick up the new JS
    footer = (footer.replace("style.css?v=26", "style.css?v=27")
                    .replace("heatmap.js?v=5", "heatmap.js?v=6")
                    .replace("knowledge.js?v=4", "knowledge.js?v=5")
                    .replace("spa.js?v=25", "spa.js?v=26"))
    head_top = (head.split("<header", 1)[0]
                  .replace("style.css?v=26", "style.css?v=27"))
    header_open = "<header class=\"header\">\n  <div class=\"container\">\n"
    header_intro = ('    <h1 class="logo">Cyllex <span class="muted">APT Encyclopedia</span></h1>\n'
                    '    <p class="sub">Threat actor profiles, ATT&amp;CK techniques, '
                    'categorized threats and Diamond Model.</p>\n')

    hub = ('\n  <section id="explore" class="section">\n'
           '    <h2>Explore by theme</h2>\n'
           '    <p class="tech">Each theme lives on its own page — pick one to dive in. '
           'Your threat-model scope and control-stack selection persist across pages.</p>\n'
           '    <div class="grid">\n'
           + "\n".join(
               f'      <a class="card res-card" href="{f}"><h3>{t} &rarr;</h3><p class="tech">{d}</p></a>'
               for f, t, d in HUB_CARDS)
           + '\n    </div>\n  </section>\n')

    for fname, sec, label in PAGES:
        body = f'\n  <section id="{sec}" class="section">{sections[sec]}</section>\n'
        if fname == "index.html":
            body += hub
        # rename the updater button + add ATT&CK version readout (resources page)
        if sec == "resources":
            body = body.replace("Update MITRE ATT&amp;CK datasets",
                                "Check for dataset updates")
            body = body.replace("Update MITRE ATT&CK datasets",
                                "Check for dataset updates")
            body = body.replace(
                '<span class="muted" id="update-status">',
                '<span class="muted">ATT&amp;CK: <span id="attack-version">—</span></span> ·\n      <span class="muted" id="update-status">')
        page = (head_top + header_open + header_intro + "    "
                + nav_html(fname) + "\n  </div>\n</header>\n\n"
                + main_open + body + "\n</main>\n" + footer)
        page = page.replace("NAVPLACEHOLDER", "")
        # per-page title
        page = re.sub(r"<title>.*?</title>",
                      f"<title>APT Encyclopedia — {label}</title>", page, count=1)
        with open(os.path.join(ROOT, fname), "w", encoding="utf-8") as f:
            f.write(page)
        print(f"wrote {fname} ({len(page)//1024} KB)")

    # active-link styling
    css = os.path.join(ROOT, "style.css")
    s = open(css, encoding="utf-8").read()
    if ".nav a.active" not in s:
        s += ("\n/* ---------------- multi-page nav ---------------- */\n"
              ".nav a.active { color: #fff; border-bottom: 2px solid var(--cv-red); padding-bottom: 2px; }\n")
        open(css, "w", encoding="utf-8").write(s)
        print("patched style.css (nav active state)")


if __name__ == "__main__":
    main()
