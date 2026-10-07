#!/usr/bin/env python3
"""Refresh local ATT&CK technique data straight from MITRE CTI.

Source: https://github.com/mitre-attack/attack-stix-data
  enterprise-attack.json (STIX 2.1 bundle, no API key needed)

What it does:
  1. Resolves the latest release tag via the GitHub API (version stamp;
     the bundle itself is pulled from master, which tracks the release).
  2. Extracts attack-pattern objects -> id, name, tactics, description,
     platforms, revoked/deprecated flags.
  3. Merges into data/techniques.json -- MITRE-owned fields are updated,
     local fields (usage, groups) are preserved. Writes .bak first.
  4. Updates matching entries in data/technique_index.json (name/tactics/
     desc only -- Compass counts c/n are never touched).
  5. Bumps the ATT&CK major version in heatmap.js (ATTACK_VERSIONS).
  6. Writes data/attack_version.txt and prints a diff summary.

Usage:
  python3 tools/update_mitre.py --check-only
  python3 tools/update_mitre.py
  python3 tools/update_mitre.py --bundle /tmp/enterprise-attack.json [--tag v16.1]

Exit codes: 0 ok / up-to-date, 1 error, 2 update available (--check-only).
"""
import argparse
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")

RELEASE_API = "https://api.github.com/repos/mitre-attack/attack-stix-data/releases/latest"
BUNDLE_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
              "/master/enterprise-attack/enterprise-attack.json")
UA = {"User-Agent": "apt-encyclopedia-replica-updater/1.0"}


def log(msg):
    print(msg, flush=True)


def http_json(url, timeout=60):
    req = urllib.request.Request(url, headers={**UA, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def http_bytes(url, timeout=600):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def major_of(tag):
    m = re.search(r"(\d+)", str(tag or ""))
    return m.group(1) if m else None


def local_attack_major():
    try:
        src = open(os.path.join(ROOT, "heatmap.js"), encoding="utf-8").read()
        m = re.search(r"attack:\s*'(\d+)'", src)
        if m:
            return m.group(1)
    except OSError:
        pass
    return None


def detect_style(path):
    """Match the file's existing indent/encoding so the diff stays small."""
    raw = open(path, encoding="utf-8").read()
    m = re.search(r"\n( +)\"", raw)
    return (len(m.group(1)) if m else 1,
            bool(re.search(r"\\u[0-9a-fA-F]{4}", raw)))


def attack_url(tid):
    if "." in tid:
        base, sub = tid.split(".", 1)
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/{tid}/"


def extract_techniques(bundle):
    out = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext = next((x for x in obj.get("external_references", [])
                    if x.get("source_name") == "mitre-attack"
                    and str(x.get("external_id", "")).startswith("T")), None)
        if not ext:
            continue
        tid = ext["external_id"]
        tactics = sorted({p["phase_name"].replace("-", " ").title()
                          for p in obj.get("kill_chain_phases", [])
                          if p.get("kill_chain_name") == "mitre-attack"
                          and p.get("phase_name")})
        out[tid] = {
            "id": tid,
            "name": obj.get("name", tid),
            "tactic": tactics[0] if tactics else "",
            "tactics": tactics,
            "description": obj.get("description", "") or "",
            "platforms": obj.get("x_mitre_platforms", []) or [],
            "isSubtechnique": "." in tid,
            "revoked": bool(obj.get("revoked", False)),
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "url": attack_url(tid),
        }
    return out


def load_json_list(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"{path} is not a JSON list")
    return data


def write_json(path, data):
    indent, ascii_only = detect_style(path)
    os.replace(path, path + ".bak")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, ensure_ascii=ascii_only)
        f.write("\n")


def merge_techniques(existing, upstream):
    by_id = {e.get("id"): e for e in existing
             if isinstance(e, dict) and e.get("id")}
    added, updated, revoked, deprecated, stale = [], [], [], [], []
    for tid, u in sorted(upstream.items()):
        cur = by_id.get(tid)
        flag = "revoked" if u["revoked"] else ("deprecated" if u["deprecated"] else None)
        if cur is None:
            by_id[tid] = {
                "id": tid, "name": u["name"], "tactic": u["tactic"],
                "tactics": u["tactics"], "description": u["description"],
                "usage": None, "platforms": u["platforms"],
                "isSubtechnique": u["isSubtechnique"],
                "status": flag or "active", "url": u["url"], "groups": [],
            }
            added.append(tid)
            continue
        changed = False
        for k in ("name", "tactic", "tactics", "description",
                  "platforms", "url", "isSubtechnique"):
            if cur.get(k) != u[k]:
                cur[k] = u[k]
                changed = True
        if flag:
            if cur.get("status") != flag:
                cur["status"] = flag
                changed = True
            (revoked if flag == "revoked" else deprecated).append(tid)
        elif cur.get("status") in ("revoked", "deprecated"):
            cur["status"] = "active"  # MITRE un-flagged it
            changed = True
        if changed:
            updated.append(tid)
    stale = sorted(t for t in by_id if t not in upstream)
    ordered = [by_id[e.get("id")] for e in existing
               if isinstance(e, dict) and e.get("id") in by_id]
    ordered += [by_id[t] for t in sorted(added)]
    return ordered, {"added": added, "updated": updated, "revoked": revoked,
                     "deprecated": deprecated, "stale": stale}


def merge_index(existing, upstream):
    by_id = {e.get("id"): e for e in existing
             if isinstance(e, dict) and e.get("id")}
    shape_c = any("c" in e for e in by_id.values())
    shape_n = any("n" in e for e in by_id.values())
    added, updated = [], []
    for tid, u in sorted(upstream.items()):
        cur = by_id.get(tid)
        if cur is None:
            row = {"id": tid, "name": u["name"],
                   "tactics": u["tactics"], "desc": u["description"]}
            if shape_c:
                row["c"] = [0, 0, 0]
            if shape_n:
                row["n"] = {}
            by_id[tid] = row
            added.append(tid)
            continue
        changed = False
        for k, v in (("name", u["name"]), ("tactics", u["tactics"]),
                     ("desc", u["description"])):
            if k in cur and cur[k] != v:
                cur[k] = v
                changed = True
        if changed:
            updated.append(tid)
    ordered = [by_id[e.get("id")] for e in existing
               if isinstance(e, dict) and e.get("id") in by_id]
    ordered += [by_id[t] for t in sorted(added)]
    return ordered, {"added": added, "updated": updated}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Refresh local ATT&CK data from MITRE CTI.")
    ap.add_argument("--check-only", action="store_true",
                    help="compare versions, change nothing")
    ap.add_argument("--bundle", default=None,
                    help="use a local enterprise-attack.json instead of downloading")
    ap.add_argument("--tag", default=None,
                    help="release tag for stamping when --bundle is used offline")
    args = ap.parse_args(argv)

    local_major = local_attack_major() or "?"
    tag, upstream_major = args.tag, major_of(args.tag)

    if args.check_only:
        if not upstream_major:
            try:
                rel = http_json(RELEASE_API)
                tag = rel.get("tag_name") or rel.get("name")
                upstream_major = major_of(tag)
            except Exception as e:
                log(f"ERROR: could not reach the MITRE release API: {e}")
                return 1
        log(f"local ATT&CK major : v{local_major}")
        log(f"upstream release  : {tag} (ATT&CK v{upstream_major})")
        if str(upstream_major) != str(local_major):
            log("UPDATE AVAILABLE -- run: python3 tools/update_mitre.py")
            return 2
        log("Up to date.")
        return 0

    if args.bundle:
        log(f"loading bundle from {args.bundle} ...")
        with open(args.bundle, "rb") as f:
            bundle = json.loads(f.read().decode("utf-8"))
    else:
        log("resolving latest MITRE release ...")
        try:
            rel = http_json(RELEASE_API)
            tag = tag or rel.get("tag_name") or rel.get("name")
            upstream_major = upstream_major or major_of(tag)
        except Exception as e:
            log(f"ERROR: {e}")
            return 1
        log(f"downloading bundle ({tag}) ...")
        try:
            bundle = json.loads(http_bytes(BUNDLE_URL).decode("utf-8"))
        except Exception as e:
            log(f"ERROR downloading bundle: {e}")
            return 1

    upstream = extract_techniques(bundle)
    log(f"upstream techniques: {len(upstream)}")
    if not upstream:
        log("ERROR: no attack-pattern objects found -- refusing to wipe local data.")
        return 1

    tech_path = os.path.join(DATA, "techniques.json")
    merged, rep = merge_techniques(load_json_list(tech_path), upstream)
    write_json(tech_path, merged)

    idx_path = os.path.join(DATA, "technique_index.json")
    idx_rep = {"added": [], "updated": []}
    if os.path.exists(idx_path):
        merged_idx, idx_rep = merge_index(load_json_list(idx_path), upstream)
        write_json(idx_path, merged_idx)

    bumped = False
    if upstream_major and str(upstream_major) != str(local_major):
        hp = os.path.join(ROOT, "heatmap.js")
        src = open(hp, encoding="utf-8").read()
        new, n = re.subn(r"attack:\s*'\d+'", f"attack: '{upstream_major}'",
                         src, count=1)
        if n:
            open(hp, "w", encoding="utf-8").write(new)
            bumped = True

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(os.path.join(DATA, "attack_version.txt"), "w", encoding="utf-8") as f:
        f.write(f"{upstream_major or local_major}\n"
                f"tag: {tag or 'unknown'}\nrefreshed: {stamp}\n")

    log(f"techniques.json: +{len(rep['added'])} new, "
        f"~{len(rep['updated'])} updated, "
        f"{len(rep['revoked'])} revoked, {len(rep['deprecated'])} deprecated, "
        f"{len(rep['stale'])} local-only (kept)")
    if rep["stale"][:10]:
        log(f"  local-only sample: {', '.join(rep['stale'][:10])}")
    log(f"technique_index.json: +{len(idx_rep['added'])} new, "
        f"~{len(idx_rep['updated'])} updated (counts preserved)")
    log(f"heatmap.js ATT&CK version: {'bumped to ' + upstream_major if bumped else 'unchanged'}")
    log("backups: data/techniques.json.bak"
        + (" data/technique_index.json.bak" if idx_rep["added"] or idx_rep["updated"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
