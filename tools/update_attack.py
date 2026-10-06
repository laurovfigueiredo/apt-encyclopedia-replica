#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
UPSTREAM_REPO = "https://github.com/ControlCompass/ControlCompass.github.io.git"
UPSTREAM_JSON = "https://gist.githubusercontent.com/ControlCompass/da98f63af81c831d15cb794ab8646038/raw/5cd4465769dd5a2b316261f60d2bae26c6cc7bec/All_v11_Techniques.json"
ATTACK_DEFS = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def run_log(cmd, cwd=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=600, text=True)
        return p.returncode, p.stdout
    except Exception as e:
        return 1, str(e)


def fetch_json(url):
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            data = r.read()
        return json.loads(data.decode('utf-8'))
    except Exception as e:
        raise RuntimeError(f"fetch {url} failed: {e}")


def main():
    log = []
    tmp = tempfile.mkdtemp(prefix="cvc_upd_")
    log.append(f"temp dir: {tmp}")
    code, out = run_log(["git", "clone", "--depth", "1", UPSTREAM_REPO, tmp])
    log.append(out)
    if code != 0:
        print(json.dumps({"ok": False, "log": log}))
        return 1

    code, out = run_log(["python3", os.path.join(HERE, "parse_resources.py"), tmp])
    log.append(out)
    if code != 0:
        print(json.dumps({"ok": False, "log": log}))
        return 1

    code, out = run_log(["python3", os.path.join(HERE, "parse_guide.py"), tmp])
    log.append(out)
    if code != 0:
        print(json.dumps({"ok": False, "log": log}))
        return 1

    # All_v11
    try:
        allv = fetch_json(UPSTREAM_JSON)
        with open(os.path.join(ROOT, "data", "intel", "all_attack_v11.json"), "w") as f:
            json.dump(allv, f, separators=(",", ":"))
        log.append("wrote data/intel/all_attack_v11.json")
    except Exception as e:
        log.append(f"warn: all_v11 {e}")

    # enterprise-attack definitions (best-effort)
    try:
        defs = fetch_json(ATTACK_DEFS)
        with open(os.path.join(ROOT, "data", "intel", "enterprise_attack.json"), "w") as f:
            json.dump(defs, f, separators=(",", ":"))
        log.append("wrote data/intel/enterprise_attack.json")
    except Exception as e:
        log.append(f"warn: enterprise_attack {e}")

    with open(os.path.join(ROOT, "data", "last_update.txt"), "w") as f:
        f.write(datetime.utcnow().isoformat() + "Z")
    log.append("wrote last_update.txt")

    print(json.dumps({"ok": True, "log": log}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
