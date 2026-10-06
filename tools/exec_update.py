#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPSTREAM = "https://github.com/ControlCompass/ControlCompass.github.io.git"

def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900, text=True)
    return p.returncode, p.stdout

def main():
    tmp = tempfile.mkdtemp(prefix="cvc_upd_")
    steps = []
    code, out = run(["git", "clone", "--depth", "1", UPSTREAM, tmp])
    steps.append(("clone", code, out[:800]))
    if code != 0:
        print(json.dumps({"ok": False, "steps": steps}))
        return 1
    code, out = run(["python3", os.path.join(ROOT, "tools", "parse_resources.py"), tmp])
    steps.append(("parse_resources", code, out[:1200]))
    if code != 0:
        print(json.dumps({"ok": False, "steps": steps}))
        return 1
    code, out = run(["python3", os.path.join(ROOT, "tools", "parse_guide.py"), tmp])
    steps.append(("parse_guide", code, out[:600]))
    ts = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    open(os.path.join(ROOT, "data", "last_update.txt"), "w").write(ts)
    steps.append(("timestamp", 0, ts))
    print(json.dumps({"ok": True, "steps": steps, "last": ts}))
    return 0

if __name__ == "__main__":
    sys.exit(main())
