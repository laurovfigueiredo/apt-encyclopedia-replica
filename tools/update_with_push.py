#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd, cwd=None, env=None):
    e = os.environ.copy()
    e["GIT_SSH_COMMAND"] = "ssh -i ~/.ssh/id_ed25519_apt -o IdentitiesOnly=yes"
    if env:
        e.update(env)
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1800, text=True, env=e)
    return p.returncode, p.stdout

def main():
    steps = []
    code, out = run(["python3", os.path.join(ROOT, "tools", "update_attack.py")], cwd=ROOT)
    steps.append(("update_attack", code, out[-1500:]))
    if code != 0:
        print(json.dumps({"ok": False, "steps": steps}, ensure_ascii=False))
        return 1
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    with open(os.path.join(ROOT, "data", "last_update.txt"), "w") as f:
        f.write(ts)
    steps.append(("timestamp", 0, ts))
    code, out = run(["git", "add", "data", "tools", "data/intel"], cwd=ROOT)
    steps.append(("git_add", code, out[-400:]))
    code, out = run(["git", "commit", "-m", f"Update MITRE ATT&CK datasets ({ts})"], cwd=ROOT)
    steps.append(("git_commit", code, out[-700:]))
    code, out = run(["git", "push", "origin", "main"], cwd=ROOT)
    steps.append(("git_push", code, out[-1200:]))
    ok = code == 0
    print(json.dumps({"ok": ok, "steps": steps, "last": ts}, ensure_ascii=False))
    return 0 if ok else 2

if __name__ == "__main__":
    sys.exit(main())
