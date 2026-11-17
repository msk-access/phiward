"""Add (or with `remove`, take out) `allowWrite ~/.phiward/spool` in a Claude Code settings file,
as an older phiward wrote it. For the quickstart check's old-settings scenario."""
import json
import os
import sys

path = sys.argv[1]
data = json.load(open(path)) if os.path.exists(path) else {}
fs = data.setdefault("sandbox", {}).setdefault("filesystem", {})
allow = [a for a in fs.get("allowWrite", []) if a != "~/.phiward/spool"]
if sys.argv[2:] != ["remove"]:
    allow.append("~/.phiward/spool")
fs["allowWrite"] = allow
with open(path, "w") as fh:
    json.dump(data, fh, indent=2)
