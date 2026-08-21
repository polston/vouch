"""Build the replay fixture directly from Claude Code transcripts.

Reads the hook decisions straight out of the session logs so commands are stored
WHOLE. The earlier version of this script sourced from a pre-extracted json whose
commands were truncated at 4000 chars, which turned every long heredoc into an
"unterminated here document" parse failure — an artifact, not a real defect.

Keeps one row per DISTINCT bash command with the verdict the previous tool gave.
"""
import json, os, sys, collections

ROOTS = [
    os.path.join(os.path.expanduser("~"), ".claude", "projects"),
    os.path.join(
        os.path.expanduser("~"),
        "AppData/Local/Temp/claude/C--project",
        "00000000-0000-0000-0000-000000000000/scratchpad/mac",
    ),
]
OUT = os.path.dirname(os.path.abspath(__file__))

files = []
for root in ROOTS:
    for dp, _d, fns in os.walk(root):
        for fn in fns:
            if fn.endswith(".jsonl"):
                files.append(os.path.join(dp, fn))
sys.stderr.write("transcripts: %d\n" % len(files))

rows = {}
counts = collections.Counter()

for path in files:
    tools = {}
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        continue
    with fh:
        for line in fh:
            if '"attachment"' not in line and '"tool_use"' not in line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue

            msg = rec.get("message") or {}
            content = msg.get("content")
            if isinstance(content, list):
                for b in content:
                    if isinstance(b, dict) and b.get("type") == "tool_use":
                        tools[b.get("id")] = (b.get("name"), b.get("input"))

            att = rec.get("attachment")
            if not isinstance(att, dict):
                continue
            if not (att.get("hookName") or "").startswith("PreToolUse"):
                continue
            stdout = att.get("stdout") or ""
            if not stdout.strip():
                continue
            try:
                hso = json.loads(stdout).get("hookSpecificOutput") or {}
            except Exception:
                continue
            verdict = hso.get("permissionDecision")
            if not verdict:
                continue

            name, inp = tools.get(att.get("toolUseID"), (None, None))
            if name != "Bash" or not isinstance(inp, dict):
                continue
            cmd = (inp.get("command") or "").strip()
            if not cmd:
                continue

            counts[verdict] += 1
            prev = rows.get(cmd)
            if prev is None or (prev["verdict"] == "allow" and verdict != "allow"):
                rows[cmd] = {"cmd": cmd, "verdict": verdict}

out = list(rows.values())
with open(os.path.join(OUT, "bash_corpus.json"), "w", encoding="utf-8") as f:
    json.dump(out, f, indent=0)

print("distinct bash commands:", len(out))
print("all records by verdict:", dict(counts))
print("distinct commands previously prompted:",
      sum(1 for r in out if r["verdict"] != "allow"))
print("longest command:", max((len(r["cmd"]) for r in out), default=0))
print("bytes:", os.path.getsize(os.path.join(OUT, "bash_corpus.json")))
