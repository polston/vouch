"""Print the surviving NOISE prompts from the replay corpus, with reasons.

A percentage does not say whether the prompts are right. This lists the actual
survivors so each can be judged, rather than tuning a default toward a number.
"""
import json
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXE = os.path.join(ROOT, "target", "release", "vouch.exe")
FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bash_corpus.json")

env = dict(os.environ)
env["VOUCH_STATE_DIR"] = os.path.join(os.environ.get("TEMP", "/tmp"), "vouch_noise_scratch")

rows = json.load(open(FIX, encoding="utf-8"))
asked = [r["cmd"] for r in rows if r.get("verdict") == "ask"]
print("old tool asked on %d distinct commands" % len(asked))

counts, samples = {}, {}
for c in asked:
    snippet = {
        "hook_event_name": "PreToolUse", "tool_use_id": "n", "session_id": "n",
        "cwd": "C:/claude", "tool_name": "Bash", "tool_input": {"command": c},
    }
    p = subprocess.run([EXE, "--hook"], input=json.dumps(snippet),
                       capture_output=True, text=True, env=env, timeout=20)
    if p.returncode != 0 or not p.stdout.strip():
        continue
    d = json.loads(p.stdout)["hookSpecificOutput"]
    if d.get("permissionDecision") != "ask":
        continue
    reason = d.get("permissionDecisionReason") or ""
    first = reason.splitlines()[0].replace("vouch stopped on: ", "")
    if "(guard)" in first or "protected file" in reason or "allowed area" in reason:
        continue  # deliberate, not noise
    counts[first] = counts.get(first, 0) + 1
    samples.setdefault(first, []).append((c, reason))

for k, n in sorted(counts.items(), key=lambda x: -x[1]):
    print("\n%4d  %s" % (n, k))
    for c, reason in samples[k][:8]:
        print("        " + " ".join(c.split())[:140])
        for ln in reason.splitlines():
            if ln.strip().startswith("the path:"):
                print("            " + ln.strip())
