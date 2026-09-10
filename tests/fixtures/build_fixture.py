"""Build the replay fixture directly from multi-host transcripts (Claude, Codex, Antigravity).

Reads the hook decisions straight out of the session logs where available so commands are stored
WHOLE. The earlier version of this script sourced from a pre-extracted json whose
commands were truncated at 4000 chars, which turned every long heredoc into an
"unterminated here document" parse failure — an artifact, not a real defect.

Keeps one row per DISTINCT bash command with the verdict the previous tool gave.
"""
import argparse, collections, json, os, sys

CODEX_DECODER = json.JSONDecoder()


def parse_codex_exec(s):
    idx = s.find("cmd:")
    if idx == -1:
        idx = s.find('"cmd":')
        if idx != -1:
            idx += 6
    else:
        idx += 4
    if idx == -1:
        return None
    while idx < len(s) and s[idx] in " \t\r\n":
        idx += 1
    if idx >= len(s) or s[idx] != '"':
        return None
    try:
        cmd, _ = CODEX_DECODER.raw_decode(s, idx)
        return cmd
    except Exception:
        return None


def detect_file_host(path, sample_lines):
    norm = path.replace("\\", "/").lower()
    if "antigravity-cli/brain" in norm or norm.endswith("/transcript.jsonl") or norm.endswith("/transcript_full.jsonl"):
        return "agy"
    if "codex/sessions" in norm or os.path.basename(norm).startswith("rollout-"):
        return "codex"
    if ".claude/projects" in norm:
        return "claude"

    for line in sample_lines:
        if '"tool_calls"' in line or '"toolCall"' in line or '"workspacePaths"' in line:
            return "agy"
        if '"custom_tool_call"' in line or '"function_call"' in line or '"response_item"' in line:
            return "codex"
        if '"tool_use"' in line or '"attachment"' in line:
            return "claude"
    return "claude"


def discover_default_roots(selected_host="all"):
    home = os.path.expanduser("~")
    candidates = [
        ("claude", os.path.join(home, ".claude", "projects")),
        ("codex", os.path.join(home, ".codex", "sessions")),
        ("agy", os.path.join(home, ".gemini", "antigravity-cli", "brain")),
    ]
    roots = []
    for host, root in candidates:
        if selected_host != "all" and selected_host != host:
            continue
        if os.path.isdir(root):
            roots.append(root)
    return roots


def main():
    p = argparse.ArgumentParser(description="Build replay fixture from transcripts across hosts.")
    p.add_argument(
        "--host",
        choices=["all", "claude", "codex", "agy"],
        default="all",
        help="harness to harvest transcripts from: all, claude, codex, agy (default: all)",
    )
    p.add_argument(
        "--roots",
        action="append",
        default=None,
        help="transcript root; repeatable (default: auto-discovered for --host)",
    )
    p.add_argument(
        "--dest",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "bash_corpus.json"),
        help="destination json path",
    )
    args = p.parse_args()

    roots = args.roots or discover_default_roots(args.host)
    files = []
    for root in roots:
        for dp, _d, fns in os.walk(root):
            for fn in fns:
                if fn.endswith(".jsonl"):
                    files.append(os.path.join(dp, fn))
    sys.stderr.write("transcripts: %d\n" % len(files))

    rows = {}
    counts = collections.Counter()
    by_host = collections.Counter()

    for path in files:
        try:
            fh = open(path, "r", encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            lines = fh.readlines()

        if not lines:
            continue

        host = detect_file_host(path, lines[:20])

        if host == "claude":
            tools = {}
            for line in lines:
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
                by_host["claude"] += 1
                prev = rows.get(cmd)
                if prev is None or (prev["verdict"] == "allow" and verdict != "allow"):
                    rows[cmd] = {"cmd": cmd, "verdict": verdict}

        elif host == "codex":
            for line in lines:
                if '"custom_tool_call"' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                payload = rec.get("payload") or rec.get("item")
                if not isinstance(payload, dict):
                    continue
                if payload.get("type") == "custom_tool_call" and payload.get("name") == "exec":
                    cmd = parse_codex_exec(payload.get("input", ""))
                    if cmd and cmd.strip():
                        cmd = cmd.strip()
                        verdict = payload.get("verdict", "allow")
                        counts[verdict] += 1
                        by_host["codex"] += 1
                        prev = rows.get(cmd)
                        if prev is None or (prev["verdict"] == "allow" and verdict != "allow"):
                            rows[cmd] = {"cmd": cmd, "verdict": verdict}

        elif host == "agy":
            for line in lines:
                if '"tool_calls"' not in line and '"toolCall"' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                tcs = rec.get("tool_calls")
                if not tcs and isinstance(rec.get("toolCall"), dict):
                    tcs = [rec["toolCall"]]
                if not isinstance(tcs, list):
                    continue
                for tc in tcs:
                    if not isinstance(tc, dict):
                        continue
                    if tc.get("name") == "run_command":
                        args_tc = tc.get("args") or {}
                        if isinstance(args_tc, dict):
                            cmd = (args_tc.get("CommandLine") or "").strip()
                            if cmd:
                                verdict = tc.get("verdict", "allow")
                                counts[verdict] += 1
                                by_host["agy"] += 1
                                prev = rows.get(cmd)
                                if prev is None or (prev["verdict"] == "allow" and verdict != "allow"):
                                    rows[cmd] = {"cmd": cmd, "verdict": verdict}

    out = list(rows.values())
    with open(args.dest, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=0)

    print("distinct bash commands:", len(out))
    print("commands by host:", dict(by_host))
    print("all records by verdict:", dict(counts))
    print("distinct commands previously prompted:",
          sum(1 for r in out if r["verdict"] != "allow"))
    print("longest command:", max((len(r["cmd"]) for r in out), default=0))
    print("bytes:", os.path.getsize(args.dest))


if __name__ == "__main__":
    main()
