"""Build the replay fixture directly from multi-host transcripts (Claude, Codex, Antigravity).

Reads the hook decisions straight out of the session logs where available so commands are stored
WHOLE. The earlier version of this script sourced from a pre-extracted json whose
commands were truncated at 4000 chars, which turned every long heredoc into an
"unterminated here document" parse failure — an artifact, not a real defect.

Keeps one row per DISTINCT bash command with the verdict the previous tool gave.
Includes automated secret redaction pass and active session transcript exclusion.
"""
import argparse
import collections
import datetime
import json
import os
import re
import sys

CODEX_DECODER = json.JSONDecoder()

TOKEN_PATTERNS = [
    re.compile(r'\b(gh[pousr]_[A-Za-z0-9]{16,})\b'),
    re.compile(r'\b(sk-[A-Za-z0-9]{16,})\b'),
    re.compile(r'\b(AKIA[0-9A-Z]{12,})\b'),
    re.compile(r'\b(xox[baprs]-[A-Za-z0-9-]{10,})\b'),
]

ENV_CRED_PATTERN = re.compile(
    r'(?i)\b([A-Za-z_][A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|PRIVATE_KEY|CREDENTIAL|SESSION_ID)[A-Za-z0-9_]*)=([\'"]?)([^\s;&|\'"]+)\2'
)

AUTH_HEADER_PATTERNS = [
    re.compile(r'(?i)\b(Bearer\s+)[A-Za-z0-9._~+/-]{16,}'),
    re.compile(r'(?i)\b(Basic\s+)[A-Za-z0-9+/=]{16,}'),
]

PRIVATE_KEY_PATTERN = re.compile(
    r'-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]+ PRIVATE KEY-----'
)

SESSION_URL_PATTERN = re.compile(
    r'claude\.ai/code/session_[A-Za-z0-9]+'
)

SESSION_ID_PATTERN = re.compile(
    r'\bsession_[A-Za-z0-9]{16,}\b'
)

JSON_CRED_PATTERN = re.compile(
    r'(?i)(["\'](?:token|secret|password|passwd|apiKey|api_key|privateKey|private_key|credential)["\']\s*:\s*)(["\'])(.*?)\2'
)


def redact_secrets(cmd: str):
    """Redact credentials, tokens, private keys, and session identifiers from command text.

    Returns (redacted_command, redaction_count).
    """
    if not cmd:
        return cmd, 0
    count = 0

    # 1. Private keys
    def sub_privkey(_):
        nonlocal count
        count += 1
        return "[REDACTED_PRIVATE_KEY]"

    cmd, _ = PRIVATE_KEY_PATTERN.subn(sub_privkey, cmd)

    # 2. Token shapes
    for pat in TOKEN_PATTERNS:
        def sub_token(_):
            nonlocal count
            count += 1
            return "<REDACTED_TOKEN>"

        cmd, _ = pat.subn(sub_token, cmd)

    # 3. Credential variable assignments
    def sub_env(m):
        nonlocal count
        count += 1
        var_name = m.group(1)
        quote = m.group(2)
        return f"{var_name}={quote}<REDACTED_SECRET>{quote}"

    cmd, _ = ENV_CRED_PATTERN.subn(sub_env, cmd)

    # 4. Auth headers
    for pat in AUTH_HEADER_PATTERNS:
        def sub_auth(m):
            nonlocal count
            count += 1
            prefix = m.group(1)
            return f"{prefix}<REDACTED_AUTH>"

        cmd, _ = pat.subn(sub_auth, cmd)

    # 5. Session URLs and IDs
    def sub_session_url(_):
        nonlocal count
        count += 1
        return "claude.ai/code/session_<REDACTED_SESSION_ID>"

    cmd, _ = SESSION_URL_PATTERN.subn(sub_session_url, cmd)

    def sub_session_id(_):
        nonlocal count
        count += 1
        return "session_<REDACTED_SESSION_ID>"

    cmd, _ = SESSION_ID_PATTERN.subn(sub_session_id, cmd)

    # 6. Structured JSON credential fields
    def sub_json_cred(m):
        nonlocal count
        count += 1
        key_prefix = m.group(1)
        quote = m.group(2)
        return f"{key_prefix}{quote}<REDACTED_SECRET>{quote}"

    cmd, _ = JSON_CRED_PATTERN.subn(sub_json_cred, cmd)

    return cmd, count


def get_active_session_ids():
    """Derive active session identifiers from environment variables."""
    active = set()
    env_keys = [
        "CLAUDE_SESSION_ID",
        "SESSION_ID",
        "CODEX_SESSION_ID",
        "AGY_CONVERSATION_ID",
        "ANTIGRAVITY_CONVERSATION_ID",
        "CONVERSATION_ID",
    ]
    for k in env_keys:
        v = os.environ.get(k)
        if v and v.strip():
            active.add(v.strip())
    return active


def is_session_excluded(path: str, excluded_sessions):
    """Return True if path belongs to an active or explicitly excluded session."""
    if not excluded_sessions:
        return False
    norm = path.replace("\\", "/")
    for s_id in excluded_sessions:
        if s_id in norm:
            return True
    return False


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
    p.add_argument(
        "--exclude-session",
        action="append",
        default=[],
        help="session ID to exclude from harvest; repeatable",
    )
    p.add_argument(
        "--stamp-meta",
        action="store_true",
        default=False,
        help="write provenance metadata sidecar file alongside destination corpus",
    )
    args = p.parse_args()

    excluded_sessions = set(args.exclude_session) | get_active_session_ids()
    if excluded_sessions:
        sys.stderr.write("excluding active sessions: %d\n" % len(excluded_sessions))

    roots = args.roots or discover_default_roots(args.host)
    files = []
    for root in roots:
        for dp, _d, fns in os.walk(root):
            for fn in fns:
                if fn.endswith(".jsonl"):
                    files.append(os.path.join(dp, fn))
    sys.stderr.write("transcripts found: %d\n" % len(files))

    rows = {}
    counts = collections.Counter()
    by_host = collections.Counter()
    redactions_total = 0
    excluded_files_count = 0
    newest_mtime = 0.0

    for path in files:
        if is_session_excluded(path, excluded_sessions):
            excluded_files_count += 1
            continue

        try:
            mtime = os.path.getmtime(path)
            if mtime > newest_mtime:
                newest_mtime = mtime
        except OSError:
            pass

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
                raw_cmd = (inp.get("command") or "").strip()
                if not raw_cmd:
                    continue

                cmd, n_redacted = redact_secrets(raw_cmd)
                redactions_total += n_redacted

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
                    raw_cmd = parse_codex_exec(payload.get("input", ""))
                    if raw_cmd and raw_cmd.strip():
                        cmd, n_redacted = redact_secrets(raw_cmd.strip())
                        redactions_total += n_redacted
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
                            raw_cmd = (args_tc.get("CommandLine") or "").strip()
                            if raw_cmd:
                                cmd, n_redacted = redact_secrets(raw_cmd)
                                redactions_total += n_redacted
                                verdict = tc.get("verdict", "allow")
                                counts[verdict] += 1
                                by_host["agy"] += 1
                                prev = rows.get(cmd)
                                if prev is None or (prev["verdict"] == "allow" and verdict != "allow"):
                                    rows[cmd] = {"cmd": cmd, "verdict": verdict}

    out = list(rows.values())
    with open(args.dest, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=0)

    if args.stamp_meta:
        meta_path = args.dest + ".meta.json"
        meta = {
            "built_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "newest_transcript_mtime": datetime.datetime.fromtimestamp(
                newest_mtime, datetime.timezone.utc
            ).isoformat() if newest_mtime > 0 else None,
            "transcripts_total": len(files),
            "transcripts_harvested": len(files) - excluded_files_count,
            "transcripts_excluded": excluded_files_count,
            "distinct_commands": len(out),
            "redactions_applied": redactions_total,
            "commands_by_host": dict(by_host),
            "records_by_verdict": dict(counts),
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    print("distinct bash commands:", len(out))
    print("commands by host:", dict(by_host))
    print("all records by verdict:", dict(counts))
    print("distinct commands previously prompted:",
          sum(1 for r in out if r["verdict"] != "allow"))
    print("longest command:", max((len(r["cmd"]) for r in out), default=0))
    print("secrets redacted:", redactions_total)
    print("active session transcripts excluded:", excluded_files_count)
    print("bytes:", os.path.getsize(args.dest))


if __name__ == "__main__":
    main()
