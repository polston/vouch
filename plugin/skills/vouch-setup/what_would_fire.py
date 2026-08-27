"""what_would_fire.py - counts-only decision replay of this machine's own
recorded session history against a CANDIDATE vouch config.

Privacy properties (spec 2026-08-20-distribution-design.md section 5):
- extracted commands are held in memory; NO file of them is written unless
  --samples-dest names an ABSOLUTE path outside every git worktree, and
  --samples-source (which reads such a file back, so phase 5 replays the same
  rows) is held to the same rule
- stdout carries counts, reason classes and program names - never command text
- the replay journal (which carries command text by construction - the row
  field is `cmd`) lands in a throwaway VOUCH_STATE_DIR and is deleted

The two source contracts this is built against, field names recorded exactly
as the code spells them:

  src/protocol.rs `HookInput` (no serde renames): `hook_event_name`,
  `tool_use_id`, `session_id`, `cwd`, `permission_mode`, `tool_name`,
  `tool_input`. `tool_input` itself carries `command`, `file_path`, `url`
  and keeps every other key. `--hook` reads ONE JSON object on stdin;
  `--hook-batch` reads one object per line and emits only index/status/emitted
  JSONL, while applying the same decision and journal path to every object.

  src/journal.rs `Record`: `id`, `ts`, `session`, `tool`, `cmd`, `verdict`,
  `reason`, `mode`, `cwd`, `outcome`, `lang`, `permission_mode`. The row's
  session identifier is named `session` (NOT `session_id`) and is populated
  from the input's `session_id` - that pairing is the join. The row also
  carries the full command text in `cmd`, which is why the scratch journal
  is itself harvested text and must die with the run.

Two journal facts the join is built around, both from src/main.rs:
  - a batch row whose input the binary cannot parse reports `refused` and
    writes NO journal row (`parse_input` error, before any journalling)
  - a snippet-bearing call writes ONE ROW PER SNIPPET, all carrying the same
    decision, so the join is many-to-one and reconciled by count
"""

import argparse
import concurrent.futures
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid

# The permission mode every replayed call is stamped with. A per-call fact the
# harness supplies rather than derives; the sentinel proves the candidate
# config does not stand down at it before any number is reported.
STAMPED_MODE = "default"

# ---------------------------------------------------------------- destinations


def refuse_unsafe_dest(p, flag="--samples-dest"):
    """Refuse a samples path that is relative or inside a repository.

    RESOLVE first (junctions/.. segments), then: absolute required, and no
    EXISTING ancestor of the resolved path contains a .git entry. Walk up to
    the first existing ancestor before testing - a not-yet-created
    subdirectory must not skip the check. `.git` is tested with exists()
    rather than is_dir() because a worktree's `.git` is a FILE.

    Applied to the SOURCE side too, not only the destination: a samples file
    holds harvested command text wherever it came from, and reading one out
    of a repository would mean it is already somewhere it must never be.
    """
    path = pathlib.Path(p)
    if not path.is_absolute():
        sys.exit("%s must be absolute" % flag)
    probe = path.resolve()
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    for anc in [probe] + list(probe.parents):
        if (anc / ".git").exists():
            sys.exit("%s must not resolve inside a git worktree" % flag)


# -------------------------------------------------------------------- harvest


class Row:
    """One recorded tool call, as replayable input. Held in memory only."""

    __slots__ = ("tool_use_id", "tool", "input", "cwd", "sidechain", "decided")

    def __init__(self, tool_use_id, tool, tool_input, cwd, sidechain, decided):
        self.tool_use_id = tool_use_id
        self.tool = tool
        self.input = tool_input
        self.cwd = cwd
        self.sidechain = sidechain
        self.decided = decided


def harvest(roots):
    """Walk every *.jsonl under each root and collect the tool calls.

    Returns (rows, counters). SNAPSHOT ONCE: phase 5's re-run must replay this
    exact row set rather than harvesting again - the store grows while it is
    being measured, and a re-harvest would fold new history into the delta.
    The mechanism for that is `--samples-dest` here and `--samples-source` on
    the later run; without those flags the reuse would be a claim with nothing
    behind it, because a second invocation has no memory of this one.
    """
    files = []
    for root in roots:
        for dp, _d, fns in os.walk(root):
            for fn in fns:
                if fn.endswith(".jsonl"):
                    files.append(os.path.join(dp, fn))

    by_id = {}
    order = []
    previously_decided = set()
    records = 0
    blocks_found = 0
    duplicates = 0

    for path in files:
        try:
            fh = open(path, "r", encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                if '"tool_use"' not in line and '"attachment"' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                records += 1

                # A PreToolUse hook attachment whose stdout carried a
                # permissionDecision means some gate already decided this
                # call. Marked, never used as a filter: a fresh machine has
                # no prior gate, and zero-rows-from-full-logs must stay
                # distinguishable from no-logs.
                att = rec.get("attachment")
                if isinstance(att, dict) and str(att.get("hookName") or "").startswith(
                    "PreToolUse"
                ):
                    out = att.get("stdout") or ""
                    if out.strip():
                        try:
                            hso = json.loads(out).get("hookSpecificOutput") or {}
                        except Exception:
                            hso = {}
                        if hso.get("permissionDecision"):
                            previously_decided.add(att.get("toolUseID"))

                msg = rec.get("message") or {}
                content = msg.get("content")
                if not isinstance(content, list):
                    continue
                cwd = rec.get("cwd")
                sidechain = bool(rec.get("isSidechain"))
                for b in content:
                    if not isinstance(b, dict) or b.get("type") != "tool_use":
                        continue
                    blocks_found += 1
                    tid = b.get("id")
                    # Resumed and branched sessions rewrite prior history, so
                    # the same tool_use id appears in more than one file.
                    if tid in by_id:
                        duplicates += 1
                        continue
                    ti = b.get("input")
                    by_id[tid] = Row(
                        tid,
                        b.get("name") or "",
                        ti if isinstance(ti, dict) else {},
                        cwd,
                        sidechain,
                        False,
                    )
                    order.append(tid)

    rows = [by_id[t] for t in order]
    for r in rows:
        r.decided = r.tool_use_id in previously_decided

    counters = {
        "files": len(files),
        "records": records,
        "blocks_found": blocks_found,
        "duplicates": duplicates,
        "rows": len(rows),
        "previously_decided": sum(1 for r in rows if r.decided),
        "sidechain_rows": sum(1 for r in rows if r.sidechain),
        "mainthread_rows": sum(1 for r in rows if not r.sidechain),
        "rows_missing_cwd": sum(1 for r in rows if not r.cwd),
    }
    return rows, counters


SAMPLES_MARKER = "wwf_samples"


def write_samples(path, rows, counters, capped):
    """Write the snapshotted row set, so phase 5 can replay THIS row set.

    A header line carries the harvest counters and the cap as they were, so a
    reload reports the same figures rather than re-deriving what it can and
    silently dropping what it cannot (files, records, blocks found and
    duplicates are harvest-time facts that rows do not carry). Every row
    carries `sidechain` and `decided` for the same reason.

    The file is harvested command text. It exists only where the caller named
    an absolute path outside every repository, and the caller deletes it.
    """
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(
            json.dumps({SAMPLES_MARKER: 1, "counters": counters, "capped": capped})
            + "\n"
        )
        for r in rows:
            fh.write(
                json.dumps(
                    {
                        "id": r.tool_use_id,
                        "tool": r.tool,
                        "input": r.input,
                        "cwd": r.cwd,
                        "sidechain": r.sidechain,
                        "decided": r.decided,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )


def read_samples(path):
    """Load a row set written by --samples-dest. Returns (rows, counters, capped).

    Phase 5 re-runs the replay against the SAME rows: the transcript store
    grows while it is being measured, and a re-harvest would fold new history
    into the delta table, which is what makes a before/after comparison
    unreadable.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        try:
            head = json.loads(first)
        except Exception:
            head = None
        if not isinstance(head, dict) or SAMPLES_MARKER not in head:
            sys.exit(
                "--samples-source: %s was not written by --samples-dest (no header "
                "line). Refusing to guess at its shape." % path
            )
        rows = []
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            ti = r.get("input")
            rows.append(
                Row(
                    r.get("id"),
                    r.get("tool") or "",
                    ti if isinstance(ti, dict) else {},
                    r.get("cwd"),
                    bool(r.get("sidechain")),
                    bool(r.get("decided")),
                )
            )
    return rows, head.get("counters") or {}, head.get("capped")


def hook_json(row, idx, fallback_cwd):
    """One hook-input object for one recorded call.

    `session_id` "wwf-<idx>" is what joins this call to the journal row(s) it
    causes (journal field: `session`). `permission_mode` is stamped
    "default" - the sentinel proves the candidate config does not stand down
    at that mode before any number is reported.
    """
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "wwf-%d" % idx,
        "tool_use_id": "wwf-%d" % idx,
        "cwd": row.cwd or fallback_cwd,
        "permission_mode": STAMPED_MODE,
        "tool_name": row.tool,
        "tool_input": row.input,
    }


def call_shape(row):
    """The dedup key for "distinct shapes": the tool plus its whole input.

    Held and counted, never printed. Canonical JSON so key order in the
    transcript cannot split one shape into two.
    """
    try:
        body = json.dumps(row.input, sort_keys=True, ensure_ascii=False)
    except Exception:
        body = repr(row.input)
    return row.tool + "\x00" + body


# A head is printed only if it looks like a plain program name. Anything else
# is a fragment of a command line, and command text never enters this report -
# so a variable head, an operator, or a token carrying punctuation is bucketed
# instead of printed. (Measured: without this, a stopwatch expression and a
# shell `&` reached the terminal report on the first smoke run.)
NAME_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-+~")
UNNAMEABLE_HEAD = "<computed or non-name head>"


def head_name(row):
    """An APPROXIMATION of the program a call runs, for the name table.

    The first token of the recorded command, leading NAME=value assignments
    skipped, quotes stripped, and a path-spelled head reduced to its base
    name (which is how vouch itself recognises a path-spelled head). A token
    that is not a plain name is bucketed under one label rather than printed.
    This is NOT vouch's own parse - it cannot see wrappers, snippets, or a
    computed head - and the report says so. Calls carrying no `command`
    field are grouped under their tool name instead.
    """
    cmd = row.input.get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        return "tool:" + (row.tool or "?")
    for tok in cmd.split():
        t = tok.strip("'\"")
        if not t:
            continue
        if "=" in t and not t.startswith("-") and t.split("=", 1)[0].isidentifier():
            continue  # a leading environment assignment, not the head
        base = t.replace("\\", "/").rstrip("/").split("/")[-1]
        if not base or set(base) - NAME_CHARS:
            return UNNAMEABLE_HEAD
        return base
    return UNNAMEABLE_HEAD


# ------------------------------------------------------------------ TOML out


def _toml_str(s):
    out = s.replace("\\", "\\\\").replace('"', '\\"')
    out = out.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return '"' + out + '"'


def _is_table_array(v):
    """A non-empty list whose every element is a table.

    An EMPTY list is not one: nothing distinguishes an empty array of tables
    from an empty array of strings, and `key = []` loads correctly as either.
    """
    return isinstance(v, list) and bool(v) and all(isinstance(x, dict) for x in v)


def _toml_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return _toml_str(v)
    if isinstance(v, list):
        if any(isinstance(x, dict) for x in v):
            # A uniform array of tables is emitted by `emit_toml` as [[…]]
            # headers and never reaches here; a MIXED list is a shape no vouch
            # config has and no inline spelling would round-trip, so it raises.
            raise TypeError("list mixing tables and scalars")
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    raise TypeError(type(v).__name__)


def emit_toml(data, prefix="", out=None):
    """A minimal writer for the shapes vouch's config has.

    Tables, dotted tables, ARRAYS OF TABLES, strings, arrays, bools, ints; an
    unhandled shape raises rather than being dropped. Arrays of tables are
    not optional here and an earlier version of this writer refused them:
    `[[write.scope]]` (per-program write scope) and `[[run.guards]]`
    (place-scoped guard override) are both real config, both documented in
    `vouch.example.toml`, and refusing them made the sentinel abort on a
    config vouch itself accepts.

    Scalars are emitted before any header at every level, because a key
    written after a `[table]` or `[[array]]` header would land inside it.

    NEVER textually append to a config file instead of this: a key appended
    at EOF lands inside whatever table is last and the loader refuses the
    whole file.
    """
    if out is None:
        out = []
    for k, v in data.items():
        if not isinstance(v, dict) and not _is_table_array(v):
            out.append("%s = %s" % (k, _toml_value(v)))
    for k, v in data.items():
        name = (prefix + "." if prefix else "") + k
        if isinstance(v, dict):
            out.append("")
            out.append("[" + name + "]")
            emit_toml(v, name, out)
        elif _is_table_array(v):
            for element in v:
                out.append("")
                out.append("[[" + name + "]]")
                emit_toml(element, name, out)
    return out


# ------------------------------------------------------------------ sentinel


def run_call(binary, payload, env, timeout=60):
    """One hook call. Returns (returncode, stdout bytes, stderr bytes)."""
    try:
        r = subprocess.run(
            [binary, "--hook"],
            input=json.dumps(payload).encode("utf-8"),
            capture_output=True,
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return (None, b"", b"")
    return (r.returncode, r.stdout, r.stderr)


def run_batch(binary, payloads, env, timeout=60):
    """Replay many calls in one process; return (rc, status rows).

    The batch protocol emits counts-only JSONL: local index, processed/refused,
    and whether the native hook path would have emitted output. It never echoes
    a payload or decision reason into this process's stdout.
    """
    body = b"\n".join(json.dumps(p).encode("utf-8") for p in payloads) + b"\n"
    try:
        r = subprocess.run(
            [binary, "--hook-batch"],
            input=body,
            capture_output=True,
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return (None, None)
    if r.returncode != 0:
        return (r.returncode, None)
    try:
        statuses = [json.loads(line) for line in r.stdout.splitlines() if line.strip()]
    except Exception:
        return (r.returncode, None)
    if len(statuses) != len(payloads):
        return (r.returncode, None)
    for index, status in enumerate(statuses):
        if (
            status.get("index") != index
            or status.get("status") not in ("processed", "refused")
            or not isinstance(status.get("emitted"), bool)
        ):
            return (r.returncode, None)
    return (r.returncode, statuses)


def read_journal(state_dir):
    p = os.path.join(state_dir, "journal.jsonl")
    rows = []
    if not os.path.exists(p):
        return rows
    with open(p, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def candidate_env(args, config_path, state_dir):
    env = dict(os.environ)
    env["VOUCH_CONFIG"] = config_path
    env["VOUCH_KNOWLEDGE"] = args.knowledge
    env["VOUCH_MY_KNOWLEDGE"] = args.my_knowledge
    env["VOUCH_STATE_DIR"] = state_dir
    return env


def sentinel(args, scratch):
    """Prove the env overrides took and the config does not stand down.

    BEFORE any number is reported. Parses the candidate config with tomllib,
    adds a marker glob to `write.deny_paths` (creating `[write]` if absent),
    re-emits it into a scratch COPY used for this call only, and feeds one
    synthetic call writing under the marker directory. The journal row must
    say deny AND mode == "live".

    Two-sided on purpose: the same call is first run against the ORIGINAL
    candidate config as a control. If that already denies, the marker
    location is walled by something else and the marked run would pass
    without proving anything.

    A miss means the env overrides did not take, or the config stands down
    at the stamped mode (a stood-down replay reports empty output for every
    ask and deny, so every number after it would be wrong). Abort loudly,
    report nothing. The BULK replay uses the ORIGINAL candidate files.
    """
    marker = os.path.join(scratch, "sentinel-" + uuid.uuid4().hex).replace(os.sep, "/")
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "wwf-sentinel",
        "tool_use_id": "wwf-sentinel",
        "cwd": scratch.replace(os.sep, "/"),
        "permission_mode": STAMPED_MODE,
        "tool_name": "Write",
        "tool_input": {"file_path": marker + "/x.txt", "content": "x"},
    }

    # Control: the unmodified candidate config must NOT already deny here.
    ctl_dir = os.path.join(scratch, "state", "sentinel-control")
    os.makedirs(ctl_dir, exist_ok=True)
    run_call(args.binary, payload, candidate_env(args, args.config, ctl_dir))
    ctl = [r for r in read_journal(ctl_dir) if r.get("session") == "wwf-sentinel"]
    if ctl and ctl[0].get("verdict") == "deny":
        sys.exit(
            "sentinel control failed: the candidate config already denies writes under "
            "the marker directory, so the marked run would prove nothing. Point "
            "--scratch somewhere the candidate config does not already wall off."
        )

    try:
        cfg = tomllib.load(open(args.config, "rb"))
    except Exception as e:
        sys.exit("sentinel failed: the candidate config did not parse (%s)" % e)

    # The stand-down check, read from the same two keys src/config.rs reads
    # ([shadow].stand_down and [shadow].modes). It is done statically as well
    # as empirically because the deny probe below cannot see one of the two
    # armed states: under stand_down = "keep-deny" a deny STAYS live while
    # every ordinary ask is suppressed, so a deny-only sentinel would pass on
    # a config that stands down at the stamped mode.
    sh = cfg.get("shadow") or {}
    toggle = sh.get("stand_down")
    modes = sh.get("modes") or []
    if toggle and toggle != "off" and STAMPED_MODE in modes:
        sys.exit(
            "sentinel failed: the candidate config STANDS DOWN at permission_mode "
            "%r ([shadow].stand_down = %r, and %r is in [shadow].modes), which is "
            "the mode this replay stamps. Emissions would be suppressed and the "
            "rows would be labelled stood-down rather than ask or deny. Remove %r "
            "from [shadow].modes in the candidate config, or measure a config "
            "that does not stand down there. Nothing was measured."
            % (STAMPED_MODE, toggle, STAMPED_MODE, STAMPED_MODE)
        )

    cfg.setdefault("write", {})
    cfg["write"]["deny_paths"] = list(cfg["write"].get("deny_paths", [])) + [
        marker + "/**"
    ]
    try:
        body = "\n".join(emit_toml(cfg)) + "\n"
    except TypeError as e:
        sys.exit(
            "sentinel failed: the candidate config carries a value shape this "
            "writer does not handle (%s). Nothing was measured." % e
        )
    sent_cfg = os.path.join(scratch, "sentinel-config.toml")
    with open(sent_cfg, "w", encoding="utf-8") as fh:
        fh.write(body)

    sd = os.path.join(scratch, "state", "sentinel")
    os.makedirs(sd, exist_ok=True)
    rc, _out, err = run_call(args.binary, payload, candidate_env(args, sent_cfg, sd))
    rows = [r for r in read_journal(sd) if r.get("session") == "wwf-sentinel"]
    if not rows:
        sys.exit(
            "sentinel failed: the call wrote NO journal row (binary exit %r). Either "
            "the binary refused the input or VOUCH_STATE_DIR did not take. Nothing "
            "was measured.%s" % (rc, "" if not err else " Binary wrote to stderr.")
        )
    row = rows[0]
    if row.get("verdict") != "deny":
        sys.exit(
            "sentinel failed: expected deny under the marker directory, got %r. "
            "Two causes reach this line and they are not the same: the "
            "VOUCH_CONFIG override did not take (a cargo-invoked run replaces the "
            "candidate files with the repository's own), or the candidate config "
            "was REFUSED at load, in which case nothing is allowed and every call "
            "asks. Run `vouch explain 'ls -la'` with the same three environment "
            "variables and read the banner to tell them apart. Nothing was "
            "measured." % row.get("verdict")
        )
    if row.get("mode") != "live":
        sys.exit(
            "sentinel failed: the row's mode is %r, not \"live\" - the candidate "
            "config STANDS DOWN at permission_mode \"default\", which is the mode "
            "this replay stamps. Every ask and deny would report as empty output. "
            "Fix [shadow].modes in the candidate config, or measure a config that "
            "does not stand down at default. Nothing was measured." % row.get("mode")
        )
    print("sentinel: deny + live - the env overrides took and the config is not "
          "standing down at the stamped permission mode", flush=True)
    return True


# -------------------------------------------------------------------- replay


def _run_chunk(args, chunk, state_dir, fallback_cwd, timeout=60):
    """Replay one partition in one process into its OWN state dir.

    Each worker gets one long-lived batch process and its own VOUCH_STATE_DIR
    because concurrent appends to one journal interleave. Process/config load
    overhead is therefore paid once per partition, not once per row.

    Returns the stdout tally AND the indices of calls where the BINARY
    failed - timed out, or exited nonzero. Those indices must not be dropped:
    a crashed process writes nothing and emits nothing, which looks exactly
    like a deliberate abstain and exactly like a refused input. A probe that
    cannot tell a crash from an abstain has produced findings from a dead
    binary in this repository before, so the two get separate labels.
    """
    os.makedirs(state_dir, exist_ok=True)
    env = candidate_env(args, args.config, state_dir)
    tally = {"empty": 0, "nonempty": 0, "timeout": 0, "nonzero_exit": 0}
    failures = {}
    payloads = [hook_json(row, idx, fallback_cwd) for idx, row in chunk]
    rc, statuses = run_batch(args.binary, payloads, env, timeout=timeout)
    if rc is None:
        tally["timeout"] = len(chunk)
        return tally, {idx: "binary-timeout" for idx, _row in chunk}
    if rc != 0 or statuses is None:
        tally["nonzero_exit"] = len(chunk)
        return tally, {idx: "binary-error" for idx, _row in chunk}
    for (idx, _row), status in zip(chunk, statuses):
        if status["emitted"]:
            tally["nonempty"] += 1
        else:
            tally["empty"] += 1
    return tally, failures


def replay(rows, args, scratch, fallback_cwd):
    """Calibrate, fan out persistent workers, then join this run's rows.

    Calibration is MEASURED, never a constant: the first rows are replayed
    in one batch and timed, and the printed estimate comes from that measured
    batch transport divided across the workers. Those rows are real replays -
    every row is replayed exactly once.

    The join is by `session` (journal) against `session_id` (input):
      - MANY rows per session are possible, one per snippet: collapsed to one
        decision per session for classification, with the snippet rows
        counted as their own labelled figure
      - NO row for a session, and the binary ran and exited 0: it refused
        that input - its own labelled class
      - NO row for a session because the binary TIMED OUT or exited nonzero:
        a different labelled class again, never folded into the refusals. A
        dead binary emits nothing and journals nothing, which is
        indistinguishable from a deliberate abstain and from a refusal unless
        the process result is kept.
    stdout is only a cross-check - abstain, stood-down, refused and failed
    are identical there (all empty).
    """
    indexed = list(enumerate(rows))
    workers = max(1, args.workers)
    state_root = os.path.join(scratch, "state")

    cal_n = min(50, len(indexed))
    # perf_counter, not monotonic: monotonic's resolution here is 15.6 ms
    # (measured with time.get_clock_info), which is the same order as one call
    # - a short calibration then prints 0.0 or 15.6 ms/call, neither of which
    # is a measurement. perf_counter is sub-microsecond on the same platform.
    t0 = time.perf_counter()
    tallies = []
    failures = {}
    if cal_n:
        t, f = _run_chunk(
            args, indexed[:cal_n], os.path.join(state_root, "w-cal"), fallback_cwd
        )
        tallies.append(t)
        failures.update(f)
    elapsed = time.perf_counter() - t0
    ms = (elapsed / cal_n * 1000.0) if cal_n else 0.0
    rest = indexed[cal_n:]
    est_s = (len(rest) * ms / 1000.0 / workers) if rest else 0.0
    est = "~%.1f min" % (est_s / 60.0) if est_s >= 60 else "~%d s" % round(est_s)
    print(
        "%d rows at %.1f ms/call across %d workers: expect %s"
        % (len(indexed), ms, workers, est),
        flush=True,
    )

    if rest:
        chunks = [rest[i::workers] for i in range(workers)]
        chunks = [c for c in chunks if c]
        # A stuck batch must not hang forever, while normal large corpora need
        # more than the sentinel's fixed minute. Ten measured runtimes plus a
        # minute floor leaves generous headroom without restoring per-row waits.
        batch_timeout = max(
            60,
            int(max(len(chunk) for chunk in chunks) * ms / 1000.0 * 10) + 1,
        )
        sys.stderr.write("replaying %d rows...\n" % len(rest))
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(chunks)) as ex:
            futs = [
                ex.submit(
                    _run_chunk,
                    args,
                    c,
                    os.path.join(state_root, "w-%d" % i),
                    fallback_cwd,
                    batch_timeout,
                )
                for i, c in enumerate(chunks)
            ]
            for fut in futs:
                t, f = fut.result()
                tallies.append(t)
                failures.update(f)

    stdout_tally = {"empty": 0, "nonempty": 0, "timeout": 0, "nonzero_exit": 0}
    for t in tallies:
        for k, v in t.items():
            stdout_tally[k] += v

    # Read each worker journal ONCE and group by `session`.
    by_session = {}
    unexpected = 0
    journal_rows = 0
    for name in sorted(os.listdir(state_root)) if os.path.isdir(state_root) else []:
        if not name.startswith("w-"):
            continue
        for r in read_journal(os.path.join(state_root, name)):
            journal_rows += 1
            s = r.get("session") or ""
            if not s.startswith("wwf-"):
                unexpected += 1
                continue
            by_session.setdefault(s, []).append(r)

    joined = []
    refused = []
    failed = []
    for idx, row in indexed:
        s = "wwf-%d" % idx
        got = by_session.get(s)
        if got:
            # The call produced a decision. A nonzero exit alongside it is
            # still counted in the stdout cross-check, but the journal row is
            # the answer.
            joined.append((row, got))
        elif idx in failures:
            failed.append((row, failures[idx]))
        else:
            refused.append(row)

    stats = {
        "rows_replayed": len(indexed),
        "rows_joined": len(joined),
        "rows_refused": len(refused),
        "rows_failed": len(failed),
        "journal_rows": journal_rows,
        "unexpected_sessions": unexpected,
        "snippet_rows": sum(len(g) for _r, g in joined if len(g) > 1),
        "multi_row_calls": sum(1 for _r, g in joined if len(g) > 1),
        "split_decision_calls": sum(
            1 for _r, g in joined if len({x.get("verdict") for x in g}) > 1
        ),
        "stdout": stdout_tally,
    }
    return joined, refused, failed, stats


# -------------------------------------------------------------------- report


def _first_line_class(reason):
    """The reason's first line, admitted only in the shape the engine writes.

    Every ask reason the engine composes starts "vouch stopped on: <name>"
    and the name is a construct, guard or setting - never command text. Any
    other shape is bucketed rather than printed, so no first line can carry a
    command into the report by surprise.
    """
    line = (reason or "").split("\n")[0].strip()
    prefix = "vouch stopped on: "
    if not line.startswith(prefix):
        return "<non-standard first line>"
    name = line[len(prefix):].strip()
    return name if name else "<empty>"


def _two_figure_table(title, pairs, note=None):
    """pairs: (label, occurrences, distinct-shape count), already ordered."""
    print("")
    print(title)
    if note:
        print("  (%s)" % note)
    if not pairs:
        print("  (none)")
        return
    width = max(len(str(p[0])) for p in pairs)
    print("  %-*s  %10s  %10s" % (width, "", "occurrences", "distinct"))
    for label, occ, dist in pairs:
        print("  %-*s  %10d  %10d" % (width, label, occ, dist))


def _tally(items):
    """items: (label, shape). Returns ordered (label, occurrences, distinct)."""
    occ = {}
    shapes = {}
    for label, shape in items:
        occ[label] = occ.get(label, 0) + 1
        shapes.setdefault(label, set()).add(shape)
    out = [(k, occ[k], len(shapes[k])) for k in occ]
    out.sort(key=lambda t: (-t[1], t[0]))
    return out


def classify(journal_rows):
    """One class per call, from the journal - never from stdout.

    A stood-down row carries verdict ask/deny with mode "stood-down"; the
    mode word decides the class, because the emission was suppressed. All
    rows of one call carry the same decision (they are written from one
    `Decision`), so the first row answers for the call.
    """
    r = journal_rows[0]
    mode = r.get("mode") or ""
    if mode == "stood-down":
        return "stood-down", r
    if mode == "shadow":
        return "shadow", r
    return (r.get("verdict") or "<no verdict>"), r


def merge_journals(scratch):
    """Fold the per-worker journals into ONE state dir, for `vouch doctor`.

    doctor reads a single `journal.jsonl` under its state dir; the replay
    writes one per worker (concurrent appends to one file interleave). This
    is the join between the two, and it is done only on --keep-state, because
    what it produces is harvested command text that outlives the run.
    """
    state_root = os.path.join(scratch, "state")
    dest = os.path.join(state_root, "merged")
    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, "journal.jsonl"), "w", encoding="utf-8") as out:
        for name in sorted(os.listdir(state_root)):
            if not name.startswith("w-"):
                continue
            src = os.path.join(state_root, name, "journal.jsonl")
            if not os.path.exists(src):
                continue
            with open(src, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.strip():
                        out.write(line if line.endswith("\n") else line + "\n")
    return dest.replace(os.sep, "/")


def report(joined, refused, failed, counters, stats, scratch, capped, kept, source):
    print("")
    print("harvest" if not source else "harvest (from the snapshotted row set)")
    for label, key in (
        ("transcript files                ", "files"),
        ("records parsed                  ", "records"),
        ("tool-use blocks found           ", "blocks_found"),
        ("duplicate ids removed           ", "duplicates"),
        ("rows (deduped)                  ", "rows"),
        ("of those, previously decided    ", "previously_decided"),
        ("subagent sidechain rows         ", "sidechain_rows"),
        ("main-thread rows                ", "mainthread_rows"),
        ("rows that used the fallback cwd ", "rows_missing_cwd"),
    ):
        if key in counters:
            print("  %s %8d" % (label, counters[key]))
    if capped is not None:
        print("  replayed after --cap             %8d" % capped)

    print("")
    print("reconciliation")
    print("  rows replayed                    %8d" % stats["rows_replayed"])
    print("  rows joined to journal rows      %8d" % stats["rows_joined"])
    print("  rows the binary refused          %8d" % stats["rows_refused"])
    print("  rows the binary failed on        %8d" % stats["rows_failed"])
    print("  journal rows written             %8d" % stats["journal_rows"])
    print("  calls that wrote >1 row          %8d" % stats["multi_row_calls"])
    print("  rows from those calls            %8d" % stats["snippet_rows"])
    print("  stdout non-empty (cross-check)   %8d" % stats["stdout"]["nonempty"])
    print("  stdout empty (cross-check)       %8d" % stats["stdout"]["empty"])
    if stats["stdout"]["timeout"]:
        print("  calls that timed out             %8d" % stats["stdout"]["timeout"])
    if stats["stdout"]["nonzero_exit"]:
        print("  calls that exited nonzero        %8d" % stats["stdout"]["nonzero_exit"])
    if stats["split_decision_calls"]:
        print(
            "  calls whose rows disagreed       %8d" % stats["split_decision_calls"]
        )

    assert stats["rows_replayed"] == (
        stats["rows_joined"] + stats["rows_refused"] + stats["rows_failed"]
    ), (
        "replayed (%d) != joined (%d) + refused (%d) + failed (%d)"
        % (
            stats["rows_replayed"],
            stats["rows_joined"],
            stats["rows_refused"],
            stats["rows_failed"],
        )
    )
    assert stats["unexpected_sessions"] == 0, (
        "%d journal rows carry a session this run did not stamp - the state dir "
        "was not clean" % stats["unexpected_sessions"]
    )

    classes = []
    asks = []
    heads = []
    for row, jrows in joined:
        cls, jr = classify(jrows)
        shape = call_shape(row)
        classes.append((cls, shape))
        heads.append((head_name(row), shape))
        if cls in ("ask", "stood-down"):
            asks.append((_first_line_class(jr.get("reason")), shape))
    for row in refused:
        shape = call_shape(row)
        classes.append(("input-refused", shape))
        heads.append((head_name(row), shape))
    # `binary-timeout` and `binary-error` are NOT decisions and never merge
    # into the refusals: they are calls where the process failed, and a
    # failed process is silent in exactly the way an abstain is.
    for row, kind in failed:
        shape = call_shape(row)
        classes.append((kind, shape))
        heads.append((head_name(row), shape))

    _two_figure_table(
        "decisions by class",
        _tally(classes),
        "input-refused is a call the binary would not parse; binary-timeout "
        "and binary-error are calls where the PROCESS failed, not decisions",
    )
    _two_figure_table(
        "ask reasons by first-line class",
        _tally(asks),
        "asks and stood-down asks; a stood-down row is a suppressed emission, "
        "not a human decision",
    )
    _two_figure_table(
        "head-program names",
        _tally(heads)[:40],
        "top 40; first token of the recorded command, path-spelled heads reduced "
        "to their base name - an approximation, not vouch's own parse",
    )

    print("")
    print(
        "these are default-mode numbers; a [shadow] section changes what the live "
        "gate emits in other modes."
    )

    state_root = os.path.join(scratch, "state").replace(os.sep, "/")
    if kept:
        print(
            "kept the replay journal, merged into %s - point VOUCH_STATE_DIR "
            "there for `vouch doctor`, then DELETE it: it is one row per "
            "replayed call, and a row carries the command text" % kept
        )
    else:
        print(
            "deleted the scratch state dirs under %s (they held one journal row "
            "per replayed call, and a journal row carries the command text)"
            % state_root
        )


# ---------------------------------------------------------------------- main


def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Counts-only decision replay of this machine's recorded "
        "session history against a candidate vouch config."
    )
    p.add_argument("--binary", required=True, help="ABSOLUTE path to vouch (never cargo)")
    p.add_argument("--config", required=True)
    p.add_argument("--knowledge", required=True)
    p.add_argument("--my-knowledge", required=True, dest="my_knowledge")
    p.add_argument(
        "--roots",
        action="append",
        default=None,
        help="transcript root; repeatable (default: ~/.claude/projects)",
    )
    p.add_argument("--cap", type=int, default=None)
    p.add_argument("--workers", type=int, default=os.cpu_count() or 4)
    p.add_argument(
        "--samples-dest",
        default=None,
        dest="samples_dest",
        help="write the snapshotted row set here, so a later run can replay "
        "the SAME rows with --samples-source; must be absolute and outside "
        "every git worktree, and the caller deletes it",
    )
    p.add_argument(
        "--samples-source",
        default=None,
        dest="samples_source",
        help="replay the row set in this file (written by --samples-dest) "
        "instead of harvesting. What phase 5 uses: the transcript store grows "
        "while it is being measured, so a re-harvest would fold new history "
        "into the before/after delta",
    )
    p.add_argument(
        "--scratch",
        default=None,
        help="scratch root for the throwaway state dirs (default: the OS temp "
        "directory's vouch-setup/ folder). Pass the session scratchpad when "
        "one exists.",
    )
    p.add_argument(
        "--keep-state",
        action="store_true",
        dest="keep_state",
        help="keep the replay journal, merged into one state directory, so "
        "`vouch doctor` can be pointed at it with VOUCH_STATE_DIR. The merged "
        "journal is harvested command text - delete it when the phase ends.",
    )
    return p.parse_args(argv)


def main(argv):
    args = parse_args(argv)

    if args.samples_dest:
        refuse_unsafe_dest(args.samples_dest)
    if args.samples_source:
        refuse_unsafe_dest(args.samples_source, "--samples-source")
        if not os.path.exists(args.samples_source):
            sys.exit("--samples-source does not exist: %s" % args.samples_source)
    if args.samples_dest and args.samples_source:
        sys.exit(
            "--samples-dest and --samples-source together would rewrite the row "
            "set being replayed; pass one or the other"
        )

    if not os.path.isabs(args.binary):
        sys.exit("--binary must be an absolute path - never invoke vouch through cargo")
    for label, path in (
        ("--binary", args.binary),
        ("--config", args.config),
        ("--knowledge", args.knowledge),
        ("--my-knowledge", args.my_knowledge),
    ):
        if not os.path.exists(path):
            sys.exit("%s does not exist: %s" % (label, path))

    scratch = args.scratch or os.path.join(tempfile.gettempdir(), "vouch-setup")
    os.makedirs(scratch, exist_ok=True)
    state_root = os.path.join(scratch, "state")
    shutil.rmtree(state_root, ignore_errors=True)

    # Every exit from here on goes through the cleanup: a replay journal is
    # harvested command text, and an abort is exactly when it would otherwise
    # be left behind.
    try:
        return _run(args, scratch)
    finally:
        if args.keep_state and os.path.isdir(os.path.join(state_root, "merged")):
            # Kept deliberately for `vouch doctor`; the per-worker copies are
            # redundant once merged, so only the merged one survives.
            for name in os.listdir(state_root):
                if name != "merged":
                    shutil.rmtree(os.path.join(state_root, name), ignore_errors=True)
        else:
            shutil.rmtree(state_root, ignore_errors=True)
        sent = os.path.join(scratch, "sentinel-config.toml")
        if os.path.exists(sent):
            os.remove(sent)


def _run(args, scratch):
    # Before any number is reported.
    sentinel(args, scratch)

    if args.samples_source:
        # Phase 5: replay the row set phase 3 snapshotted, never a re-harvest.
        rows, counters, capped = read_samples(args.samples_source)
        if not rows:
            print("")
            print("--samples-source holds no rows: %s" % args.samples_source)
            return 0
    else:
        roots = args.roots or [
            os.path.join(os.path.expanduser("~"), ".claude", "projects")
        ]
        present = [r for r in roots if os.path.isdir(r)]
        if not present:
            print("")
            print("no session logs found under: %s" % ", ".join(roots))
            print(
                "nothing to replay. Shadow mode ([shadow], or `vouch install "
                "--shadow` beside a still-live older gate) accumulates evidence "
                "while running."
            )
            return 0

        rows, counters = harvest(present)
        if not rows:
            print("")
            print("session logs are present (%d files) but hold no tool-use blocks."
                  % counters["files"])
            return 0
        capped = None

    # The cap truncates AFTER the harvest counters are computed, so "found" is
    # never understated by it.
    if args.cap is not None and args.cap < len(rows):
        rows = rows[: args.cap]
        capped = len(rows)

    if args.samples_dest:
        os.makedirs(os.path.dirname(args.samples_dest) or ".", exist_ok=True)
        write_samples(args.samples_dest, rows, counters, capped)
        sys.stderr.write(
            "wrote %d extracted calls to %s - this file is harvested command "
            "text; it stays on this machine and out of every repository, and "
            "it is yours to delete once phase 5 has replayed it\n"
            % (len(rows), args.samples_dest)
        )

    fallback_cwd = os.getcwd()
    joined, refused, failed, stats = replay(rows, args, scratch, fallback_cwd)
    kept = merge_journals(scratch) if args.keep_state else None
    report(
        joined,
        refused,
        failed,
        counters,
        stats,
        scratch,
        capped,
        kept,
        args.samples_source,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
