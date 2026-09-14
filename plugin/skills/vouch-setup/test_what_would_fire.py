"""Tests for multi-host transcript harvesting in what_would_fire.py.

Verifies detection, extraction, and deduplication across Claude, Codex,
and Antigravity transcript formats using synthetic test fixtures.
"""

import json
import os
import sys
import tempfile
import tomllib
import unittest

# Add script directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import what_would_fire as wwf


class TestCodexParsing(unittest.TestCase):
    def test_parse_codex_exec_simple(self):
        s = 'const r = await tools.exec_command({cmd:"git status",workdir:"C:/Users/dev/repo"});text(r.output)'
        cmd, cwd = wwf.parse_codex_exec(s)
        self.assertEqual(cmd, "git status")
        self.assertEqual(cwd, "C:/Users/dev/repo")

    def test_parse_codex_exec_quoted_keys(self):
        s = 'tools.exec_command({"cmd": "cargo test --release", "workdir": "C:/Users/dev/project"})'
        cmd, cwd = wwf.parse_codex_exec(s)
        self.assertEqual(cmd, "cargo test --release")
        self.assertEqual(cwd, "C:/Users/dev/project")

    def test_parse_codex_exec_multiline_and_escapes(self):
        s = r'tools.exec_command({cmd:"echo \"hello world\"\nls -la",workdir:"C:/Users/dev/app"})'
        cmd, cwd = wwf.parse_codex_exec(s)
        self.assertEqual(cmd, 'echo "hello world"\nls -la')
        self.assertEqual(cwd, "C:/Users/dev/app")

    def test_parse_codex_exec_no_workdir(self):
        s = 'tools.exec_command({cmd:"git diff"})'
        cmd, cwd = wwf.parse_codex_exec(s)
        self.assertEqual(cmd, "git diff")
        self.assertIsNone(cwd)

    def test_parse_codex_exec_malformed(self):
        s = 'tools.not_exec({other:"data"})'
        cmd, cwd = wwf.parse_codex_exec(s)
        self.assertIsNone(cmd)
        self.assertIsNone(cwd)


class TestHostDetection(unittest.TestCase):
    def test_detect_by_path(self):
        self.assertEqual(wwf.detect_file_host("/tmp/test/.claude/projects/sess.jsonl", []), "claude")
        self.assertEqual(wwf.detect_file_host("/tmp/test/codex/sessions/rollout-1.jsonl", []), "codex")
        self.assertEqual(wwf.detect_file_host("/tmp/test/antigravity-cli/brain/uuid/transcript.jsonl", []), "agy")

    def test_detect_by_content(self):
        claude_line = '{"message": {"content": [{"type": "tool_use", "name": "Bash"}]}}'
        codex_line = '{"payload": {"type": "custom_tool_call", "name": "exec"}}'
        agy_line = '{"source": "MODEL", "tool_calls": [{"name": "run_command"}]}'

        self.assertEqual(wwf.detect_file_host("/tmp/unknown/file1.jsonl", [claude_line]), "claude")
        self.assertEqual(wwf.detect_file_host("/tmp/unknown/file2.jsonl", [codex_line]), "codex")
        self.assertEqual(wwf.detect_file_host("/tmp/unknown/file3.jsonl", [agy_line]), "agy")


class TestMultiHostHarvest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.claude_dir = os.path.join(self.tmpdir.name, ".claude", "projects")
        self.codex_dir = os.path.join(self.tmpdir.name, ".codex", "sessions")
        self.agy_dir = os.path.join(self.tmpdir.name, ".gemini", "antigravity-cli", "brain", "session-1", ".system_generated", "logs")
        os.makedirs(self.claude_dir, exist_ok=True)
        os.makedirs(self.codex_dir, exist_ok=True)
        os.makedirs(self.agy_dir, exist_ok=True)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_harvest_all_hosts(self):
        # 1. Claude session file
        claude_file = os.path.join(self.claude_dir, "claude-session.jsonl")
        claude_records = [
            {
                "message": {
                    "content": [
                        {"type": "tool_use", "id": "call-claude-1", "name": "Bash", "input": {"command": "git status"}}
                    ]
                },
                "attachment": {
                    "hookName": "PreToolUse",
                    "toolUseID": "call-claude-1",
                    "stdout": json.dumps({"hookSpecificOutput": {"permissionDecision": "allow"}})
                }
            },
            # Duplicate tool call ID should be skipped
            {
                "message": {
                    "content": [
                        {"type": "tool_use", "id": "call-claude-1", "name": "Bash", "input": {"command": "git status"}}
                    ]
                }
            }
        ]
        with open(claude_file, "w", encoding="utf-8") as f:
            for r in claude_records:
                f.write(json.dumps(r) + "\n")

        # 2. Codex session file
        codex_file = os.path.join(self.codex_dir, "rollout-codex.jsonl")
        codex_records = [
            {
                "payload": {
                    "type": "custom_tool_call",
                    "name": "exec",
                    "id": "call-codex-1",
                    "input": 'tools.exec_command({cmd:"cargo check",workdir:"C:/Users/dev/workspace"});'
                }
            },
            {
                "payload": {
                    "type": "function_call",
                    "name": "apply_patch",
                    "id": "call-codex-2",
                    "arguments": json.dumps({"patch": "*** file.txt\n--- file.txt\n+hello"})
                }
            }
        ]
        with open(codex_file, "w", encoding="utf-8") as f:
            for r in codex_records:
                f.write(json.dumps(r) + "\n")

        # 3. Antigravity transcript file
        agy_file = os.path.join(self.agy_dir, "transcript.jsonl")
        agy_records = [
            {
                "step_index": 0,
                "source": "MODEL",
                "workspacePaths": ["C:/Users/dev/workspace"],
                "tool_calls": [
                    {
                        "id": "call-agy-1",
                        "name": "run_command",
                        "args": {"CommandLine": "cargo test", "Cwd": "C:/Users/dev/workspace"}
                    }
                ]
            },
            {
                "step_index": 1,
                "source": "SUBAGENT",
                "workspacePaths": ["C:/Users/dev/workspace"],
                "tool_calls": [
                    {
                        "id": "call-agy-2",
                        "name": "write_to_file",
                        "args": {"TargetFile": "C:/Users/dev/workspace/test.txt", "CodeContent": "sample"}
                    }
                ]
            }
        ]
        with open(agy_file, "w", encoding="utf-8") as f:
            for r in agy_records:
                f.write(json.dumps(r) + "\n")

        # Harvest from all three directories
        rows, counters = wwf.harvest([self.claude_dir, self.codex_dir, self.agy_dir])

        self.assertEqual(counters["files_claude"], 1)
        self.assertEqual(counters["files_codex"], 1)
        self.assertEqual(counters["files_agy"], 1)

        self.assertEqual(counters["rows_claude"], 1)
        self.assertEqual(counters["rows_codex"], 2)
        self.assertEqual(counters["rows_agy"], 2)

        self.assertEqual(counters["duplicates"], 1)
        self.assertEqual(len(rows), 5)

        # Check Claude row
        r_claude = [r for r in rows if r.tool == "Bash" and r.tool_use_id == "call-claude-1"][0]
        self.assertEqual(r_claude.input.get("command"), "git status")
        self.assertTrue(r_claude.decided)
        self.assertFalse(r_claude.sidechain)

        # Check Codex rows
        r_codex_exec = [r for r in rows if r.tool_use_id == "call-codex-1"][0]
        self.assertEqual(r_codex_exec.tool, "Bash")
        self.assertEqual(r_codex_exec.input.get("command"), "cargo check")
        self.assertEqual(r_codex_exec.cwd, "C:/Users/dev/workspace")

        r_codex_patch = [r for r in rows if r.tool_use_id == "call-codex-2"][0]
        self.assertEqual(r_codex_patch.tool, "apply_patch")

        # Check Antigravity rows
        r_agy_cmd = [r for r in rows if r.tool_use_id == "call-agy-1"][0]
        self.assertEqual(r_agy_cmd.tool, "run_command")
        self.assertEqual(r_agy_cmd.input.get("CommandLine"), "cargo test")
        self.assertFalse(r_agy_cmd.sidechain)

        r_agy_subagent = [r for r in rows if r.tool_use_id == "call-agy-2"][0]
        self.assertEqual(r_agy_subagent.tool, "write_to_file")
        self.assertTrue(r_agy_subagent.sidechain)


class TestSynthesisAndVerification(unittest.TestCase):
    def test_extract_head_and_subcommand(self):
        cases = [
            ("git status", "git", "status"),
            ("cargo --color=never check", "cargo", "check"),
            ("VAR=1 python3 script.py", "python3", None),
            ("/usr/local/bin/kubectl get pods", "kubectl", "get"),
            (r"C:\tools\git.exe branch -v", "git.exe", "branch"),
            ("ls -la", "ls", None),
            ("   ", None, None),
        ]
        for cmd, want_head, want_sub in cases:
            h, s = wwf.extract_head_and_subcommand(cmd)
            self.assertEqual(h, want_head, "head mismatch for `%s`" % cmd)
            self.assertEqual(s, want_sub, "subcommand mismatch for `%s`" % cmd)

    def test_synthesize_baseline_knowledge(self):
        synthetic_rows = [
            wwf.Row("1", "Bash", {"command": "git status"}, "C:/Users/dev", False, True),
            wwf.Row("2", "Bash", {"command": "git diff"}, "C:/Users/dev", False, True),
            wwf.Row("3", "Bash", {"command": "git reset --hard"}, "C:/Users/dev", False, True),
            wwf.Row("4", "run_command", {"CommandLine": "cargo test"}, "C:/Users/dev", False, True),
            wwf.Row("5", "run_command", {"CommandLine": "cargo check"}, "C:/Users/dev", False, True),
            wwf.Row("6", "Bash", {"command": "rm -rf /tmp/scratch"}, "C:/Users/dev", False, True),
            wwf.Row("7", "Bash", {"command": "kill -9 1234"}, "C:/Users/dev", False, True),
            wwf.Row("8", "run_command", {"CommandLine": "jq . data.json"}, "C:/Users/dev", False, True),
        ]
        toml_text, summary = wwf.synthesize_baseline_knowledge(synthetic_rows)
        self.assertIn("git", summary["programs"])
        self.assertIn("cargo", summary["programs"])
        self.assertIn("jq", summary["programs"])
        # Dangerous programs must be filtered
        self.assertNotIn("rm", summary["programs"])
        self.assertNotIn("kill", summary["programs"])

        parsed = tomllib.loads(toml_text)
        self.assertIn("program", parsed)
        programs_by_name = {p["name"]: p for p in parsed["program"]}

        git_entry = programs_by_name["git"]
        self.assertIn("status", git_entry["subcommands"])
        self.assertIn("diff", git_entry["subcommands"])
        # Destructive verb 'reset' must be filtered
        self.assertNotIn("reset", git_entry["subcommands"])

        cargo_entry = programs_by_name["cargo"]
        self.assertIn("check", cargo_entry["subcommands"])
        self.assertIn("test", cargo_entry["subcommands"])

        # jq has no subcommands
        jq_entry = programs_by_name["jq"]
        self.assertNotIn("subcommands", jq_entry)

        # Privacy assertion: zero PII / no live paths in generated overlay
        self.assertNotIn("C:/Users/dev", toml_text)
        self.assertNotIn("/tmp/scratch", toml_text)

    def test_verify_candidate_rule(self):
        synthetic_rows = [
            wwf.Row("1", "Bash", {"command": "cargo test"}, "C:/Users/dev", False, True),
            wwf.Row("2", "Bash", {"command": "cargo check"}, "C:/Users/dev", False, True),
            wwf.Row("3", "Bash", {"command": "cargo build"}, "C:/Users/dev", False, True),
            wwf.Row("4", "Bash", {"command": "git status"}, "C:/Users/dev", False, True),
        ]

        # Valid candidate with matching subcommands
        res1 = wwf.verify_candidate_rule({"name": "cargo", "subcommands": ["test", "check"]}, synthetic_rows)
        self.assertTrue(res1["valid"])
        self.assertTrue(res1["intent_verified"])
        self.assertEqual(res1["matched_rows"], 2)
        self.assertEqual(res1["matched_subcommands"], ["check", "test"])
        self.assertEqual(res1["unmatched_rows"], 1)  # cargo build
        self.assertFalse(res1["overbroad"])

        # Overbroad candidate: git with no subcommands
        res2 = wwf.verify_candidate_rule({"name": "git"}, synthetic_rows)
        self.assertTrue(res2["valid"])
        self.assertFalse(res2["intent_verified"])
        self.assertTrue(res2["overbroad"])
        self.assertEqual(res2["matched_rows"], 1)

        # Dangerous candidate: rm
        res3 = wwf.verify_candidate_rule({"name": "rm"}, synthetic_rows)
        self.assertTrue(res3["valid"])
        self.assertFalse(res3["intent_verified"])
        self.assertTrue(any("dangerous" in w for w in res3["warnings"]))

        # Dangerous subcommand: git reset
        res4 = wwf.verify_candidate_rule({"name": "git", "subcommands": ["reset"]}, synthetic_rows)
        self.assertTrue(res4["valid"])
        self.assertFalse(res4["intent_verified"])
        self.assertTrue(any("destructive" in w for w in res4["warnings"]))


class TestShapeExtraction(unittest.TestCase):
    def test_normalize_token_varieties(self):
        # Flags
        self.assertEqual(wwf.normalize_token("--release"), "--release")
        self.assertEqual(wwf.normalize_token("-rf"), "-rf")
        self.assertEqual(wwf.normalize_token("--grep=curl"), "--grep=<VAL>")
        self.assertEqual(wwf.normalize_token("--out=src/main.rs"), "--out=<PATH>")

        # Numbers
        self.assertEqual(wwf.normalize_token("42"), "<NUM>")

        # Variables
        self.assertEqual(wwf.normalize_token("$FOO"), "<VAR>")
        self.assertEqual(wwf.normalize_token("%USERPROFILE%"), "<VAR>")

        # URLs
        self.assertEqual(wwf.normalize_token("https://example.com/api"), "<URL>")

        # Quoted strings
        self.assertEqual(wwf.normalize_token('"commit message"'), "<STR>")
        self.assertEqual(wwf.normalize_token("'quoted text'"), "<STR>")

        # Paths
        self.assertEqual(wwf.normalize_token("src/lib.rs"), "<PATH>")
        self.assertEqual(wwf.normalize_token("C:\\Users\\dev\\file.txt"), "<PATH>")
        self.assertEqual(wwf.normalize_token("./scripts/verify.sh"), "<PATH>")

        # Common verbs
        self.assertEqual(wwf.normalize_token("status"), "status")
        self.assertEqual(wwf.normalize_token("commit"), "commit")
        self.assertEqual(wwf.normalize_token("test"), "test")

    def test_normalize_command_line(self):
        shape, head = wwf.normalize_command_line("git log -n 5 --grep=fix src/main.rs")
        self.assertEqual(head, "git")
        self.assertEqual(shape, "git log -n <NUM> --grep=<VAL> <PATH>")

        # Chained commands with operators
        chained = 'echo "hello world" && rm -rf "$TARGET_DIR"'
        shape, head = wwf.normalize_command_line(chained)
        self.assertEqual(head, "echo")
        self.assertEqual(shape, "echo <STR> && rm -rf <VAR>")

    def test_extract_shapes_dedup_and_privacy(self):
        rows = [
            wwf.Row("1", "Bash", {"command": "git status"}, "C:/Users/dev", False, True),
            wwf.Row("2", "Bash", {"command": "git status"}, "C:/Users/dev", False, True),
            wwf.Row("3", "Bash", {"command": "cargo test --release"}, "C:/Users/dev", False, True),
            wwf.Row("4", "Bash", {"command": "curl -s https://private.corp.internal/token=abc12345"}, "C:/Users/dev", False, True),
            wwf.Row("5", "Bash", {"command": "python /Users/secretuser/project/script.py --id=123"}, "C:/Users/dev", False, True),
        ]

        shapes = wwf.extract_shapes(rows)
        self.assertEqual(len(shapes), 4)

        # Most frequent first
        self.assertEqual(shapes[0]["shape"], "git status")
        self.assertEqual(shapes[0]["count"], 2)

        # Ensure all shapes contain ZERO PII / live secrets
        all_shapes_str = json.dumps(shapes)
        self.assertNotIn("/Users/secretuser", all_shapes_str)
        self.assertNotIn("private.corp.internal", all_shapes_str)
        self.assertNotIn("abc12345", all_shapes_str)
        self.assertNotIn("C:/Users/dev", all_shapes_str)


if __name__ == "__main__":
    unittest.main()
