"""Unit tests for secret redaction and active session exclusion in build_fixture.py.

Verifies that credential patterns, tokens, and active session transcripts are
properly sanitized or excluded when harvesting replay corpus fixtures.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_fixture


class TestSecretRedaction(unittest.TestCase):
    def test_redact_tokens(self):
        # Construct test token strings dynamically with scan-allow marker
        gh_tok = "gh" + "p_1234567890123456"  # scan-allow
        oa_tok = "sk" + "-1234567890123456"  # scan-allow
        aws_tok = "AKIA" + "123456789012"  # scan-allow
        slack_tok = "xoxb" + "-123456789012"  # scan-allow

        cmd1 = f"curl -H 'Authorization: token {gh_tok}' https://api.github.com"
        redacted1, count1 = build_fixture.redact_secrets(cmd1)
        self.assertNotIn(gh_tok, redacted1)
        self.assertIn("<REDACTED_TOKEN>", redacted1)
        self.assertGreaterEqual(count1, 1)

        cmd2 = f"export OPENAI_API_KEY={oa_tok}"
        redacted2, count2 = build_fixture.redact_secrets(cmd2)
        self.assertNotIn(oa_tok, redacted2)
        self.assertIn("<REDACTED_SECRET>", redacted2)
        self.assertGreaterEqual(count2, 1)

        cmd3 = f"aws s3 ls --access-key {aws_tok}"
        redacted3, count3 = build_fixture.redact_secrets(cmd3)
        self.assertNotIn(aws_tok, redacted3)
        self.assertIn("<REDACTED_TOKEN>", redacted3)
        self.assertGreaterEqual(count3, 1)

        cmd4 = f"slack-cli --token={slack_tok}"
        redacted4, count4 = build_fixture.redact_secrets(cmd4)
        self.assertNotIn(slack_tok, redacted4)
        self.assertIn("<REDACTED_TOKEN>", redacted4)
        self.assertGreaterEqual(count4, 1)

    def test_redact_env_credential_assignments(self):
        cmd = "export GITHUB_TOKEN=mysecretpassword123 && echo done"
        redacted, count = build_fixture.redact_secrets(cmd)
        self.assertNotIn("mysecretpassword123", redacted)
        self.assertIn("GITHUB_TOKEN=<REDACTED_SECRET>", redacted)
        self.assertGreaterEqual(count, 1)

        cmd_quoted = 'DB_PASSWORD="super_secret_val" ./run.sh'
        redacted_q, count_q = build_fixture.redact_secrets(cmd_quoted)
        self.assertNotIn("super_secret_val", redacted_q)
        self.assertIn('DB_PASSWORD="<REDACTED_SECRET>"', redacted_q)
        self.assertGreaterEqual(count_q, 1)

    def test_redact_auth_headers(self):
        cmd = "curl -H 'Authorization: Bearer mylongsecrettoken12345' https://example.com"
        redacted, count = build_fixture.redact_secrets(cmd)
        self.assertNotIn("mylongsecrettoken12345", redacted)
        self.assertIn("Bearer <REDACTED_AUTH>", redacted)
        self.assertGreaterEqual(count, 1)

    def test_redact_private_keys(self):
        priv_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nsecretkeydatahere12345\n-----END OPENSSH PRIVATE KEY-----"
        cmd = f"echo '{priv_key}' > id_rsa"
        redacted, count = build_fixture.redact_secrets(cmd)
        self.assertNotIn("secretkeydatahere12345", redacted)
        self.assertIn("[REDACTED_PRIVATE_KEY]", redacted)
        self.assertGreaterEqual(count, 1)

    def test_redact_session_urls_and_ids(self):
        sess_token = "session_" + "1234567890abcdef"  # scan-allow
        cmd = f"git commit -m 'test\n\nhttps://claude.ai/code/{sess_token}'"  # scan-allow
        redacted, count = build_fixture.redact_secrets(cmd)
        self.assertNotIn(sess_token, redacted)
        self.assertIn("session_<REDACTED_SESSION_ID>", redacted)
        self.assertGreaterEqual(count, 1)

    def test_redact_json_credentials(self):
        cmd = 'curl -X POST -d \'{"username": "admin", "password": "supersecretpassword"}\' http://localhost/login'
        redacted, count = build_fixture.redact_secrets(cmd)
        self.assertNotIn("supersecretpassword", redacted)
        self.assertIn('"password": "<REDACTED_SECRET>"', redacted)
        self.assertGreaterEqual(count, 1)

    def test_preserve_benign_commands(self):
        benign = [
            "ls -la",
            "git status",
            "cargo test --release",
            "cat /tmp/notes.txt",
            "grep -rn TODO src/",
            "echo 'hello world' > out.txt",
        ]
        for cmd in benign:
            redacted, count = build_fixture.redact_secrets(cmd)
            self.assertEqual(cmd, redacted)
            self.assertEqual(count, 0)


class TestActiveSessionExclusion(unittest.TestCase):
    def test_session_exclusion_by_path(self):
        invented_uuid = "00000000-0000-0000-0000-000000000000"
        excluded = {"sess-active-123", invented_uuid}

        path_active_claude = "/home/dev/.claude/projects/myproj/sess-active-123.jsonl"
        self.assertTrue(build_fixture.is_session_excluded(path_active_claude, excluded))

        path_active_agy = f"/home/dev/.gemini/antigravity-cli/brain/{invented_uuid}/transcript.jsonl"
        self.assertTrue(build_fixture.is_session_excluded(path_active_agy, excluded))

        path_inactive = "/home/dev/.claude/projects/myproj/sess-past-999.jsonl"
        self.assertFalse(build_fixture.is_session_excluded(path_inactive, excluded))

    def test_environment_active_session_ids(self):
        old_env = dict(os.environ)
        try:
            os.environ["CLAUDE_SESSION_ID"] = "test-claude-session"
            os.environ["CONVERSATION_ID"] = "test-agy-convo"
            active = build_fixture.get_active_session_ids()
            self.assertIn("test-claude-session", active)
            self.assertIn("test-agy-convo", active)
        finally:
            os.environ.clear()
            os.environ.update(old_env)


if __name__ == "__main__":
    unittest.main()
