---
name: vouch-status
description: Use when checking what vouch is installed on this machine — reports installed binary, knowledge, and plugin versions against the newest public release, entirely read-only; it writes nothing, proposes nothing, and hands any actual move to vouch-update.
---

# vouch-status — what is installed, against what is released

The read-only half of `vouch-update`, alone: the survey and the comparison,
never the download or the install. Run it to answer "what version am I on and
is there a newer one" without being offered anything. The `/plugin` panel
shows only the plugin entry, so this is where the gate's own versions are
read.

## Hard rules

1. **This skill writes nothing and proposes nothing.** No download, no
   backup, no install, no config edit, no accept to give. A lag it finds is
   reported with the one command that acts on it (`/vouch:update`), and that
   is the whole handoff.
2. **It never opens `~/.claude/settings.json` or `~/.codex/hooks.json`.**
   Versions do not live there, and whole host documents never enter a
   conversation.

## Do this, in order

1. **Installed binary**: first line of `~/.config/vouch/bin/vouch --version`
   (`vouch X.Y.Z`, exit 0). Missing binary: report "not installed" and point
   at `vouch-setup`; the rest of the survey still runs.
2. **Installed knowledge**: confirm `~/.config/vouch/knowledge.toml` exists
   and read only its `version = N` schema line. The pair ships together, so
   the binary's version speaks for both; a missing file is its own finding.
3. **Installed plugin vs marketplace**: read the installed version and the
   marketplace entry's version exactly as `vouch-setup` phase 1 describes
   (`~/.claude/plugins/installed_plugins.json` against the marketplace's own
   `marketplace.json`; `codex plugin list` on Codex). A version-keyed cache
   moves only when `claude plugin update vouch` runs.
4. **Latest public release**: derive `<owner>/vouch` from the marketplace
   clone's git remote, then `gh release view --repo <owner>/vouch --json
   tagName,publishedAt` (public tags are plain `v<version>`). No marketplace
   clone: ask the operator for the repository once. No `gh` or no network:
   report the local half and say plainly that the release half is unknown —
   an unreachable release is never reported as "up to date".
5. **Report**, one table: installed binary, knowledge schema, installed
   plugin, marketplace plugin, latest release, and one verdict line —
   current, binary behind (`/vouch:update`), plugin behind
   (`claude plugin update vouch`), both behind (run both, gate first), or
   installed ahead of the release (a dev build; nothing to do here).

## Common mistakes

- Turning a lag report into an offer to fix it. The handoff is naming the
  command, not proposing the run — `vouch-update` owns the accept.
- Reporting "up to date" when the release lookup failed. Unknown is unknown.
- Reading any file beyond the version fields named above.
