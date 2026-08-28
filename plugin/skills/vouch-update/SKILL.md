---
name: vouch-update
description: Use when updating an installed vouch to a newer release — compares the installed pair against the newest public release, downloads and verifies the platform bundle, installs binaries and knowledge together, proves the result, and writes nothing without an explicit accept.
---

# vouch-update — move an installed gate to a newer release

The plugin route moves only procedures: `claude plugin update` refreshes
skills while the installed binary-and-knowledge pair stays where it was. This
skill is the other half — the gate itself, updated over the same verified
release route `vouch-setup` uses to provision a fresh machine, on an explicit
operator accept.

Checking without moving anything is `vouch-status` — the survey and
comparison below, alone, with no proposal at the end.

One delivery route per machine. A machine that develops vouch updates from its
clone (`cargo build --release && scripts/install-binaries.sh &&
scripts/install-knowledge.sh`) — if a clone built this install, say so and
stop rather than overwriting a dev build with a release.

## Hard rules

1. **Nothing is downloaded or written without an explicit accept.** The survey
   is read-only; the proposal names both versions; only an accept starts the
   download.
2. **Binaries and knowledge move together, from one release.** They are
   version-gated against each other: between a new binary and an old knowledge
   file the gate refuses everything. Never update one alone.
3. **Verify the archive against `SHA256SUMS` BEFORE anything is unpacked or
   run.** A file that fails the check is not unpacked, not run, and not
   reported as "probably fine".
4. **Hook wiring and `config.toml` are never touched.** The archive carries
   neither; this skill opens neither. There is no reason for this skill to
   read `~/.claude/settings.json` or `~/.codex/hooks.json` at all.
5. **Never downgrade silently.** An installed version NEWER than the latest
   release is a dev build or a pulled release — report it and stop unless the
   operator explicitly asks for the older version.

## Do this, in order

### 1. Survey (read-only)

- **Installed version**: first line of `~/.config/vouch/bin/vouch --version`
  (`vouch X.Y.Z`, exit 0). A missing binary means this is provisioning, not
  updating — hand over to `vouch-setup` and stop.
- **Platform triple**: `aarch64-apple-darwin` (Apple Silicon macOS),
  `x86_64-unknown-linux-gnu` (Linux), `x86_64-pc-windows-msvc` (Windows).
  These are the three the release workflow builds.
- **The release repository**: derive `<owner>/vouch` from the installed
  marketplace clone — `git -C ~/.claude/plugins/marketplaces/<marketplace>
  remote get-url origin` for the marketplace that carries the vouch plugin.
  If no marketplace clone exists, ask the operator for the repository once;
  do not guess an owner.
- **Latest release**: `gh release view --repo <owner>/vouch --json
  tagName,publishedAt`. Public release tags are plain `v<version>`. `gh` must
  be present and authenticated; without it, report that and stop — do not
  substitute an unverified download path.
- **Plugin lag**, for the reminder in step 5: read the installed plugin
  version and the marketplace entry's version exactly as `vouch-setup` phase 1
  describes (`~/.claude/plugins/installed_plugins.json` against the
  marketplace's own `marketplace.json`). A lagging plugin is a finding to
  report alongside the binary lag, not something this skill fixes.

### 2. Compare and propose

- Installed equals latest: say so and stop. Nothing to do is a result.
- Installed older: propose the update in one line — `vouch X.Y.Z →
  vouch A.B.C, released <date>` — and wait for the operator's accept.
- Installed newer: hard rule 5. Report both versions and stop.

### 3. Download and verify

In a scratch directory (the session scratchpad when one exists, else the OS
temp directory):

1. `gh release download --repo <owner>/vouch --pattern
   'vouch-<triple>.zip'` and, from the same release, `--pattern SHA256SUMS`.
2. Check the archive's digest against its `SHA256SUMS` line
   (`shasum -a 256 -c` on the matching line; on Windows compare
   `Get-FileHash -Algorithm SHA256` output by hand). Integrity first,
   semantics second (hard rule 3).

### 4. Back up, install, prove

1. Byte-for-byte backup of the current `~/.config/vouch/bin/` binaries and
   `~/.config/vouch/knowledge.toml` into the scratch directory. Show the
   operator the one command that restores it.
2. Unpack the archive into `~/.config/vouch/`: both binaries land in `bin/`,
   `knowledge.toml` lands beside the config, `vouch.example.toml` lands
   beside it too (it seeds nothing — a `config.toml` already exists on an
   installed machine, and this skill never touches it). On Windows use
   `Expand-Archive`; the binaries are `vouch.exe` and
   `vouch-codex-broker.exe`.
3. Prove the pair: `~/.config/vouch/bin/vouch --version` reports the new
   version, and `vouch explain 'ls -la'` answers with no gap or refusal
   banner — the loaded knowledge matches the binary.
4. On any failed proof: restore the backup, re-run the same two probes to
   confirm the restore took, and report the exact failure. A half-updated
   gate is worse than an old one.

### 5. Finish

- Remind the operator to move the procedures with the gate:
  `claude plugin update vouch` then a restart on Claude Code, or the Codex
  plugin update on Codex. Skills describe the binary's flags; a new binary
  under old skills is the skew this reminder exists for.
- Delete the scratch downloads; keep the backup until the operator has used
  the updated gate once, then say where it is so they can remove it.
- Report what changed in two lines: the version pair, and that config and
  hook wiring were untouched.

## Common mistakes

- Updating the binary from a release while the machine actually runs a dev
  build installed from a clone (hard rule 5 catches the version shape; the
  clone check in the opening catches the rest).
- Unpacking before the checksum verifies, "just to look".
- Reading the host's settings or hooks file to "check the wiring" — this
  skill has no reason to open either, and the wiring is not its business.
- Treating a missing `gh` as a reason to fetch the archive some other way.
  The verified route is the route.
