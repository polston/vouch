#!/usr/bin/env bash
# Prove paired installation without touching the operator's real installation.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
subject="$here/install-binaries.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pass=0
fail=0
check() {
  if [ "$2" = "$3" ]; then
    pass=$((pass + 1))
  else
    printf '  FAIL  %s (expected rc=%s, got rc=%s)\n' "$1" "$2" "$3"
    fail=$((fail + 1))
  fi
}

fresh_repo() {
  local repo="$work/$1"
  mkdir -p "$repo/scripts" "$repo/target/release" "$repo/fakehome"
  cp "$subject" "$repo/scripts/install-binaries.sh"
  printf '%s' "$repo"
}

fake_binary() { # fake_binary <path> <identity> <version>
  printf '#!/usr/bin/env bash\n[ "$1" = "--version" ] || exit 2\nprintf "%%s %%s\\n" "%s" "%s"\n' "$2" "$3" > "$1"
  chmod +x "$1"
}

run_install() { env HOME="$1/fakehome" bash "$1/scripts/install-binaries.sh" >/dev/null 2>&1; }

repo="$(fresh_repo missing)"
run_install "$repo"; rc=$?
check "missing binaries refuse" 1 "$rc"
[ -e "$repo/fakehome/.config/vouch/bin/vouch" ]; check "missing binaries install nothing" 1 "$?"

repo="$(fresh_repo half)"
fake_binary "$repo/target/release/vouch" vouch 1.2.3
run_install "$repo"; rc=$?
check "a missing broker refuses" 1 "$rc"
[ -e "$repo/fakehome/.config/vouch/bin/vouch" ]; check "a missing broker leaves no gate" 1 "$?"

repo="$(fresh_repo good)"
fake_binary "$repo/target/release/vouch" vouch 1.2.3
fake_binary "$repo/target/release/vouch-codex-broker" vouch-codex-broker 1.2.3
run_install "$repo"; rc=$?
check "a matched pair installs" 0 "$rc"
[ -x "$repo/fakehome/.config/vouch/bin/vouch" ]; check "the gate is executable" 0 "$?"
[ -x "$repo/fakehome/.config/vouch/bin/vouch-codex-broker" ]; check "the broker is executable" 0 "$?"
run_install "$repo"; check "re-running is idempotent" 0 "$?"

fake_binary "$repo/target/release/vouch" vouch 2.0.0
fake_binary "$repo/target/release/vouch-codex-broker" vouch-codex-broker 2.1.0
run_install "$repo"; rc=$?
check "mismatched versions refuse" 1 "$rc"
"$repo/fakehome/.config/vouch/bin/vouch" --version | grep -qx 'vouch 1.2.3'
check "a mismatch preserves the gate" 0 "$?"
"$repo/fakehome/.config/vouch/bin/vouch-codex-broker" --version | grep -qx 'vouch-codex-broker 1.2.3'
check "a mismatch preserves the broker" 0 "$?"

fake_binary "$repo/target/release/vouch" vouch 2.0.0
printf 'not executable\n' > "$repo/target/release/vouch-codex-broker"
chmod -x "$repo/target/release/vouch-codex-broker"
run_install "$repo"; rc=$?
check "an unusable broker refuses" 1 "$rc"
"$repo/fakehome/.config/vouch/bin/vouch" --version | grep -qx 'vouch 1.2.3'
check "an unusable broker preserves the pair" 0 "$?"

repo="$(fresh_repo occupied)"
fake_binary "$repo/target/release/vouch" vouch 1.2.3
fake_binary "$repo/target/release/vouch-codex-broker" vouch-codex-broker 1.2.3
mkdir -p "$repo/fakehome/.config/vouch/bin/vouch-codex-broker"
run_install "$repo"; rc=$?
check "a directory at a destination refuses" 1 "$rc"
[ -e "$repo/fakehome/.config/vouch/bin/vouch" ]; check "destination refusal installs no gate" 1 "$?"

repo="$(fresh_repo nosettings)"
mkdir -p "$repo/fakehome/.claude"
printf '{"hooks":{}}' > "$repo/fakehome/.claude/settings.json"
before="$(cat "$repo/fakehome/.claude/settings.json")"
fake_binary "$repo/target/release/vouch" vouch 1.2.3
fake_binary "$repo/target/release/vouch-codex-broker" vouch-codex-broker 1.2.3
run_install "$repo"
[ "$(cat "$repo/fakehome/.claude/settings.json")" = "$before" ]
check "hook settings remain untouched" 0 "$?"

repo="$(fresh_repo rollbackfails)"
fake_binary "$repo/target/release/vouch" vouch 1.2.3
fake_binary "$repo/target/release/vouch-codex-broker" vouch-codex-broker 1.2.3
run_install "$repo"
fake_binary "$repo/target/release/vouch" vouch 2.0.0
fake_binary "$repo/target/release/vouch-codex-broker" vouch-codex-broker 2.0.0
mkdir -p "$repo/fakebin"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'src="$2" destination="$3"' \
  'case "$destination" in' \
  '  */vouch|*/vouch.exe) exit 1 ;;' \
  '  */vouch-codex-broker|*/vouch-codex-broker.exe)' \
  '    case "$src" in *.restore|*.restore.exe) exit 1 ;; esac ;;' \
  'esac' \
  'exec "$VOUCH_TEST_REAL_MV" "$@"' \
  > "$repo/fakebin/mv"
chmod +x "$repo/fakebin/mv"
real_mv="$(command -v mv)"
out="$(env HOME="$repo/fakehome" PATH="$repo/fakebin:$PATH" \
  VOUCH_TEST_REAL_MV="$real_mv" bash "$repo/scripts/install-binaries.sh" 2>&1)"
rc=$?
check "a failed rollback still refuses" 1 "$rc"
"$repo/fakehome/.config/vouch/bin/vouch-codex-broker.rollback" --version \
  | grep -qx 'vouch-codex-broker 1.2.3'
check "a failed rollback retains the previous broker" 0 "$?"
printf '%s' "$out" | grep -q 'recovery copies were retained'
check "a failed rollback reports retained recovery" 0 "$?"
rm -f "$repo/fakehome/.config/vouch/bin/"*.rollback \
  "$repo/fakehome/.config/vouch/bin/"*.restore

leftovers="$(find "$work" -type f \( -name '*.new*' -o -name '*.rollback*' -o -name '*.restore*' \) -print)"
[ -z "$leftovers" ]; check "no scratch files remain" 0 "$?"

printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
