#!/usr/bin/env bash
# Prove skill installation and destination reconciliation without touching the operator's real installation.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
subject="$here/install-skill.sh"
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

fresh_env() {
  local repo="$work/$1"
  mkdir -p "$repo/scripts" "$repo/plugin/skills/test-skill" "$repo/fakehome"
  cp "$subject" "$repo/scripts/install-skill.sh"
  chmod +x "$repo/scripts/install-skill.sh"
  printf '%s' "$repo"
}

run_install() {
  local repo="$1"
  shift
  env HOME="$repo/fakehome" bash "$repo/scripts/install-skill.sh" "$@"
}

# 1. Missing skills directory exits 1
empty_repo="$work/empty_repo"
mkdir -p "$empty_repo/scripts" "$empty_repo/fakehome"
cp "$subject" "$empty_repo/scripts/install-skill.sh"
out=$(env HOME="$empty_repo/fakehome" bash "$empty_repo/scripts/install-skill.sh" 2>&1 || true)
echo "$out" | grep -q 'missing '
check "missing skills directory refuses" 0 "$?"

# 2. Fresh install copies all source files
repo="$(fresh_env fresh)"
printf '# Test Skill\n' > "$repo/plugin/skills/test-skill/SKILL.md"
printf 'print("helper")\n' > "$repo/plugin/skills/test-skill/helper.py"
out=$(run_install "$repo")
check "fresh install succeeds" 0 "$?"
echo "$out" | grep -q 'installed: test-skill/SKILL.md'
check "reports installed SKILL.md" 0 "$?"
echo "$out" | grep -q 'installed: test-skill/helper.py'
check "reports installed helper.py" 0 "$?"
[ -f "$repo/fakehome/.claude/skills/test-skill/SKILL.md" ]
check "destination SKILL.md exists" 0 "$?"
[ -f "$repo/fakehome/.claude/skills/test-skill/helper.py" ]
check "destination helper.py exists" 0 "$?"

# 3. Re-running is idempotent and reports identical
out=$(run_install "$repo")
check "idempotent rerun succeeds" 0 "$?"
echo "$out" | grep -q 'identical: test-skill/SKILL.md'
check "reports identical SKILL.md" 0 "$?"
echo "$out" | grep -q 'identical: test-skill/helper.py'
check "reports identical helper.py" 0 "$?"

# 4. Differing destination file without --force exits 1
printf 'modified locally\n' > "$repo/fakehome/.claude/skills/test-skill/helper.py"
out=$(run_install "$repo" 2>&1 || true)
echo "$out" | grep -q 'the installed copy differs'
check "differing destination file detects diff" 0 "$?"
echo "$out" | grep -q 're-run with --force to overwrite'
check "differing destination file warns on --force" 0 "$?"

# 5. Differing destination file with --force overwrites
out=$(run_install "$repo" --force)
check "overwrite with --force succeeds" 0 "$?"
echo "$out" | grep -q 'installed: test-skill/helper.py'
check "reports installed on --force overwrite" 0 "$?"
[ "$(cat "$repo/fakehome/.claude/skills/test-skill/helper.py")" = 'print("helper")' ]
check "overwritten content matches source" 0 "$?"

# 6. Removing a source file reconciles (deletes) destination orphan
rm -f "$repo/plugin/skills/test-skill/helper.py"
out=$(run_install "$repo")
check "install after file removal succeeds" 0 "$?"
echo "$out" | grep -q 'pruned: test-skill/helper.py'
check "reports pruned orphaned destination file" 0 "$?"
[ ! -f "$repo/fakehome/.claude/skills/test-skill/helper.py" ]
check "orphaned destination file is deleted" 0 "$?"
[ -f "$repo/fakehome/.claude/skills/test-skill/SKILL.md" ]
check "remaining source file is preserved" 0 "$?"

# 7. Bytecode and cache directories are not copied
mkdir -p "$repo/plugin/skills/test-skill/__pycache__"
printf 'compiled bytecode\n' > "$repo/plugin/skills/test-skill/__pycache__/helper.cpython-312.pyc"
mkdir -p "$repo/plugin/skills/test-skill/.pytest_cache"
printf 'cache\n' > "$repo/plugin/skills/test-skill/.pytest_cache/v"
printf 'pyc\n' > "$repo/plugin/skills/test-skill/extra.pyc"
out=$(run_install "$repo")
check "install with cache artifacts in source succeeds" 0 "$?"
[ ! -e "$repo/fakehome/.claude/skills/test-skill/__pycache__" ]
check "__pycache__ is not copied to destination" 0 "$?"
[ ! -e "$repo/fakehome/.claude/skills/test-skill/.pytest_cache" ]
check ".pytest_cache is not copied to destination" 0 "$?"
[ ! -e "$repo/fakehome/.claude/skills/test-skill/extra.pyc" ]
check "*.pyc is not copied to destination" 0 "$?"

# 8. Pre-existing cache directories in destination are pruned during reconciliation
mkdir -p "$repo/fakehome/.claude/skills/test-skill/__pycache__"
printf 'old bytecode\n' > "$repo/fakehome/.claude/skills/test-skill/__pycache__/old.pyc"
out=$(run_install "$repo")
check "reconciliation over destination with cache succeeds" 0 "$?"
[ ! -e "$repo/fakehome/.claude/skills/test-skill/__pycache__" ]
check "destination __pycache__ is purged during reconciliation" 0 "$?"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -gt 0 ]; then
  exit 1
fi
