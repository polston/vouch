#!/usr/bin/env bash
# Copy this repository's knowledge.toml to where an installed vouch reads it.
#
# A development convenience, not part of vouch. vouch never writes a file in
# ~/.config on its own initiative (CLAUDE.md §4), and there is deliberately no
# CLI verb for this: it is a file copy.
set -euo pipefail

src="$(cd "$(dirname "$0")/.." && pwd)/knowledge.toml"
dst="${HOME}/.config/vouch/knowledge.toml"

[ -f "$src" ] || { echo "no knowledge.toml at $src" >&2; exit 1; }

# Compared by CONTENT, not bytes. With `core.autocrlf` on, installing from a
# worktree and re-checking from the main checkout can otherwise report a
# difference whose diff shows no visible change, then exit non-zero — which
# inside a landing sequence reads as a failed step. `.gitattributes` pins this
# file to LF so it should not arise; this makes it harmless when it does.
if [ -f "$dst" ] && ! diff -q --strip-trailing-cr "$src" "$dst" >/dev/null; then
  echo "$dst differs from the repository copy. Nothing was written."
  diff -u --strip-trailing-cr "$dst" "$src" || true
  echo
  echo "re-run with --force to overwrite it."
  [ "${1:-}" = "--force" ] || exit 1
fi

mkdir -p "$(dirname "$dst")"
cp "$src" "$dst"
echo "copied to $dst"
echo "note: my-knowledge.toml is yours and was not touched."
