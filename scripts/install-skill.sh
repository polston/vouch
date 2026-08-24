#!/usr/bin/env bash
# Install this repository's skills where every session can load them. The repo
# copies are the source of truth; same pattern as install-knowledge.sh. Refuses
# to overwrite local edits unless --force.
#
# Installs EVERY skill under plugin/skills/, not a named one. It used to
# hardcode `vouch-trust`, which meant adding a second skill silently installed
# nothing — the file would sit in the repo looking installed while no session
# could load it. A skill nobody loads is worse than no skill: it reads as
# covered.
# Copies EVERY file in each skill directory, not only SKILL.md — a skill may
# carry a harness beside its text.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
src_dir="$root/plugin/skills"
[ -d "$src_dir" ] || { echo "missing $src_dir" >&2; exit 1; }

force="${1:-}"
installed=0
skipped=0
differ=0

for sdir in "$src_dir"/*/; do
    [ -f "$sdir/SKILL.md" ] || continue
    name="$(basename "$sdir")"
    while IFS= read -r -d '' src; do
        rel="${src#"$sdir"}"
        dst="$HOME/.claude/skills/$name/$rel"
        if [ -f "$dst" ] && [ "$force" != "--force" ]; then
            # Compared by CONTENT, not bytes: `--strip-trailing-cr` ignores a
            # line-ending difference. `.gitattributes` pins these files to LF so the
            # question should not arise, but an installed copy predating that pin, or
            # one an editor rewrote, would otherwise be reported as a local edit with
            # a diff showing nothing — the least useful report available.
            if diff -q --strip-trailing-cr "$src" "$dst" >/dev/null 2>&1; then
                skipped=$((skipped + 1)); continue
            fi
            echo "$name/$rel: the installed copy differs from this repository's. Diff:"
            diff --strip-trailing-cr "$dst" "$src" || true
            differ=$((differ + 1)); continue
        fi
        mkdir -p "$(dirname "$dst")"
        cp "$src" "$dst"
        installed=$((installed + 1))
    done < <(find "$sdir" -type f -print0)
done

if [ "$installed" -eq 0 ] && [ "$skipped" -eq 0 ] && [ "$differ" -eq 0 ]; then
    echo "no skills found under $src_dir" >&2
    exit 1
fi

printf '%d installed, %d already identical, %d differing\n' "$installed" "$skipped" "$differ"
if [ "$differ" -gt 0 ]; then
    echo "re-run with --force to overwrite the differing ones"
    exit 1
fi
