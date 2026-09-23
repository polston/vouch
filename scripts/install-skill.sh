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
# Reconciles destinations against the current source list by deleting files
# no longer present in source, excludes and prunes bytecode/cache directories,
# and reports per-file progress (M2.159).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
src_dir="$root/plugin/skills"
[ -d "$src_dir" ] || { echo "missing $src_dir" >&2; exit 1; }

force="${1:-}"
installed=0
skipped=0
differ=0
pruned=0

for sdir in "$src_dir"/*/; do
    [ -f "$sdir/SKILL.md" ] || continue
    sdir="${sdir%/}"
    name="$(basename "$sdir")"
    dst_sdir="$HOME/.claude/skills/$name"

    # Destination reconciliation: delete any destination file no longer present
    # in the skill's current source (and prune cache artifacts).
    if [ -d "$dst_sdir" ]; then
        # Prune existing cache directories in destination
        find "$dst_sdir" \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".mypy_cache" \) -exec rm -rf {} + 2>/dev/null || true
        find "$dst_sdir" \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null || true

        while IFS= read -r -d '' dst_file; do
            rel="${dst_file#"$dst_sdir/"}"
            src_file="$sdir/$rel"
            if [ ! -f "$src_file" ]; then
                rm -f "$dst_file"
                echo "pruned: $name/$rel"
                pruned=$((pruned + 1))
            fi
        done < <(find "$dst_sdir" -type f -print0)

        # Remove empty directories left after pruning
        find "$dst_sdir" -depth -mindepth 1 -type d -empty -delete 2>/dev/null || true
    fi

    # Copy files from source, pruning cache directories and cache files
    while IFS= read -r -d '' src; do
        rel="${src#"$sdir/"}"
        dst="$dst_sdir/$rel"
        if [ -f "$dst" ] && [ "$force" != "--force" ]; then
            # Compared by CONTENT, not bytes: `--strip-trailing-cr` ignores a
            # line-ending difference. `.gitattributes` pins these files to LF so the
            # question should not partition, but an installed copy predating that pin, or
            # one an editor rewrote, would otherwise be reported as a local edit with
            # a diff showing nothing — the least useful report available.
            if diff -q --strip-trailing-cr "$src" "$dst" >/dev/null 2>&1; then
                echo "identical: $name/$rel"
                skipped=$((skipped + 1)); continue
            fi
            echo "$name/$rel: the installed copy differs from this repository's. Diff:"
            diff --strip-trailing-cr "$dst" "$src" || true
            differ=$((differ + 1)); continue
        fi
        mkdir -p "$(dirname "$dst")"
        cp "$src" "$dst"
        echo "installed: $name/$rel"
        installed=$((installed + 1))
    done < <(find "$sdir" \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".mypy_cache" \) -prune -o -type f ! -name "*.pyc" ! -name "*.pyo" -print0)
done

if [ "$installed" -eq 0 ] && [ "$skipped" -eq 0 ] && [ "$differ" -eq 0 ] && [ "$pruned" -eq 0 ]; then
    echo "no skills found under $src_dir" >&2
    exit 1
fi

printf '%d installed, %d already identical, %d differing, %d pruned\n' "$installed" "$skipped" "$differ" "$pruned"
if [ "$differ" -gt 0 ]; then
    echo "re-run with --force to overwrite the differing ones"
    exit 1
fi
