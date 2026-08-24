#!/usr/bin/env bash
# Install this checkout's two release binaries into the release-bundle layout.
# Hook configuration remains a human save; this script only installs files.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
release="$root/target/release"
suffix=""
if [ ! -f "$release/vouch" ] && [ -f "$release/vouch.exe" ]; then
  suffix=".exe"
fi

gate_src="$release/vouch$suffix"
broker_src="$release/vouch-codex-broker$suffix"
dst_dir="${HOME}/.config/vouch/bin"
gate_dst="$dst_dir/vouch$suffix"
broker_dst="$dst_dir/vouch-codex-broker$suffix"

for src in "$gate_src" "$broker_src"; do
  if [ ! -f "$src" ]; then
    echo "a release binary is missing; nothing was installed" >&2
    echo "build both first: cargo build --release" >&2
    exit 1
  fi
done

probe() { # probe <path> <identity prefix>
  local path="$1" prefix="$2" output line
  if ! output="$("$path" --version 2>/dev/null)"; then
    echo "$prefix did not run; nothing was installed" >&2
    return 1
  fi
  line="${output%%$'\n'*}"
  case "$line" in
    "$prefix "*) printf '%s\n' "$line" ;;
    *)
      echo "a release binary did not identify itself as $prefix; nothing was installed" >&2
      return 1
      ;;
  esac
}

gate_line="$(probe "$gate_src" vouch)"
broker_line="$(probe "$broker_src" vouch-codex-broker)"
gate_version="${gate_line#vouch }"
broker_version="${broker_line#vouch-codex-broker }"
if [ "$gate_version" != "$broker_version" ]; then
  echo "the gate and broker versions differ; nothing was installed" >&2
  exit 1
fi

mkdir -p "$dst_dir"
for dst in "$gate_dst" "$broker_dst"; do
  if [ -d "$dst" ]; then
    echo "a binary destination is a directory; nothing was installed" >&2
    exit 1
  fi
done

gate_tmp="$dst_dir/vouch.new$suffix"
broker_tmp="$dst_dir/vouch-codex-broker.new$suffix"
gate_old="$dst_dir/vouch.rollback$suffix"
broker_old="$dst_dir/vouch-codex-broker.rollback$suffix"
keep_recovery=0
cleanup() {
  rm -f "$gate_tmp" "$broker_tmp"
  if [ "$keep_recovery" -eq 0 ]; then
    rm -f "$gate_old" "$broker_old" "$gate_dst.restore" "$broker_dst.restore"
  fi
}
trap cleanup EXIT

cp "$gate_src" "$gate_tmp"
cp "$broker_src" "$broker_tmp"
chmod +x "$gate_tmp" "$broker_tmp"

staged_gate="$(probe "$gate_tmp" vouch)"
staged_broker="$(probe "$broker_tmp" vouch-codex-broker)"
[ "$staged_gate" = "$gate_line" ] || { echo "the staged gate changed; nothing was installed" >&2; exit 1; }
[ "$staged_broker" = "$broker_line" ] || { echo "the staged broker changed; nothing was installed" >&2; exit 1; }

gate_had=0
broker_had=0
if [ -f "$gate_dst" ]; then cp -p "$gate_dst" "$gate_old"; gate_had=1; fi
if [ -f "$broker_dst" ]; then cp -p "$broker_dst" "$broker_old"; broker_had=1; fi

replace() { # replace <staged> <destination>
  local staged="$1" destination="$2" attempt
  for attempt in 1 2 3 4 5; do
    if mv -f "$staged" "$destination" 2>/dev/null; then return 0; fi
    sleep 1
  done
  return 1
}

restore() { # restore <destination> <backup> <previously-present>
  local destination="$1" backup="$2" had="$3"
  if [ "$had" = 1 ]; then
    cp -p "$backup" "$destination.restore" && mv -f "$destination.restore" "$destination"
  else
    rm -f "$destination"
  fi
}

# Install the broker first. The gate is replaced last, so a new gate never
# points at an older broker. If the gate swap fails, restore the broker.
if ! replace "$broker_tmp" "$broker_dst"; then
  echo "the broker destination stayed busy; nothing was changed" >&2
  exit 1
fi
if ! replace "$gate_tmp" "$gate_dst"; then
  if restore "$broker_dst" "$broker_old" "$broker_had"; then
    echo "the gate destination stayed busy; the broker was restored" >&2
  else
    keep_recovery=1
    echo "the gate destination stayed busy and broker rollback failed; recovery copies were retained" >&2
  fi
  exit 1
fi

if ! installed_gate="$(probe "$gate_dst" vouch)" ||
   ! installed_broker="$(probe "$broker_dst" vouch-codex-broker)" ||
   [ "$installed_gate" != "$gate_line" ] ||
   [ "$installed_broker" != "$broker_line" ]; then
  rollback_failed=0
  restore "$gate_dst" "$gate_old" "$gate_had" || rollback_failed=1
  restore "$broker_dst" "$broker_old" "$broker_had" || rollback_failed=1
  if [ "$rollback_failed" -eq 0 ]; then
    echo "installed verification failed; both previous binaries were restored" >&2
  else
    keep_recovery=1
    echo "installed verification failed and rollback was incomplete; recovery copies were retained" >&2
  fi
  exit 1
fi

echo "installed vouch and vouch-codex-broker $gate_version"
echo "hook registration was not changed; generate it from the installed vouch binary"
