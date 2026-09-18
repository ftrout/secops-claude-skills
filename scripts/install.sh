#!/usr/bin/env sh
# Copy (or symlink) skills from this repo into a Claude Code skills directory.
#
#   ./scripts/install.sh                 # all skills -> ~/.claude/skills (personal)
#   ./scripts/install.sh --project       # all skills -> ./.claude/skills (this repo/project)
#   ./scripts/install.sh --link          # symlink instead of copy (edits in repo take effect immediately)
#   ./scripts/install.sh ioc-extraction phishing-analysis   # only these skills
#
# Prefer the plugin route when you can (see README); this script is for teams that vendor
# skills into their own repos or run without marketplace access.
set -eu

HERE="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$HOME/.claude/skills"
MODE="copy"
SELECTED=""

for arg in "$@"; do
  case "$arg" in
    --project) DEST="$(pwd)/.claude/skills" ;;
    --link) MODE="link" ;;
    --dest=*) DEST="${arg#--dest=}" ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) SELECTED="$SELECTED $arg" ;;
  esac
done

mkdir -p "$DEST"
[ -n "$SELECTED" ] || SELECTED="$(ls "$HERE/skills")"

for name in $SELECTED; do
  src="$HERE/skills/$name"
  if [ ! -f "$src/SKILL.md" ]; then
    echo "skip: $name (no SKILL.md)" >&2
    continue
  fi
  rm -rf "$DEST/$name"
  if [ "$MODE" = "link" ]; then
    ln -s "$src" "$DEST/$name"
  else
    cp -R "$src" "$DEST/$name"
  fi
  echo "installed: $name -> $DEST/$name"
done
