#!/bin/sh
# The section of CHANGELOG.md of a version, without its heading: the notes of its
# release on GitHub
#
#     release/notes.sh v1.2.0
set -eu
cd "$(dirname "$0")/.."
notes=$(awk -v v="$1" '$1 == "##" { if (on) exit; on = ($2 == v); next } on' CHANGELOG.md)
test -n "$notes" || { echo "CHANGELOG.md has no section ## $1" >&2; exit 1; }
printf '%s\n' "$notes"
