#!/bin/sh
# ABOUTME: Refreshes data/public_suffix_list.dat from the canonical upstream URL, never in place.
# ABOUTME: Verifies the MPL header, a VERSION line, both section markers and a minimum size before replacing.
set -eu

URL="https://publicsuffix.org/list/public_suffix_list.dat"
DEST="$(cd "$(dirname "$0")/.." && pwd)/data/public_suffix_list.dat"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

curl -fsSL -m 60 "$URL" -o "$TMP"

grep -q "Mozilla Public" "$TMP" || { echo "update-psl: missing MPL header" >&2; exit 1; }
grep -q "^// VERSION:" "$TMP" || { echo "update-psl: missing VERSION line" >&2; exit 1; }
grep -q "^// ===BEGIN ICANN DOMAINS===" "$TMP" || { echo "update-psl: missing ICANN marker" >&2; exit 1; }
grep -q "^// ===BEGIN PRIVATE DOMAINS===" "$TMP" || { echo "update-psl: missing PRIVATE marker" >&2; exit 1; }

SIZE=$(wc -c < "$TMP")
[ "$SIZE" -gt 200000 ] || { echo "update-psl: file is only $SIZE bytes, expected over 200000" >&2; exit 1; }

mv "$TMP" "$DEST"
trap - EXIT
echo "update-psl: wrote $DEST ($SIZE bytes)"
grep "^// VERSION:" "$DEST"
