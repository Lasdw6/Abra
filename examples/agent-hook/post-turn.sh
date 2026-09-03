#!/bin/sh
set -eu

: "${ABRA_PEER:?set ABRA_PEER}"
: "${ABRA_WORKSPACE:?set ABRA_WORKSPACE}"

label=${1:-agent turn}
result=$(abra --json snapshot "$ABRA_WORKSPACE" -m "$label")
snapshot=$(printf '%s' "$result" | jq -r '.snapshot_id // empty')
[ -n "$snapshot" ] || { echo "snapshot id missing" >&2; exit 1; }
abra send "$ABRA_PEER" --capsule "$snapshot"
