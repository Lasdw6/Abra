#!/bin/sh
set -eu

: "${ABRA_PEER:?set ABRA_PEER}"
: "${ABRA_WORKSPACE:?set ABRA_WORKSPACE}"

abra send "$ABRA_PEER" --path "$ABRA_WORKSPACE" --wait
