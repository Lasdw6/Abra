#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ABRA="${ABRA_BIN:-$REPO_ROOT/target/release/abra}"
CADABRA="${CADABRA_BIN:-$REPO_ROOT/target/release/cadabra}"
ABRA_FC="${ABRA_FC_BIN:-$REPO_ROOT/target/release/abra-fc}"
FC="${FIRECRACKER_BIN:-/usr/local/bin/firecracker}"
ARTIFACTS="${FIRECRACKER_ARTIFACT_DIR:-/home/ubuntu/paperplanes/artifacts/firecracker}"
KERNEL="${FIRECRACKER_KERNEL:-$ARTIFACTS/vmlinux}"
ROOTFS="${FIRECRACKER_ROOTFS:-$ARTIFACTS/rootfs-headless-abra.ext4}"
KEY="${FIRECRACKER_SSH_KEY:-$ARTIFACTS/desktop_id_rsa}"
RUN_ROOT="${ABRA_FC_E2E_ROOT:-/home/ubuntu/.abra-fc-e2e}"
WORKSPACE="${ABRA_FC_E2E_WORKSPACE:-/home/ubuntu/abra-fc-e2e-workspace}"
REPORT="${ABRA_FC_E2E_REPORT:-$REPO_ROOT/adapters/firecracker/tests/e2e-report.json}"
HOST_LOG="$RUN_ROOT/host-daemon.log"
HOST_PID=""

cleanup() {
  "$ABRA_FC" --root "$RUN_ROOT" down --slot 0 >/dev/null 2>&1 || true
  "$ABRA_FC" --root "$RUN_ROOT" down --slot 1 >/dev/null 2>&1 || true
  [[ -z "$HOST_PID" ]] || kill "$HOST_PID" 2>/dev/null || true
}
trap cleanup EXIT

now_ms() { date +%s%3N; }
wait_until() {
  local description="$1"; shift
  for _ in $(seq 1 240); do
    if "$@"; then return 0; fi
    sleep 0.25
  done
  echo "timed out: $description" >&2
  return 1
}
guest() {
  ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$KEY" root@172.30.0.2 "$@"
}
host_has_peer() { "$ABRA" --root "$RUN_ROOT" --json peers 2>/dev/null | jq -e --arg id "$GUEST_PEER" '.[] | select(.peer_id == $id)' >/dev/null; }
host_has_snapshot() { "$ABRA" --root "$RUN_ROOT" --json log --capsule "$CAPSULE" 2>/dev/null | jq -e --arg id "$GUEST_SNAPSHOT" '.[] | select(.snapshot_id == $id)' >/dev/null; }
guest_has_capsule() { guest "abra --root /var/lib/abra --json log --capsule '$CAPSULE'" 2>/dev/null | jq -e 'length > 0' >/dev/null; }

for binary in "$ABRA" "$CADABRA" "$ABRA_FC" "$FC" "$KERNEL" "$ROOTFS" "$KEY"; do
  [[ -e "$binary" ]] || { echo "missing prerequisite: $binary" >&2; exit 1; }
done
"$ABRA_FC" --root "$RUN_ROOT" down --slot 0 >/dev/null 2>&1 || true
"$ABRA_FC" --root "$RUN_ROOT" down --slot 1 >/dev/null 2>&1 || true
rm -rf "$RUN_ROOT" "$WORKSPACE"
mkdir -p "$RUN_ROOT" "$WORKSPACE" "$(dirname "$REPORT")"
chmod 0700 "$RUN_ROOT"

STARTED="$(now_ms)"
"$CADABRA" --root "$RUN_ROOT" --yes >"$HOST_LOG" 2>&1 &
HOST_PID=$!
wait_until "host daemon socket" test -S "$RUN_ROOT/cadabra.sock"
HOST_PEER="$("$ABRA" --root "$RUN_ROOT" --json status | jq -r .peer_id)"

printf 'portable-before-snapshot\n' > "$WORKSPACE/marker.txt"
"$ABRA" --root "$RUN_ROOT" init "$WORKSPACE" >/dev/null
INITIAL="$("$ABRA" --root "$RUN_ROOT" --json snapshot "$WORKSPACE")"
CAPSULE="$(jq -r .capsule_id <<<"$INITIAL")"
TOKEN="$("$ABRA" --root "$RUN_ROOT" --json enroll --capsule "$CAPSULE" --kind dev.abra.workspace --ttl 1h --send --receive | jq -r .token)"

UP_STARTED="$(now_ms)"
"$ABRA_FC" --root "$RUN_ROOT" --firecracker "$FC" --ssh-key "$KEY" up --slot 0 --rootfs "$ROOTFS" --kernel "$KERNEL" --mem 512 --vcpus 1 --token "$TOKEN" >"$RUN_ROOT/up.json"
UP_MS="$(( $(now_ms) - UP_STARTED ))"
GUEST_PEER="$(guest 'abra --root /var/lib/abra --json status' | jq -r .peer_id)"
wait_until "guest enrollment visible on host" host_has_peer

"$ABRA" --root "$RUN_ROOT" send "$GUEST_PEER" --capsule "$CAPSULE" >/dev/null
wait_until "capsule delivered to guest" guest_has_capsule
tar -C "$WORKSPACE" -cf - . | guest 'mkdir -p /workspace && tar -C /workspace -xf -'
guest "mkdir -p /workspace/.abra; printf '%s' '$CAPSULE' > /workspace/.abra/capsule_id; printf 'native-marker\n' > /workspace/native-marker.txt; cd /workspace; nohup python3 -m http.server 8123 >/tmp/abra-marker.log 2>&1 &"
sleep 3
GUEST_SNAPSHOT="$(guest 'abra --root /var/lib/abra --json snapshot /workspace' | jq -r .snapshot_id)"
guest "abra --root /var/lib/abra send '$HOST_PEER' --capsule '$GUEST_SNAPSHOT' >/dev/null"
wait_until "guest snapshot received by host" host_has_snapshot

SNAP_STARTED="$(now_ms)"
NATIVE_RESULT="$("$ABRA_FC" --root "$RUN_ROOT" --firecracker "$FC" --ssh-key "$KEY" snapshot --slot 0 --capsule "$CAPSULE")"
SNAPSHOT_MS="$(( $(now_ms) - SNAP_STARTED ))"
NATIVE_SNAPSHOT="$(jq -r .snapshot_id <<<"$NATIVE_RESULT")"
MANIFEST="$RUN_ROOT/capsules/$CAPSULE/snapshots/$NATIVE_SNAPSHOT.cjson"
jq -e '.native | length == 3 and all(.fingerprint.hypervisor == "firecracker")' "$MANIFEST" >/dev/null

"$ABRA_FC" --root "$RUN_ROOT" down --slot 0
RESTORE_RESULT="$("$ABRA_FC" --root "$RUN_ROOT" --firecracker "$FC" --ssh-key "$KEY" restore --slot 0 --capsule "$CAPSULE" --snapshot "$NATIVE_SNAPSHOT")"
RESTORE_MS="$(jq -r .restore_ms <<<"$RESTORE_RESULT")"
guest 'test -f /workspace/native-marker.txt; pgrep -f "python3 -m http.server 8123" >/dev/null'

"$ABRA_FC" --root "$RUN_ROOT" down --slot 0
FAKE='{"os":"linux","arch":"x86_64","hypervisor":"firecracker","snapshot_format_major":999,"cpu_template":"-"}'
FALLBACK_RESULT="$(ABRA_FC_FAKE_FINGERPRINT="$FAKE" "$ABRA_FC" --root "$RUN_ROOT" --firecracker "$FC" --ssh-key "$KEY" restore --slot 1 --capsule "$CAPSULE" --snapshot "$NATIVE_SNAPSHOT")"
[[ "$(jq -r .mode <<<"$FALLBACK_RESULT")" == portable-fallback ]]
ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$KEY" root@172.30.1.2 test -f /workspace/native-marker.txt

jq -n \
  --arg capsule "$CAPSULE" --arg snapshot "$NATIVE_SNAPSHOT" \
  --argjson total_ms "$(( $(now_ms) - STARTED ))" --argjson up_ms "$UP_MS" \
  --argjson snapshot_ms "$SNAPSHOT_MS" --argjson restore_ms "$RESTORE_MS" \
  --argjson native "$(jq -c .native "$MANIFEST")" \
  '{ok:true,capsule:$capsule,native_snapshot:$snapshot,timings_ms:{total:$total_ms,up:$up_ms,snapshot:$snapshot_ms,native_restore:$restore_ms},native:$native,checks:{enrollment:true,transfer:true,native_manifest:true,process_resumed:true,portable_fallback:true}}' | tee "$REPORT"
