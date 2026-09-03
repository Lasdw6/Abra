#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ABRA="${ABRA_BIN:-$REPO_ROOT/target/release/abra}"
CADABRA="${CADABRA_BIN:-$REPO_ROOT/target/release/cadabra}"
ABRA_FC="${ABRA_FC_BIN:-$REPO_ROOT/target/release/abra-fc}"
FC="${FIRECRACKER_BIN:-/usr/local/bin/firecracker}"
ARTIFACTS="${FIRECRACKER_ARTIFACT_DIR:-/home/ubuntu/paperplanes/artifacts/firecracker}"
KERNEL="${FIRECRACKER_KERNEL:-$ARTIFACTS/vmlinux}"
BASE_ROOTFS="${FIRECRACKER_BASE_ROOTFS:-$ARTIFACTS/rootfs-headless-base.ext4}"
# With per-run image rebuild (the default) only the base image must pre-exist.
if [[ "${ABRA_FC_E2E_REBUILD_IMAGE:-1}" == "1" ]]; then
  ROOTFS="${FIRECRACKER_ROOTFS:-$BASE_ROOTFS}"
else
  ROOTFS="${FIRECRACKER_ROOTFS:-$ARTIFACTS/rootfs-headless-abra.ext4}"
fi
KEY="${FIRECRACKER_SSH_KEY:-$ARTIFACTS/desktop_id_rsa}"
RUN_ROOT="${ABRA_FC_E2E_ROOT:-/home/ubuntu/.abra-fc-e2e}"
RUN_ROOT_B="${ABRA_FC_E2E_ROOT_B:-${RUN_ROOT}-device-b}"
FRESH_ROOT="${ABRA_FC_E2E_FRESH_ROOT:-${RUN_ROOT}-fresh-host}"
WORKSPACE="${ABRA_FC_E2E_WORKSPACE:-/home/ubuntu/abra-fc-e2e-workspace}"
RECEIVED_B="${ABRA_FC_E2E_RECEIVED_B:-${WORKSPACE}-received-b}"
REPORT="${ABRA_FC_E2E_REPORT:-$REPO_ROOT/adapters/firecracker/tests/e2e-report.json}"
HOST_LOG="$RUN_ROOT/host-daemon.log"
HOST_PID=""
HOST_PID_B=""
FRESH_PID=""
RICH_IMAGE_TOOLS=null
SECOND_DEVICE_NATIVE=null

cleanup() {
  "$ABRA_FC" --root "$RUN_ROOT" down --slot 0 >/dev/null 2>&1 || true
  "$ABRA_FC" --root "$RUN_ROOT" down --slot 1 >/dev/null 2>&1 || true
  "$ABRA_FC" --root "$RUN_ROOT_B" down --slot 0 >/dev/null 2>&1 || true
  "$ABRA_FC" --root "$FRESH_ROOT" down --slot 1 >/dev/null 2>&1 || true
  [[ -z "$HOST_PID" ]] || kill "$HOST_PID" 2>/dev/null || true
  [[ -z "$HOST_PID_B" ]] || kill "$HOST_PID_B" 2>/dev/null || true
  [[ -z "$FRESH_PID" ]] || kill "$FRESH_PID" 2>/dev/null || true
  for tap in osdtap0 osdtap1; do sudo ip link del "$tap" >/dev/null 2>&1 || true; done
  while read -r pid; do
    [[ -r "/proc/$pid/cmdline" ]] || continue
    tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Eq "$(printf '%s|%s' "$RUN_ROOT" "$FRESH_ROOT")" && sudo kill "$pid" 2>/dev/null || true
  done < <(pgrep -x firecracker 2>/dev/null || true)
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
inbox_has() { "$ABRA" --root "$1" --json inbox 2>/dev/null | jq -e --arg id "$2" '.[] | select(.id == $id)' >/dev/null; }
# Full-capsule snapshots sync into the capsule log, not the inbox.
log_has() { "$ABRA" --root "$1" --json log --capsule "$2" 2>/dev/null | jq -e --arg id "$3" '.[] | select(.snapshot_id == $id)' >/dev/null; }

for binary in "$ABRA" "$CADABRA" "$ABRA_FC" "$FC" "$KERNEL" "$ROOTFS" "$KEY"; do
  [[ -e "$binary" ]] || { echo "missing prerequisite: $binary" >&2; exit 1; }
done
"$ABRA_FC" --root "$RUN_ROOT" down --slot 0 >/dev/null 2>&1 || true
"$ABRA_FC" --root "$RUN_ROOT" down --slot 1 >/dev/null 2>&1 || true
rm -rf "$RUN_ROOT" "$RUN_ROOT_B" "$FRESH_ROOT" "$WORKSPACE" "$RECEIVED_B"
mkdir -p "$RUN_ROOT" "$RUN_ROOT_B" "$FRESH_ROOT" "$WORKSPACE" "$(dirname "$REPORT")"
chmod 0700 "$RUN_ROOT" "$RUN_ROOT_B" "$FRESH_ROOT"

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

# Guest binaries must be STATIC (musl): the guest rootfs (jammy, glibc 2.35)
# cannot run host-glibc builds, and a stale image silently breaks enrollment
# when token/protocol formats change. Rebuild both per run unless disabled.
if [[ "${ABRA_FC_E2E_REBUILD_IMAGE:-1}" == "1" ]]; then
  (cd "$REPO_ROOT" && cargo build --release --target x86_64-unknown-linux-musl -p abra-cli -p cadabra >/dev/null)
  MUSL="$REPO_ROOT/target/x86_64-unknown-linux-musl/release"
  ROOTFS="$RUN_ROOT/rootfs-headless-abra.ext4"
  cp -f "$BASE_ROOTFS" "$ROOTFS"
  if [[ "${ABRA_FC_E2E_RICH_IMAGE:-0}" == "1" ]]; then
    sudo -E bash "$REPO_ROOT/adapters/firecracker/guest/provision-rootfs.sh" \
      "$ROOTFS" "$MUSL/abra" "$MUSL/cadabra" >/dev/null
  else
    sudo bash "$REPO_ROOT/adapters/firecracker/guest/install-rootfs.sh" \
      "$ROOTFS" "$MUSL/abra" "$MUSL/cadabra" >/dev/null
  fi
fi

UP_STARTED="$(now_ms)"
"$ABRA_FC" --root "$RUN_ROOT" --firecracker "$FC" --ssh-key "$KEY" up --slot 0 --rootfs "$ROOTFS" --kernel "$KERNEL" --mem 512 --vcpus 1 --token "$TOKEN" >"$RUN_ROOT/up.json"
UP_MS="$(( $(now_ms) - UP_STARTED ))"
GUEST_PEER="$(guest 'abra --root /var/lib/abra --json status' | jq -r .peer_id)"
guest "test \"\$(stat -c '%U:%G:%a' /etc/abra/token)\" = root:root:600; ! grep -Fq 'abra.token=' /proc/cmdline"
if [[ "${ABRA_FC_E2E_RICH_IMAGE:-0}" == "1" ]]; then
  guest "node --version | grep -q '^v22\\.'; google-chrome --version >/dev/null; codex --version >/dev/null; command -v abra-browser >/dev/null"
  guest "abra --root /var/lib/abra --json adapters list" | jq -e \
    '.adapters[] | select(.manifest.name == "dev.abra.browser-session")' >/dev/null
  guest 'set -eu
    profile="$(mktemp -d /tmp/abra-rich-chrome.XXXXXX)"
    bundle="$(mktemp -d /tmp/abra-rich-bundle.XXXXXX)"
    chrome_pid=""
    cleanup_rich() { [ -z "$chrome_pid" ] || kill "$chrome_pid" 2>/dev/null || true; rm -rf "$profile" "$bundle"; }
    trap cleanup_rich EXIT
    google-chrome --headless=new --no-sandbox --disable-dev-shm-usage --user-data-dir="$profile" --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 --no-first-run about:blank >/tmp/abra-rich-chrome.log 2>&1 &
    chrome_pid=$!
    cdp=""
    for _ in $(seq 1 200); do cdp="$(curl -fsS http://127.0.0.1:9222/json/version 2>/dev/null | jq -r .webSocketDebuggerUrl 2>/dev/null || true)"; [ -z "$cdp" ] || break; sleep .05; done
    [ -n "$cdp" ]
    abra-browser export "$cdp" --from cdp --out "$bundle" >/dev/null
    jq -e '\''.kind == "dev.abra.browser.session.v1" and .source == "cdp"'\'' "$bundle/manifest.json" >/dev/null'
  RICH_IMAGE_TOOLS='{"node_22":true,"google_chrome":true,"codex_cli":true,"browser_session_adapter":true,"chrome_cdp_export":true}'
fi
! grep -FR -- "$TOKEN" "$RUN_ROOT/up.json" "$RUN_ROOT/firecracker/slots/0/firecracker.log" \
  "$RUN_ROOT/firecracker/slots/0/stdout.log" "$RUN_ROOT/firecracker/slots/0/stderr.log"
wait_until "guest enrollment visible on host" host_has_peer

"$ABRA" --root "$RUN_ROOT" send "$GUEST_PEER" --capsule "$CAPSULE" >/dev/null
wait_until "capsule delivered to guest" guest_has_capsule
tar -C "$WORKSPACE" -cf - . | guest 'mkdir -p /workspace && tar -C /workspace -xf -'
guest "mkdir -p /workspace/.abra; printf '%s' '$CAPSULE' > /workspace/.abra/capsule_id; printf 'native-marker\n' > /workspace/native-marker.txt; cd /workspace; nohup python3 -m http.server 8123 >/tmp/abra-marker.log 2>&1 &"
sleep 3
MARKER_PID="$(guest "pgrep -f '[p]ython3 -m http.server 8123' | head -n1")"
MARKER_START="$(guest "awk '{print \$22}' /proc/$MARKER_PID/stat")"
guest "test -n '$MARKER_PID'; test -n '$MARKER_START'; curl -sf http://127.0.0.1:8123/native-marker.txt | grep -qx native-marker"
GUEST_SNAPSHOT="$(guest 'abra --root /var/lib/abra --json snapshot /workspace' | jq -r .snapshot_id)"
guest "abra --root /var/lib/abra send '$HOST_PEER' --capsule '$GUEST_SNAPSHOT' >/dev/null"
wait_until "guest snapshot received by host" host_has_snapshot

SNAP_STARTED="$(now_ms)"
NATIVE_RESULT="$("$ABRA_FC" --root "$RUN_ROOT" --firecracker "$FC" --ssh-key "$KEY" snapshot --slot 0 --capsule "$CAPSULE")"
SNAPSHOT_MS="$(( $(now_ms) - SNAP_STARTED ))"
PORTABLE_SNAPSHOT="$(jq -r .portable_snapshot_id <<<"$NATIVE_RESULT")"
NATIVE_SNAPSHOT="$(jq -r .native_snapshot_id <<<"$NATIVE_RESULT")"
[[ "$PORTABLE_SNAPSHOT" != null && "$NATIVE_SNAPSHOT" != null ]]
MANIFEST="$RUN_ROOT/capsules/$CAPSULE/snapshots/$NATIVE_SNAPSHOT.cjson"
jq -e '.native | length == 3 and all(.fingerprint.hypervisor == "firecracker")' "$MANIFEST" >/dev/null

# Device B receives only the portable parent, then materializes files and recipes.
"$CADABRA" --root "$RUN_ROOT_B" --yes >"$RUN_ROOT_B/daemon.log" 2>&1 &
HOST_PID_B=$!
wait_until "device B daemon socket" test -S "$RUN_ROOT_B/cadabra.sock"
PAIR_TICKET_B="$("$ABRA" --root "$RUN_ROOT_B" pair ticket)"
"$ABRA" --root "$RUN_ROOT" pair add "$PAIR_TICKET_B" >/dev/null
PEER_B="$("$ABRA" --root "$RUN_ROOT_B" --json status | jq -r .peer_id)"
"$ABRA" --root "$RUN_ROOT" send "$PEER_B" --capsule "$PORTABLE_SNAPSHOT" >/dev/null
wait_until "portable snapshot at device B" log_has "$RUN_ROOT_B" "$CAPSULE" "$PORTABLE_SNAPSHOT"
"$ABRA" --root "$RUN_ROOT_B" accept "$PORTABLE_SNAPSHOT" --to "$RECEIVED_B" >/dev/null
# B holds the guest-authored snapshot: the original marker plus the file the guest wrote.
diff -q "$WORKSPACE/marker.txt" "$RECEIVED_B/marker.txt"
grep -qx native-marker "$RECEIVED_B/native-marker.txt"
test -s "$RECEIVED_B/.abra/recipes.json"

# A rich image makes the native disk object several GiB. The default minimal
# run proves cross-device native transfer; rich runs exercise local native
# restore plus portable transfers and report this large transfer as skipped.
if [[ "${ABRA_FC_E2E_RICH_IMAGE:-0}" != "1" ]]; then
  "$ABRA" --root "$RUN_ROOT" send "$PEER_B" --capsule "$NATIVE_SNAPSHOT" >/dev/null
  wait_until "native snapshot at device B" log_has "$RUN_ROOT_B" "$CAPSULE" "$NATIVE_SNAPSHOT"
  "$ABRA_FC" --root "$RUN_ROOT" down --slot 0
  SECOND_NATIVE_RESULT="$("$ABRA_FC" --root "$RUN_ROOT_B" --firecracker "$FC" --ssh-key "$KEY" restore \
    --slot 0 --capsule "$CAPSULE" --snapshot "$NATIVE_SNAPSHOT" \
    --kernel "$KERNEL" --rootfs "$ROOTFS" --mem 512 --vcpus 1)"
  [[ "$(jq -r .mode <<<"$SECOND_NATIVE_RESULT")" == native ]]
  guest "test -f /workspace/native-marker.txt; test -r /proc/$MARKER_PID/stat; test \"\$(awk '{print \$22}' /proc/$MARKER_PID/stat)\" = '$MARKER_START'"
  curl -sf --noproxy '*' http://172.30.0.2:8123/native-marker.txt | grep -qx native-marker
  "$ABRA_FC" --root "$RUN_ROOT_B" down --slot 0
  SECOND_DEVICE_NATIVE=true
fi

# A third empty root acts as a fresh compatible host. It receives the portable
# parent, so native blobs are absent even though host A still owns them.
"$CADABRA" --root "$FRESH_ROOT" --yes >"$FRESH_ROOT/daemon.log" 2>&1 &
FRESH_PID=$!
wait_until "fresh host daemon socket" test -S "$FRESH_ROOT/cadabra.sock"
PAIR_TICKET_FRESH="$("$ABRA" --root "$FRESH_ROOT" pair ticket)"
"$ABRA" --root "$RUN_ROOT" pair add "$PAIR_TICKET_FRESH" >/dev/null
PEER_FRESH="$("$ABRA" --root "$FRESH_ROOT" --json status | jq -r .peer_id)"
"$ABRA" --root "$RUN_ROOT" send "$PEER_FRESH" --capsule "$PORTABLE_SNAPSHOT" >/dev/null
wait_until "portable snapshot at fresh host" log_has "$FRESH_ROOT" "$CAPSULE" "$PORTABLE_SNAPSHOT"
FRESH_RESULT="$("$ABRA_FC" --root "$FRESH_ROOT" --firecracker "$FC" --ssh-key "$KEY" restore \
  --slot 1 --capsule "$CAPSULE" --snapshot "$PORTABLE_SNAPSHOT" \
  --kernel "$KERNEL" --rootfs "$ROOTFS" --mem 512 --vcpus 1)"
[[ "$(jq -r .mode <<<"$FRESH_RESULT")" == portable-fallback ]]
ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$KEY" root@172.30.1.2 \
  'test -f /workspace/native-marker.txt && test -s /workspace/.abra/recipes.json'
test -s "$FRESH_ROOT/firecracker/config.json"
"$ABRA_FC" --root "$FRESH_ROOT" down --slot 1

"$ABRA_FC" --root "$RUN_ROOT" down --slot 0
printf '%s\n' '{"os":"linux","arch":"x86_64","hypervisor":"firecracker","snapshot_format_major":999,"cpu_template":"-","cpu_identity":"lying-cache"}' > "$RUN_ROOT/firecracker/fingerprint.json"
RESTORE_RESULT="$("$ABRA_FC" --root "$RUN_ROOT" --firecracker "$FC" --ssh-key "$KEY" restore --slot 0 --capsule "$CAPSULE" --snapshot "$NATIVE_SNAPSHOT")"
RESTORE_MS="$(jq -r .restore_ms <<<"$RESTORE_RESULT")"
[[ "$(jq -r .mode <<<"$RESTORE_RESULT")" == native ]]
guest "test -f /workspace/native-marker.txt; test -r /proc/$MARKER_PID/stat; test \"\$(awk '{print \$22}' /proc/$MARKER_PID/stat)\" = '$MARKER_START'"
curl -sf --noproxy '*' http://172.30.0.2:8123/native-marker.txt | grep -qx native-marker

"$ABRA_FC" --root "$RUN_ROOT" down --slot 0
FAKE='{"os":"linux","arch":"x86_64","hypervisor":"firecracker","snapshot_format_major":999,"cpu_template":"-","cpu_identity":"fake"}'
FALLBACK_RESULT="$(ABRA_FC_FAKE_FINGERPRINT="$FAKE" "$ABRA_FC" --root "$RUN_ROOT" --firecracker "$FC" --ssh-key "$KEY" restore --slot 1 --capsule "$CAPSULE" --snapshot "$NATIVE_SNAPSHOT")"
[[ "$(jq -r .mode <<<"$FALLBACK_RESULT")" == portable-fallback ]]
ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$KEY" root@172.30.1.2 test -f /workspace/native-marker.txt
ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$KEY" root@172.30.1.2 "! pgrep -f '[p]ython3 -m http.server 8123' >/dev/null"

"$ABRA_FC" --root "$RUN_ROOT" down --slot 1
cleanup
[[ -z "$(pgrep -x firecracker 2>/dev/null || true)" ]]
! ip link show osdtap0 >/dev/null 2>&1
! ip link show osdtap1 >/dev/null 2>&1

jq -n \
  --arg capsule "$CAPSULE" --arg snapshot "$NATIVE_SNAPSHOT" --arg portable "$PORTABLE_SNAPSHOT" \
  --argjson total_ms "$(( $(now_ms) - STARTED ))" --argjson up_ms "$UP_MS" \
  --argjson snapshot_ms "$SNAPSHOT_MS" --argjson restore_ms "$RESTORE_MS" \
  --argjson native "$(jq -c .native "$MANIFEST")" \
  --argjson rich_image_tools "$RICH_IMAGE_TOOLS" \
  --argjson second_device_native "$SECOND_DEVICE_NATIVE" \
  '{ok:true,capsule:$capsule,portable_snapshot:$portable,native_snapshot:$snapshot,timings_ms:{total:$total_ms,up:$up_ms,snapshot:$snapshot_ms,native_restore:$restore_ms},native:$native,checks:{token_file_root_0600:true,token_absent_from_cmdline_and_logs:true,enrollment:true,transfer:true,native_manifest:true,cached_fingerprint_ignored:true,same_pid:true,same_starttime:true,http_after_resume:true,portable_fallback:true,fallback_marker_process_absent:true,second_device_transfer:true,second_device_files:true,second_device_recipes:true,native_transfer:$second_device_native,second_root_native_restore:$second_device_native,fresh_root_config:true,fresh_host_portable_fallback:true,zero_firecracker_processes:true,zero_taps:true,rich_image_tools:$rich_image_tools}}' | tee "$REPORT"
