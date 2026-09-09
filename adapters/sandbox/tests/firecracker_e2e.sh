#!/usr/bin/env bash
# Coordinator flow on a Linux KVM host: two Firecracker guests via abra-fc, two
# Abra roots on the host, ssh driver. Guest A runs an HTTP fixture (and, with a
# rich image, headless Chrome holding a test cookie). Root A captures it, sends
# to root B, and root B restores into guest B, starting the HTTP candidate
# explicitly. Same slot/TAP ownership and cleanup rules as
# adapters/firecracker/tests/e2e.sh.
#
# Env: FIRECRACKER_ROOTFS points at a prebuilt image and skips provisioning.
# ABRA_FC_E2E_RICH_IMAGE=1 enables the browser half (needs node + Chrome in the
# guest, which provision-rootfs.sh installs). Without FIRECRACKER_ROOTFS the
# script builds the image from FIRECRACKER_BASE_ROOTFS like the abra-fc suite.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ABRA="${ABRA_BIN:-$REPO_ROOT/target/release/abra}"
ABRA_FC="${ABRA_FC_BIN:-$REPO_ROOT/target/release/abra-fc}"
COORDINATOR="$REPO_ROOT/adapters/sandbox/bin/abra-sandbox"
ADAPTER_DIR="$REPO_ROOT/adapters/browser-session"
FC="${FIRECRACKER_BIN:-/usr/local/bin/firecracker}"
ARTIFACTS="${FIRECRACKER_ARTIFACT_DIR:-/home/ubuntu/paperplanes/artifacts/firecracker}"
KERNEL="${FIRECRACKER_KERNEL:-$ARTIFACTS/vmlinux}"
BASE_ROOTFS="${FIRECRACKER_BASE_ROOTFS:-$ARTIFACTS/rootfs-headless-base.ext4}"
KEY="${FIRECRACKER_SSH_KEY:-$ARTIFACTS/desktop_id_rsa}"
KNOWN_HOSTS="${FIRECRACKER_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
RICH="${ABRA_FC_E2E_RICH_IMAGE:-0}"
RUN_ROOT="${ABRA_SANDBOX_E2E_ROOT:-/home/ubuntu/.abra-sandbox-e2e}"
ROOT_A="$RUN_ROOT/root-a"
ROOT_B="$RUN_ROOT/root-b"
REPORT="${ABRA_SANDBOX_E2E_REPORT:-$REPO_ROOT/adapters/sandbox/tests/e2e-report.json}"
GUEST_A=172.30.0.2
GUEST_B=172.30.1.2
MEM=512
[[ "$RICH" != 1 ]] || MEM=2048
NAME="fc-e2e"
COOKIE="abra-cookie-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
LOCAL_VALUE="abra-local-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
BROWSER_RESULT=null

if pgrep -x firecracker >/dev/null 2>&1 \
  || ip link show osdtap0 >/dev/null 2>&1 \
  || ip link show osdtap1 >/dev/null 2>&1; then
  echo "sandbox e2e requires an idle host: existing VMs or test TAPs found" >&2
  exit 1
fi

cleanup() {
  "$ABRA_FC" --root "$RUN_ROOT" down --slot 0 >/dev/null 2>&1 || true
  "$ABRA_FC" --root "$RUN_ROOT" down --slot 1 >/dev/null 2>&1 || true
  "$ABRA" --root "$ROOT_A" stop >/dev/null 2>&1 || true
  "$ABRA" --root "$ROOT_B" stop >/dev/null 2>&1 || true
  for tap in osdtap0 osdtap1; do sudo ip link del "$tap" >/dev/null 2>&1 || true; done
  while read -r pid; do
    [[ -r "/proc/$pid/cmdline" ]] || continue
    tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "$RUN_ROOT" && sudo kill "$pid" 2>/dev/null || true
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
  local ip="$1"; shift
  ssh -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=\"$KNOWN_HOSTS\"" -o BatchMode=yes -i "$KEY" "root@$ip" "$@"
}
coordinator() {
  local root="$1" ip="$2"; shift 2
  python3 "$COORDINATOR" "$@" --driver ssh --driver-opt "host=$ip" --driver-opt user=root --driver-opt "key=$KEY" \
    --driver-opt "known_hosts=$KNOWN_HOSTS" \
    --name "$NAME" --remote-workspace /workspace --abra "$ABRA" --abra-root "$root" --json
}
push_fixture() {
  tar -C "$ADAPTER_DIR" -cf - bin lib | guest "$1" 'rm -rf /tmp/abra-fixture && mkdir -p /tmp/abra-fixture && tar -C /tmp/abra-fixture -xf -'
}
start_chrome() {
  guest "$1" 'set -eu
    google-chrome --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage --no-first-run \
      --user-data-dir=/tmp/abra-chrome --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 \
      about:blank >/tmp/abra-chrome.log 2>&1 </dev/null &
    for _ in $(seq 1 200); do curl -fsS http://127.0.0.1:9222/json/version >/dev/null 2>&1 && exit 0; sleep .1; done
    echo "chrome CDP did not come up" >&2; exit 1'
}
cdp_url() { guest "$1" "curl -fsS http://127.0.0.1:9222/json/version" | jq -r .webSocketDebuggerUrl; }

for path in "$ABRA" "$ABRA_FC" "$FC" "$KERNEL" "$KEY" "$COORDINATOR"; do
  [[ -e "$path" ]] || { echo "missing prerequisite: $path" >&2; exit 1; }
done
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
"$ABRA_FC" --root "$RUN_ROOT" down --slot 0 >/dev/null 2>&1 || true
"$ABRA_FC" --root "$RUN_ROOT" down --slot 1 >/dev/null 2>&1 || true
rm -rf "$RUN_ROOT"
mkdir -p "$RUN_ROOT" "$ROOT_A" "$ROOT_B" "$(dirname "$REPORT")"
chmod 0700 "$RUN_ROOT" "$ROOT_A" "$ROOT_B"
STARTED="$(now_ms)"

# Image: prebuilt, or built here the way the abra-fc suite builds it.
if [[ -n "${FIRECRACKER_ROOTFS:-}" ]]; then
  ROOTFS="$FIRECRACKER_ROOTFS"
  IMAGE_SOURCE="prebuilt"
else
  [[ -e "$BASE_ROOTFS" ]] || { echo "missing prerequisite: $BASE_ROOTFS" >&2; exit 1; }
  (cd "$REPO_ROOT" && cargo build --release --target x86_64-unknown-linux-musl -p abra-cli >/dev/null)
  MUSL="$REPO_ROOT/target/x86_64-unknown-linux-musl/release"
  ROOTFS="$RUN_ROOT/rootfs.ext4"
  cp -f "$BASE_ROOTFS" "$ROOTFS"
  if [[ "$RICH" == 1 ]]; then
    sudo -E bash "$REPO_ROOT/adapters/firecracker/guest/provision-rootfs.sh" "$ROOTFS" "$MUSL/abra" >/dev/null
    IMAGE_SOURCE="provision-rootfs.sh"
  else
    sudo bash "$REPO_ROOT/adapters/firecracker/guest/install-rootfs.sh" "$ROOTFS" "$MUSL/abra" >/dev/null
    IMAGE_SOURCE="install-rootfs.sh"
  fi
fi
[[ -e "$ROOTFS" ]] || { echo "missing rootfs: $ROOTFS" >&2; exit 1; }

UP_STARTED="$(now_ms)"
"$ABRA_FC" --root "$RUN_ROOT" --firecracker "$FC" --ssh-key "$KEY" up --slot 0 --rootfs "$ROOTFS" --kernel "$KERNEL" --mem "$MEM" --vcpus 1 >"$RUN_ROOT/up-0.json"
"$ABRA_FC" --root "$RUN_ROOT" --firecracker "$FC" --ssh-key "$KEY" up --slot 1 --rootfs "$ROOTFS" --kernel "$KERNEL" --mem "$MEM" --vcpus 1 >"$RUN_ROOT/up-1.json"
UP_MS="$(( $(now_ms) - UP_STARTED ))"
guest "$GUEST_A" 'python3 --version >/dev/null && command -v tar >/dev/null'
guest "$GUEST_B" 'python3 --version >/dev/null && command -v tar >/dev/null'
if [[ "$RICH" == 1 ]]; then
  guest "$GUEST_A" "node --version | grep -q '^v22\\.'; google-chrome --version >/dev/null"
fi

# Two Abra roots on the host, paired.
"$ABRA" --root "$ROOT_A" daemon --background --yes --adapters "$REPO_ROOT/adapters" >/dev/null
"$ABRA" --root "$ROOT_B" daemon --background --yes --adapters "$REPO_ROOT/adapters" >/dev/null
TICKET_B="$("$ABRA" --root "$ROOT_B" pair ticket)"
"$ABRA" --root "$ROOT_A" pair add "$TICKET_B" >/dev/null
PEER_B="$("$ABRA" --root "$ROOT_B" --json status | jq -r .peer_id)"

# Guest A: workspace, HTTP fixture, optional browser state.
guest "$GUEST_A" "mkdir -p /workspace/src; printf 'fc-marker\n' > /workspace/marker.txt; printf 'print(1)\n' > /workspace/src/app.py; cd /workspace; nohup python3 -m http.server 8123 --bind 127.0.0.1 >/tmp/abra-marker.log 2>&1 </dev/null &"
wait_until "http fixture in guest A" guest "$GUEST_A" "curl -fsS http://127.0.0.1:8123/marker.txt | grep -qx fc-marker"
CAPTURE_ARGS=()
if [[ "$RICH" == 1 ]]; then
  start_chrome "$GUEST_A"
  push_fixture "$GUEST_A"
  guest "$GUEST_A" "node /tmp/abra-fixture/bin/cdp-fixture.mjs set --cdp '$(cdp_url "$GUEST_A")' --url http://127.0.0.1:8123/marker.txt --cookie 'sid=$COOKIE' --local 'abra=$LOCAL_VALUE'" \
    | jq -e '.cookies == ["sid"]' >/dev/null
  CAPTURE_ARGS=(--browser-port 9222)
fi

CAPTURE_STARTED="$(now_ms)"
CAPTURED="$(coordinator "$ROOT_A" "$GUEST_A" capture --membership all ${CAPTURE_ARGS[@]+"${CAPTURE_ARGS[@]}"})"
CAPTURE_MS="$(( $(now_ms) - CAPTURE_STARTED ))"
printf '%s\n' "$CAPTURED" > "$RUN_ROOT/capture.json"
SNAPSHOT="$(jq -r .snapshot_id <<<"$CAPTURED")"
CAPSULE="$(jq -r .capsule_id <<<"$CAPTURED")"
BARRIER="$(jq -r .observation_barrier <<<"$CAPTURED")"
MIRROR="$(jq -r .mirror <<<"$CAPTURED")"
MANIFEST="$ROOT_A/capsules/$CAPSULE/snapshots/$SNAPSHOT.cjson"
jq -e --arg barrier "$BARRIER" '.extensions["dev.abra.observed"] | .schema == "dev.abra.observed/3" and .observer.barrier == $barrier and .observer.mode == "once" and .coverage.scope == "all"' "$MANIFEST" >/dev/null
jq -e --arg host "$GUEST_A" '.extensions["dev.abra.observed"].host.facts | .provider == "ssh" and .host == $host and .native == null' "$MANIFEST" >/dev/null
jq -e '.recipes[] | select(.ports | index(8123))' "$MANIFEST" >/dev/null
jq -e '.extensions["dev.abra.observed"].service_candidates[] | select(.recipe.ports | index(8123)) | .restartability == "unverified"' "$MANIFEST" >/dev/null
CANDIDATE_INDEX="$(jq -r '[.extensions["dev.abra.observed"].service_candidates[] | .recipe.ports // [] | index(8123) != null] | index(true)' "$MANIFEST")"
[[ "$CANDIDATE_INDEX" != null ]]
grep -qx fc-marker "$MIRROR/marker.txt"
test -f "$MIRROR/src/app.py"
test -f "$MIRROR/.abra/capsule_id"
test ! -e "$MIRROR/.abra/observed-$BARRIER.json"
guest "$GUEST_A" "test ! -e /workspace/.abra/observed-$BARRIER.json; test -z \"\$(ls -d /tmp/abra-collector-* /tmp/abra-browser-* /tmp/abra-runner-* 2>/dev/null)\"; test -z \"\$(find /tmp /workspace -maxdepth 3 -type f -name abra)\""
if [[ "$RICH" == 1 ]]; then
  jq -e '.browser.fingerprint != null and (.browser.domains | index("127.0.0.1"))' <<<"$CAPTURED" >/dev/null
  BUNDLE_A="$(jq -r .browser.bundle <<<"$CAPTURED")"
  ! grep -rl --exclude-dir='browser-*' -e "$COOKIE" -e "$LOCAL_VALUE" "$ROOT_A" >/dev/null
fi

# Transfer to root B: the workspace snapshot and, with a browser, the bundle.
TRANSFER_STARTED="$(now_ms)"
"$ABRA" --root "$ROOT_A" --json send "$PEER_B" --snapshot "$SNAPSHOT" --wait --timeout 180s | jq -e '.entry.state == "acked"' >/dev/null
BUNDLE_B=""
if [[ "$RICH" == 1 ]]; then
  BUNDLE_SNAPSHOT="$("$ABRA" --root "$ROOT_A" --json send "$PEER_B" --kind dev.abra.browser.session.v1 --source "bundle:$BUNDLE_A" --wait --timeout 180s | jq -r .snapshot_id)"
  BUNDLE_B="$ROOT_B/browser-bundle"
  "$ABRA" --root "$ROOT_B" accept "$BUNDLE_SNAPSHOT" "$BUNDLE_B" --no-import >/dev/null
  test -f "$BUNDLE_B/manifest.json"
fi
TRANSFER_MS="$(( $(now_ms) - TRANSFER_STARTED ))"

# Restore into guest B: files first, nothing started; then the named candidate.
RESTORE_STARTED="$(now_ms)"
PUSHED="$(coordinator "$ROOT_B" "$GUEST_B" restore --snapshot "$SNAPSHOT" --replace-workspace)"
jq -e '.started == []' <<<"$PUSHED" >/dev/null
jq -e --argjson i "$CANDIDATE_INDEX" '.candidates[$i].ports | index(8123)' <<<"$PUSHED" >/dev/null
guest "$GUEST_B" "grep -qx fc-marker /workspace/marker.txt; test -f /workspace/src/app.py; test -s /workspace/.abra/recipes.json; test ! -e /workspace/.abra/capsule_id; ! pgrep -f '[p]ython3 -m http.server 8123' >/dev/null"
RESTORE_ARGS=(--replace-workspace --start "$CANDIDATE_INDEX")
if [[ "$RICH" == 1 ]]; then
  start_chrome "$GUEST_B"
  push_fixture "$GUEST_B"
  RESTORE_ARGS+=(--browser "$BUNDLE_B" --browser-port 9222)
fi
RESTORED="$(coordinator "$ROOT_B" "$GUEST_B" restore --snapshot "$SNAPSHOT" "${RESTORE_ARGS[@]}")"
printf '%s\n' "$RESTORED" > "$RUN_ROOT/restore.json"
RESTORE_MS="$(( $(now_ms) - RESTORE_STARTED ))"
jq -e '.started | length == 1 and .[0].pid > 0' <<<"$RESTORED" >/dev/null
wait_until "http candidate in guest B" guest "$GUEST_B" "curl -fsS http://127.0.0.1:8123/marker.txt | grep -qx fc-marker"
if [[ "$RICH" == 1 ]]; then
  jq -e '.browser.install_id != null' <<<"$RESTORED" >/dev/null
  guest "$GUEST_B" "node /tmp/abra-fixture/bin/cdp-fixture.mjs get --cdp '$(cdp_url "$GUEST_B")' --url http://127.0.0.1:8123/" > "$RUN_ROOT/fixture-b.json"
  jq -e --arg c "$COOKIE" --arg l "$LOCAL_VALUE" '(.cookies | any(.name == "sid" and .value == $c)) and (.local_storage | any(.name == "abra" and .value == $l))' "$RUN_ROOT/fixture-b.json" >/dev/null
  BROWSER_RESULT="$(jq -c '{cookie_present:true,local_storage_present:true,tabs:.tabs}' "$RUN_ROOT/fixture-b.json")"
fi

"$ABRA_FC" --root "$RUN_ROOT" down --slot 0
"$ABRA_FC" --root "$RUN_ROOT" down --slot 1
cleanup
[[ -z "$(pgrep -x firecracker 2>/dev/null || true)" ]]
! ip link show osdtap0 >/dev/null 2>&1
! ip link show osdtap1 >/dev/null 2>&1

jq -n \
  --arg capsule "$CAPSULE" --arg snapshot "$SNAPSHOT" --arg barrier "$BARRIER" --arg image "$IMAGE_SOURCE" \
  --argjson rich "$([[ "$RICH" == 1 ]] && echo true || echo false)" \
  --argjson candidate "$CANDIDATE_INDEX" \
  --argjson total_ms "$(( $(now_ms) - STARTED ))" --argjson up_ms "$UP_MS" --argjson capture_ms "$CAPTURE_MS" \
  --argjson transfer_ms "$TRANSFER_MS" --argjson restore_ms "$RESTORE_MS" \
  --argjson browser "$BROWSER_RESULT" \
  '{ok:true,driver:"ssh",image:$image,rich_image:$rich,capsule:$capsule,snapshot:$snapshot,barrier:$barrier,candidate_index:$candidate,
    timings_ms:{total:$total_ms,up_two_slots:$up_ms,capture:$capture_ms,transfer:$transfer_ms,restore:$restore_ms},
    checks:{barrier_matches:true,scope_all:true,host_facts_ssh:true,recipe_8123:true,candidate_unverified:true,mirror_files:true,
      pinned_ledger_removed:true,sandbox_temp_dirs_removed:true,no_abra_binary_uploaded:true,snapshot_acked:true,
      nothing_started_without_start:true,files_pushed:true,no_capsule_id_pushed:true,candidate_started:true,marker_served_on_b:true,
      cookie_outside_bundle:$rich,bundle_transfer:$rich,zero_firecracker_processes:true,zero_taps:true},
    browser:$browser}' | tee "$REPORT"
