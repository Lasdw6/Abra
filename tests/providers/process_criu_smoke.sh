#!/usr/bin/env bash
set -euo pipefail

if [[ "${ABRA_RUN_CRIU_SMOKE:-}" != "1" ]]; then
    echo "SKIP: set ABRA_RUN_CRIU_SMOKE=1 to run the CRIU smoke test on a disposable Linux host"
    exit 0
fi
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "ERROR: the CRIU smoke test requires Linux" >&2
    exit 1
fi
prebuilt_abra="${ABRA_PROCESS_SMOKE_ABRA_BIN:-}"
prebuilt_probe="${ABRA_PROCESS_SMOKE_PROBE_BIN:-}"
if { [[ -n "$prebuilt_abra" ]] && [[ -z "$prebuilt_probe" ]]; } \
    || { [[ -z "$prebuilt_abra" ]] && [[ -n "$prebuilt_probe" ]]; }; then
    echo "ERROR: ABRA_PROCESS_SMOKE_ABRA_BIN and ABRA_PROCESS_SMOKE_PROBE_BIN must be set together" >&2
    exit 1
fi

required_commands=(python3 readlink sed)
if [[ -z "$prebuilt_abra" ]]; then
    required_commands+=(cargo)
fi
for command in "${required_commands[@]}"; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "ERROR: required command is missing: $command" >&2
        exit 1
    fi
done

criu_bin="${CRIU_BIN:-criu}"
if ! command -v "$criu_bin" >/dev/null 2>&1 && [[ ! -x "$criu_bin" ]]; then
    echo "ERROR: CRIU is missing; install it or set CRIU_BIN to its executable" >&2
    exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
temp_parent="${TMPDIR:-/tmp}"
temp_parent="$(cd "$temp_parent" && pwd -P)"
run_dir="$(mktemp -d "$temp_parent/abra-criu-smoke.XXXXXX")"
workspace="$run_dir/workspace"
source_workspace="$run_dir/source-workspace"
bundle="$run_dir/bundle"
source_pid=""
restored_pid=""
probe_bin=""

owned_pid() {
    local pid="$1"
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    (( pid > 1 )) || return 1
    [[ -n "$probe_bin" && -e "/proc/$pid/exe" ]] || return 1
    [[ "$(readlink -f "/proc/$pid/exe")" == "$probe_bin" ]]
}

pid_is_zombie() {
    local pid="$1"
    local state
    [[ -r "/proc/$pid/stat" ]] || return 1
    state="$(sed -E 's/^.*\) ([A-Z]) .*$/\1/' "/proc/$pid/stat" 2>/dev/null)" || return 1
    [[ "$state" == "Z" ]]
}

stop_owned_pid() {
    local pid="$1"
    [[ -e "/proc/$pid" ]] || return 0
    if ! owned_pid "$pid"; then
        echo "ERROR: refusing to signal PID $pid because it is not this run's memory_probe" >&2
        return 1
    fi
    kill -TERM "$pid" 2>/dev/null || true
    for _ in {1..50}; do
        [[ -e "/proc/$pid" ]] || return 0
        pid_is_zombie "$pid" && return 0
        sleep 0.1
    done
    if ! owned_pid "$pid"; then
        echo "ERROR: refusing delayed SIGKILL because PID $pid changed identity" >&2
        return 1
    fi
    kill -KILL "$pid" 2>/dev/null || true
    for _ in {1..50}; do
        [[ -e "/proc/$pid" ]] || return 0
        pid_is_zombie "$pid" && return 0
        sleep 0.1
    done
    echo "ERROR: owned PID $pid still exists after SIGKILL" >&2
    return 1
}

cleanup() {
    local status=$?
    if [[ -n "$restored_pid" ]]; then
        stop_owned_pid "$restored_pid" || status=1
    fi
    if [[ -n "$source_pid" ]]; then
        stop_owned_pid "$source_pid" || status=1
        wait "$source_pid" 2>/dev/null || true
    fi

    local executable pid
    shopt -s nullglob
    if [[ -n "$probe_bin" ]]; then
        for executable in /proc/[0-9]*/exe; do
            [[ "$(readlink -f "$executable" 2>/dev/null || true)" == "$probe_bin" ]] || continue
            pid="${executable#/proc/}"
            pid="${pid%/exe}"
            stop_owned_pid "$pid" || status=1
        done
    fi

    if [[ -n "$run_dir" && -d "$run_dir" ]]; then
        local run_parent run_name live_process
        run_parent="$(cd "$(dirname "$run_dir")" && pwd -P)"
        run_name="$(basename "$run_dir")"
        live_process=0
        if [[ -n "$probe_bin" ]]; then
            for executable in /proc/[0-9]*/exe; do
                if [[ "$(readlink -f "$executable" 2>/dev/null || true)" == "$probe_bin" ]]; then
                    live_process=1
                fi
            done
        fi
        if [[ "$live_process" == "1" ]]; then
            echo "ERROR: preserving $run_dir because an owned restored process may still use it" >&2
            status=1
        elif [[ "$run_parent" == "$temp_parent" && "$run_name" == abra-criu-smoke.* ]]; then
            if (( status != 0 )); then
                local failure_dir log saved_log
                failure_dir=""
                for log in "$run_dir"/.abra-criu-*.log; do
                    [[ -f "$log" ]] || continue
                    if [[ -z "$failure_dir" ]]; then
                        failure_dir="$(mktemp -d "$temp_parent/abra-criu-smoke-failure.XXXXXX")"
                        chmod 700 "$failure_dir"
                    fi
                    saved_log="$failure_dir/$run_name-$(basename "$log")"
                    cp -- "$log" "$saved_log"
                    chmod 600 "$saved_log"
                    echo "Preserved private CRIU log: $saved_log" >&2
                done
            fi
            rm -rf -- "$run_dir"
        else
            echo "ERROR: refusing to remove unexpected test path: $run_dir" >&2
            status=1
        fi
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

cd "$repo_root"
if [[ -n "$prebuilt_abra" ]]; then
    for binary in "$prebuilt_abra" "$prebuilt_probe"; do
        if [[ ! -f "$binary" || ! -x "$binary" ]]; then
            echo "ERROR: prebuilt smoke binary is missing or not executable: $binary" >&2
            exit 1
        fi
    done
    abra_bin="$(readlink -f "$prebuilt_abra")"
    source_probe_bin="$(readlink -f "$prebuilt_probe")"
else
    cargo build -p abra-cli
    cargo build -p abra-runtime --example memory_probe
    abra_bin="$repo_root/target/debug/abra"
    source_probe_bin="$repo_root/target/debug/examples/memory_probe"
fi
mkdir -m 700 "$run_dir/bin"
cp -- "$source_probe_bin" "$run_dir/bin/memory_probe"
chmod 700 "$run_dir/bin/memory_probe"
probe_bin="$(readlink -f "$run_dir/bin/memory_probe")"

if ! check_output="$("$abra_bin" --json process check --criu "$criu_bin" 2>&1)"; then
    echo "ERROR: CRIU preflight failed. The host needs a compatible kernel and checkpoint permissions." >&2
    echo "$check_output" >&2
    exit 1
fi

mkdir -m 700 "$workspace"
port="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
(cd "$workspace" && exec "$probe_bin" serve "$port") </dev/null >/dev/null 2>&1 &
source_pid=$!

ready=0
for _ in {1..100}; do
    if "$probe_bin" query "$port" status >"$run_dir/ready.json" 2>/dev/null; then
        ready=1
        break
    fi
    if ! kill -0 "$source_pid" 2>/dev/null; then
        echo "ERROR: memory_probe exited before it became ready" >&2
        exit 1
    fi
    sleep 0.1
done
if [[ "$ready" != "1" ]]; then
    echo "ERROR: memory_probe did not become ready within 10 seconds" >&2
    exit 1
fi

before="$("$probe_bin" query "$port" "advance 40")"
python3 - "$before" <<'PY'
import json, sys
value = json.loads(sys.argv[1])
if value.get("completed") != 40 or value.get("state_storage") != "memory-only":
    raise SystemExit("ERROR: fixture did not reach 40 memory-only tasks: %r" % value)
if len(value.get("nonce", "")) != 64 or len(value.get("digest", "")) != 64:
    raise SystemExit("ERROR: fixture returned an invalid nonce or digest")
PY

if ! capture_output="$("$abra_bin" --json process capture "$source_pid" \
    --workspace "$workspace" --bundle "$bundle" --criu "$criu_bin" 2>&1)"; then
    echo "ERROR: live CRIU capture failed. The backend attempts to resume a verified stopped source." >&2
    echo "$capture_output" >&2
    exit 1
fi

if ! owned_pid "$source_pid"; then
    echo "ERROR: refusing to terminate source PID because its executable identity changed" >&2
    exit 1
fi
kill -KILL "$source_pid"
wait "$source_pid" 2>/dev/null || true
source_pid=""
mv -- "$workspace" "$source_workspace"

if ! plan_output="$("$abra_bin" --json process plan "$bundle" --criu "$criu_bin" 2>&1)"; then
    echo "ERROR: captured bundle failed process restore planning" >&2
    echo "$plan_output" >&2
    exit 1
fi
if ! restore_output="$("$abra_bin" --json process restore "$bundle" --criu "$criu_bin" 2>&1)"; then
    echo "ERROR: live CRIU restore failed" >&2
    echo "$restore_output" >&2
    exit 1
fi
restored_pid="$(python3 - "$restore_output" <<'PY'
import json, sys
value = json.loads(sys.argv[1])
pid = value.get("restored_pid")
if not isinstance(pid, int) or pid <= 1:
    raise SystemExit("ERROR: restore returned an invalid PID: %r" % value)
print(pid)
PY
)"

after=""
for _ in {1..100}; do
    if after="$("$probe_bin" query "$port" status 2>/dev/null)"; then
        break
    fi
    [[ -e "/proc/$restored_pid" ]] || {
        echo "ERROR: restored memory_probe exited before answering" >&2
        exit 1
    }
    sleep 0.1
done
if [[ -z "$after" ]]; then
    echo "ERROR: restored memory_probe did not answer within 10 seconds" >&2
    exit 1
fi

python3 - "$before" "$after" "$restored_pid" <<'PY'
import json, sys
before, after = map(json.loads, sys.argv[1:3])
restored_pid = int(sys.argv[3])
for field in ("nonce", "digest", "completed", "state_storage"):
    if after.get(field) != before.get(field):
        raise SystemExit("ERROR: restored %s changed: before=%r after=%r" % (field, before, after))
if after.get("completed") != 40 or after.get("pid") != restored_pid:
    raise SystemExit("ERROR: restored fixture has the wrong task count or PID: %r" % after)
PY

advanced="$("$probe_bin" query "$port" "advance 60")"
status="$("$probe_bin" query "$port" status)"
python3 - "$before" "$advanced" "$status" <<'PY'
import json, sys
before, advanced, status = map(json.loads, sys.argv[1:4])
if advanced.get("completed") != 100:
    raise SystemExit("ERROR: restored fixture did not advance to 100 tasks: %r" % advanced)
if advanced.get("nonce") != before.get("nonce"):
    raise SystemExit("ERROR: restored fixture nonce changed after advancing")
if advanced.get("digest") == before.get("digest"):
    raise SystemExit("ERROR: restored fixture digest did not change after advancing")
for field in ("nonce", "digest", "completed", "pid", "state_storage"):
    if status.get(field) != advanced.get(field):
        raise SystemExit("ERROR: status after advancing changed field %s" % field)
PY

echo "PASS: CRIU restored the memory-only nonce and 40-task digest, then advanced to 100 tasks"
