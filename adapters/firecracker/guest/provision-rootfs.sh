#!/usr/bin/env bash
set -euo pipefail

if [[ ${ABRA_PROVISION_PRIVATE_NS:-0} != 1 ]]; then
  exec env ABRA_PROVISION_PRIVATE_NS=1 unshare --mount --pid --fork --propagation private -- "$0" "$@"
fi

if [[ $# -lt 2 || $# -gt 4 ]]; then
  echo "usage: sudo $0 ROOTFS_EXT4 ABRA_BIN [CADABRA_BIN [BROWSER_SESSION_DIR]]" >&2
  exit 2
fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "provision-rootfs.sh must run as root (loop mount required)" >&2
  exit 1
fi

ROOTFS="$(realpath "$1")"
ABRA_BIN="$(realpath "$2")"
CADABRA_BIN="$(realpath "${3:-$2}")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(realpath "$SCRIPT_DIR/../../..")"
BROWSER_SESSION_DIR="$(realpath "${4:-$REPO_ROOT/adapters/browser-session}")"
ROOTFS_SIZE="${ABRA_GUEST_ROOTFS_SIZE:-4G}"
CODEX_PACKAGE="${ABRA_CODEX_PACKAGE:-@openai/codex}"

for path in "$ROOTFS" "$ABRA_BIN" "$CADABRA_BIN" \
            "$BROWSER_SESSION_DIR/abra-adapter.json"; do
  [[ -e "$path" ]] || { echo "missing prerequisite: $path" >&2; exit 1; }
done
for command in chroot e2fsck mknod mount mountpoint numfmt resize2fs truncate unshare; do
  command -v "$command" >/dev/null || { echo "missing host command: $command" >&2; exit 1; }
done

current_size="$(stat -c %s "$ROOTFS")"
target_size="$(numfmt --from=iec "$ROOTFS_SIZE")"
if (( current_size < target_size )); then
  truncate -s "$ROOTFS_SIZE" "$ROOTFS"
  set +e
  e2fsck -pf "$ROOTFS"
  check_status=$?
  set -e
  if (( check_status > 2 )); then
    echo "e2fsck failed with status $check_status" >&2
    exit "$check_status"
  fi
  resize2fs "$ROOTFS"
fi

MOUNT_DIR="$(mktemp -d)"
RESOLV_BACKUP=""
RESOLV_INSTALLED=0
mounted=()
validate_guest_resolver() {
  local path="$1" target resolved
  if [[ -L "$path" ]]; then
    target="$(readlink "$path")"
    if [[ "$target" == /* ]]; then
      resolved="$(realpath -m -- "$MOUNT_DIR/${target#/}")"
    else
      resolved="$(realpath -m -- "$(dirname "$path")/$target")"
    fi
    if [[ "$resolved" != "$MOUNT_DIR"/* ]]; then
      echo "refusing guest resolver symlink that escapes the image: ${path#"$MOUNT_DIR"} -> $target" >&2
      return 1
    fi
    return 0
  fi
  if [[ -e "$path" && ! -f "$path" ]]; then
    echo "guest resolver path is not a regular file: ${path#"$MOUNT_DIR"}" >&2
    return 1
  fi
}
validate_guest_paths() {
  local name path
  for name in etc dev proc sys; do
    path="$MOUNT_DIR/$name"
    if [[ -L "$path" ]]; then
      echo "refusing symlinked guest path: /$name" >&2
      return 1
    fi
    if [[ -e "$path" && ! -d "$path" ]]; then
      echo "guest path is not a directory: /$name" >&2
      return 1
    fi
  done
  [[ -d "$MOUNT_DIR/etc" ]] || { echo "guest image lacks /etc" >&2; return 1; }
  for name in resolv.conf resolv.conf.abra-build; do
    path="$MOUNT_DIR/etc/$name"
    validate_guest_resolver "$path" || return 1
  done
}
cleanup() {
  local allow_lazy="${1:-1}" failed=0 paths_safe=1
  if mountpoint -q "$MOUNT_DIR" && ! validate_guest_paths; then
    paths_safe=0
    failed=1
  fi
  if [[ "$paths_safe" == 1 && "$RESOLV_INSTALLED" == 1 ]]; then
    rm -f "$MOUNT_DIR/etc/resolv.conf" || failed=1
    RESOLV_INSTALLED=0
  fi
  if [[ "$paths_safe" == 1 && -n "$RESOLV_BACKUP" && ( -e "$RESOLV_BACKUP" || -L "$RESOLV_BACKUP" ) ]]; then
    mv "$RESOLV_BACKUP" "$MOUNT_DIR/etc/resolv.conf" || failed=1
    RESOLV_BACKUP=""
  fi
  for ((index=${#mounted[@]}-1; index>=0; index--)); do
    if mountpoint -q "${mounted[index]}" && ! umount "${mounted[index]}"; then
      echo "failed to unmount ${mounted[index]}" >&2
      failed=1
      if [[ "$allow_lazy" == 1 ]]; then
        umount -l "${mounted[index]}" 2>/dev/null || true
      fi
    fi
  done
  rmdir "$MOUNT_DIR" 2>/dev/null || failed=1
  return "$failed"
}
on_exit() {
  local status=$?
  trap - EXIT
  cleanup 1 || true
  exit "$status"
}
trap on_exit EXIT

mount -o loop,nodev,nosuid "$ROOTFS" "$MOUNT_DIR"
mounted+=("$MOUNT_DIR")
validate_guest_paths
if [[ ! -f "$MOUNT_DIR/etc/debian_version" ]]; then
  echo "guest image must be Debian or Ubuntu" >&2
  exit 1
fi
if [[ ! -x "$MOUNT_DIR/usr/bin/setpriv" || -L "$MOUNT_DIR/usr/bin/setpriv" ]]; then
  echo "guest image lacks a regular executable /usr/bin/setpriv" >&2
  exit 1
fi

for directory in dev proc sys; do
  mkdir -p "$MOUNT_DIR/$directory"
done
mount -t tmpfs -o mode=0755,nosuid,noexec tmpfs "$MOUNT_DIR/dev"
mounted+=("$MOUNT_DIR/dev")
mkdir -p "$MOUNT_DIR/dev/pts"
mount -t devpts -o newinstance,ptmxmode=0666,mode=0620,gid=5 devpts "$MOUNT_DIR/dev/pts"
mounted+=("$MOUNT_DIR/dev/pts")
for device in 'null 1 3' 'zero 1 5' 'random 1 8' 'urandom 1 9'; do
  read -r name major minor <<<"$device"
  mknod -m 0666 "$MOUNT_DIR/dev/$name" c "$major" "$minor"
done
ln -s pts/ptmx "$MOUNT_DIR/dev/ptmx"
ln -s /proc/self/fd "$MOUNT_DIR/dev/fd"
ln -s /proc/self/fd/0 "$MOUNT_DIR/dev/stdin"
ln -s /proc/self/fd/1 "$MOUNT_DIR/dev/stdout"
ln -s /proc/self/fd/2 "$MOUNT_DIR/dev/stderr"
mount -t proc -o ro,nosuid,nodev,noexec proc "$MOUNT_DIR/proc"
mounted+=("$MOUNT_DIR/proc")
mount -t sysfs -o ro,nosuid,nodev,noexec sysfs "$MOUNT_DIR/sys"
mounted+=("$MOUNT_DIR/sys")

if [[ -e "$MOUNT_DIR/etc/resolv.conf" || -L "$MOUNT_DIR/etc/resolv.conf" ]]; then
  RESOLV_BACKUP="$MOUNT_DIR/etc/resolv.conf.abra-build"
  [[ ! -e "$RESOLV_BACKUP" && ! -L "$RESOLV_BACKUP" ]] || {
    echo "temporary resolver backup already exists in guest image" >&2
    exit 1
  }
  mv "$MOUNT_DIR/etc/resolv.conf" "$RESOLV_BACKUP"
fi
install -m 0644 /etc/resolv.conf "$MOUNT_DIR/etc/resolv.conf"
RESOLV_INSTALLED=1

PROVISION_CAPS='-all,+chown,+dac_override,+dac_read_search,+fowner,+fsetid,+kill,+setgid,+setuid,+setpcap,+audit_write,+setfcap'
chroot "$MOUNT_DIR" /usr/bin/setpriv --bounding-set="$PROVISION_CAPS" \
  --inh-caps=-all --ambient-caps=-all /usr/bin/env -i \
  HOME=/root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  DEBIAN_FRONTEND=noninteractive ABRA_CODEX_PACKAGE="$CODEX_PACKAGE" \
  /bin/bash -s <<'CHROOT'
set -euo pipefail

if [[ "$(dpkg --print-architecture)" != amd64 ]]; then
  echo "Google Chrome guest provisioning currently requires an amd64 image" >&2
  exit 1
fi

dangerous_caps=$(( (1 << 10) | (1 << 12) | (1 << 16) | (1 << 17) | (1 << 18) | (1 << 19) | (1 << 21) | (1 << 27) ))
for field in CapEff CapBnd; do
  value="$(awk -v field="$field:" '$1 == field { print $2 }' /proc/self/status)"
  if (( (16#$value & dangerous_caps) != 0 )); then
    echo "package chroot retains dangerous capabilities in $field" >&2
    exit 1
  fi
done

policy_created=0
if [[ ! -e /usr/sbin/policy-rc.d ]]; then
  printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
  chmod 0755 /usr/sbin/policy-rc.d
  policy_created=1
fi
cleanup_chroot() {
  rm -f /tmp/google-chrome.asc /tmp/google-chrome.gpg /tmp/nodesource.gpg
  if [[ "$policy_created" == 1 ]]; then
    rm -f /usr/sbin/policy-rc.d
  fi
}
trap cleanup_chroot EXIT

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl gnupg
install -d -m 0755 /usr/share/keyrings

curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
  | gpg --dearmor --yes -o /tmp/nodesource.gpg
install -m 0644 /tmp/nodesource.gpg /usr/share/keyrings/nodesource.gpg
printf '%s\n' \
  'deb [arch=amd64 signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main' \
  > /etc/apt/sources.list.d/nodesource.list

curl -fsSL https://dl.google.com/linux/linux_signing_key.pub -o /tmp/google-chrome.asc
google_primary_fingerprints="$(gpg --batch --show-keys --with-colons /tmp/google-chrome.asc \
  | awk -F: '$1 == "pub" { primary=1; next } $1 == "fpr" && primary { print $10; primary=0 }')"
grep -qx 'EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796' <<<"$google_primary_fingerprints"
while read -r fingerprint; do
  case "$fingerprint" in
    EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796|4CCA1EAF950CEE4AB83976DCA040830F7FAC5991) ;;
    *) echo "unexpected Google signing-key fingerprint: $fingerprint" >&2; exit 1 ;;
  esac
done <<<"$google_primary_fingerprints"
gpg --batch --dearmor --yes -o /tmp/google-chrome.gpg /tmp/google-chrome.asc
install -m 0644 /tmp/google-chrome.gpg /usr/share/keyrings/google-chrome.gpg
printf '%s\n' \
  'deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main' \
  > /etc/apt/sources.list.d/google-chrome.list

apt-get update
apt-get install -y --no-install-recommends nodejs google-chrome-stable
NPM_CONFIG_USERCONFIG=/dev/null NPM_CONFIG_UPDATE_NOTIFIER=false \
  npm install --global --omit=dev --no-audit --no-fund "$ABRA_CODEX_PACKAGE"

node_version="$(node --version)"
[[ "$node_version" == v22.* ]] || { echo "expected Node 22, got $node_version" >&2; exit 1; }
google-chrome --version
codex --version

apt-get clean
rm -rf /var/lib/apt/lists/* /root/.npm
CHROOT

if ! cleanup 0; then
  echo "rootfs cleanup was incomplete; refusing to run install-rootfs.sh" >&2
  exit 1
fi
trap - EXIT
exec env ABRA_INSTALL_PRIVATE_NS=1 "$SCRIPT_DIR/install-rootfs.sh" \
  "$ROOTFS" "$ABRA_BIN" "$CADABRA_BIN" "$BROWSER_SESSION_DIR"
