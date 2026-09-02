#!/usr/bin/env bash
set -euo pipefail

if [[ ${ABRA_INSTALL_PRIVATE_NS:-0} != 1 ]]; then
  exec env ABRA_INSTALL_PRIVATE_NS=1 unshare --mount --propagation private -- "$0" "$@"
fi

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: sudo $0 ROOTFS_EXT4 ABRA_BIN [CADABRA_BIN]" >&2
  exit 2
fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "install-rootfs.sh must run as root (loop mount required)" >&2
  exit 1
fi

ROOTFS="$(realpath "$1")"
ABRA_BIN="$(realpath "$2")"
CADABRA_BIN="$(realpath "${3:-$2}")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOUNT_DIR="$(mktemp -d)"
cleanup() {
  if mountpoint -q "$MOUNT_DIR"; then
    umount "$MOUNT_DIR" 2>/dev/null || umount -l "$MOUNT_DIR" 2>/dev/null || true
  fi
  rmdir "$MOUNT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

mount -o loop,nodev,nosuid "$ROOTFS" "$MOUNT_DIR"
# The host kernel resolves symlinks inside the mounted image against the HOST
# root, so any symlink on a path we write to could redirect the write outside
# the image. Absolute symlinks are normal inside a guest rootfs (e.g.
# usr/lib64/ld-linux-x86-64.so.2 -> /lib/...), so we do not reject the image;
# we refuse to write through any symlink component on our own destinations.
safe_dest() {
  local rel="${1#"$MOUNT_DIR"/}" cur="$MOUNT_DIR" part
  IFS=/ read -r -a parts <<<"$rel"
  for part in "${parts[@]}"; do
    [[ -z "$part" || "$part" == "." ]] && continue
    [[ "$part" == ".." ]] && { echo "refusing '..' in destination: $rel" >&2; exit 1; }
    cur="$cur/$part"
    if [[ -L "$cur" ]]; then
      echo "refusing to write through symlink in rootfs destination: ${cur#"$MOUNT_DIR"/} -> $(readlink "$cur")" >&2
      exit 1
    fi
  done
}
for dest in usr/local/bin/abra usr/local/bin/cadabra usr/local/libexec/abra-observer \
            usr/local/libexec/abra-start-guest var/lib/abra workspace etc/abra \
            etc/systemd/system/cadabra.service etc/systemd/system/abra-observer.service \
            etc/systemd/system/multi-user.target.wants/cadabra.service \
            etc/systemd/system/multi-user.target.wants/abra-observer.service; do
  safe_dest "$MOUNT_DIR/$dest"
done
install -D -m 0755 "$ABRA_BIN" "$MOUNT_DIR/usr/local/bin/abra"
install -D -m 0755 "$CADABRA_BIN" "$MOUNT_DIR/usr/local/bin/cadabra"
install -D -m 0755 "$SCRIPT_DIR/observer.py" "$MOUNT_DIR/usr/local/libexec/abra-observer"
install -D -m 0755 "$SCRIPT_DIR/start-guest.sh" "$MOUNT_DIR/usr/local/libexec/abra-start-guest"
mkdir -p "$MOUNT_DIR/var/lib/abra" "$MOUNT_DIR/workspace" "$MOUNT_DIR/etc/abra"
chmod 0700 "$MOUNT_DIR/var/lib/abra"

install -D -m 0644 /dev/stdin "$MOUNT_DIR/etc/systemd/system/cadabra.service" <<'EOF'
[Unit]
Description=Abra guest daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/libexec/abra-start-guest
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

install -D -m 0644 /dev/stdin "$MOUNT_DIR/etc/systemd/system/abra-observer.service" <<'EOF'
[Unit]
Description=Abra ambient process observer
After=cadabra.service

[Service]
Type=simple
ExecStart=/usr/local/libexec/abra-observer --workspace /workspace
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

ln -sfn /etc/systemd/system/cadabra.service "$MOUNT_DIR/etc/systemd/system/multi-user.target.wants/cadabra.service"
ln -sfn /etc/systemd/system/abra-observer.service "$MOUNT_DIR/etc/systemd/system/multi-user.target.wants/abra-observer.service"
sync
echo "installed Abra guest payload into $ROOTFS"
