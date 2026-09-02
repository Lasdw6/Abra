#!/usr/bin/env bash
set -euo pipefail

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
  mountpoint -q "$MOUNT_DIR" && umount "$MOUNT_DIR"
  rmdir "$MOUNT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

mount -o loop "$ROOTFS" "$MOUNT_DIR"
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

