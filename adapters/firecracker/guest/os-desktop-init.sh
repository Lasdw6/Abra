#!/bin/sh
set -eu

# Firecracker starts this as PID 1 (init=/usr/local/bin/os-desktop-init.sh).
# Mount the pseudo filesystems, make sure sshd has host keys, then hand PID 1
# to the image's systemd, which starts cadabra.service and abra-observer.service.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /dev/pts /dev/shm /run /run/lock /run/sshd
mount -t devpts devpts /dev/pts 2>/dev/null || true
mount -t tmpfs tmpfs /dev/shm 2>/dev/null || true
chmod 1777 /tmp /dev/shm

/usr/bin/ssh-keygen -A
exec /sbin/init "$@"
