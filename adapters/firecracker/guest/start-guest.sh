#!/bin/sh
set -eu

token=""
if [ -s /etc/abra/token ]; then
  token=$(cat /etc/abra/token)
fi
if [ -n "$token" ]; then
  exec /usr/local/bin/abra --root /var/lib/abra daemon --token "$token"
fi
exec /usr/local/bin/abra --root /var/lib/abra daemon
