#!/bin/sh
set -eu

token=""
if [ -s /etc/abra/token ]; then
  token=$(cat /etc/abra/token)
fi
if [ -n "$token" ]; then
  exec /usr/local/bin/cadabra --root /var/lib/abra --token "$token"
fi
exec /usr/local/bin/cadabra --root /var/lib/abra
