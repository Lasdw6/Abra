#!/bin/sh
set -eu

token=""
for argument in $(cat /proc/cmdline); do
  case "$argument" in
    abra.token=*) token=${argument#abra.token=} ;;
  esac
done
if [ -z "$token" ] && [ -s /etc/abra/token ]; then
  token=$(cat /etc/abra/token)
fi
if [ -n "$token" ]; then
  exec /usr/local/bin/cadabra --root /var/lib/abra --token "$token"
fi
exec /usr/local/bin/cadabra --root /var/lib/abra

