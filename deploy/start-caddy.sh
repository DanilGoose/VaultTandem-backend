#!/bin/sh
set -eu
export PUBLIC_IPV4 ACME_EMAIL

config=$(mktemp)
cat /etc/vaulttandem/Caddyfile > "$config"
if [ -n "${SYNC_DOMAIN:-}" ]; then
  case "$SYNC_DOMAIN" in
    *[!A-Za-z0-9.-]*) echo 'Invalid SYNC_DOMAIN' >&2; exit 1;;
  esac
  printf '\nhttps://%s {\n\timport sync_backend\n}\n' "$SYNC_DOMAIN" >> "$config"
fi
exec caddy run --config "$config" --adapter caddyfile
