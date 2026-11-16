#!/bin/sh
set -eu

issue() {
  certbot certonly --non-interactive --agree-tos --email "$ACME_EMAIL" \
    --webroot -w /var/www/acme "$@"
}

while :; do
  if [ ! -r /etc/letsencrypt/live/xsync-ip/fullchain.pem ]; then
    issue --cert-name xsync-ip --preferred-profile shortlived --ip-address "$PUBLIC_IPV4" || echo 'IP certificate issuance failed' >&2
  fi
  if [ -n "${SYNC_DOMAIN:-}" ]; then
    issue --cert-name xsync-domain --keep-until-expiring -d "$SYNC_DOMAIN" || echo 'Domain certificate update failed' >&2
  fi
  certbot renew --non-interactive || echo 'xSync certificate renewal failed' >&2
  sleep 43200 &
  trap 'kill "$!" 2>/dev/null || true; exit 0' TERM INT
  wait "$!"
done
