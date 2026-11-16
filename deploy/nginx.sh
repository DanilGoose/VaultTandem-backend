#!/bin/sh
set -eu
conf=/etc/nginx/conf.d/default.conf
case "${SYNC_DOMAIN:-}" in *[!A-Za-z0-9.-]*) echo 'Invalid SYNC_DOMAIN' >&2; exit 1;; esac

render() {
  cat <<'HTTP'
map $http_upgrade $xsync_connection {
    default upgrade;
    '' close;
}
server {
    listen 80 default_server;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 404; }
}
HTTP
  if [ -r /etc/letsencrypt/live/xsync-ip/fullchain.pem ]; then
    printf '%s\n' 'server {' '    listen 8443 ssl default_server;' '    server_name _;' \
      '    ssl_certificate /etc/letsencrypt/live/xsync-ip/fullchain.pem;' \
      '    ssl_certificate_key /etc/letsencrypt/live/xsync-ip/privkey.pem;' \
      '    include /deploy/proxy.conf;' '}'
  fi
  if [ -n "${SYNC_DOMAIN:-}" ] && [ -r /etc/letsencrypt/live/xsync-domain/fullchain.pem ]; then
    printf '%s\n' 'server {' '    listen 443 ssl;' "    server_name $SYNC_DOMAIN;" \
      '    ssl_certificate /etc/letsencrypt/live/xsync-domain/fullchain.pem;' \
      '    ssl_certificate_key /etc/letsencrypt/live/xsync-domain/privkey.pem;' \
      '    include /deploy/proxy.conf;' '}'
  fi
}

fingerprint() {
  for name in xsync-ip xsync-domain; do
    file="/etc/letsencrypt/live/$name/fullchain.pem"
    if [ -r "$file" ]; then cksum "$file"; fi
  done
}

render > "$conf"
current=$(fingerprint)
nginx -g 'daemon off;' &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null || true' TERM INT
while kill -0 "$pid" 2>/dev/null; do
  sleep 10 &
  wait "$!" || true
  next=$(fingerprint)
  if [ "$next" != "$current" ]; then
    cp "$conf" /tmp/xsync-nginx.previous
    render > "$conf"
    if nginx -t && nginx -s reload; then
      current=$next
    else
      cp /tmp/xsync-nginx.previous "$conf"
    fi
  fi
done
wait "$pid"
