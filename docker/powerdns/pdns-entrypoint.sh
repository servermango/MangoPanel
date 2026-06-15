#!/bin/sh
set -eu

PDNS_DB="${PDNS_DB:-/var/lib/powerdns/pdns.sqlite3}"
PDNS_API_KEY="${PDNS_API_KEY:-mangopanel-dev-pdns}"
SCHEMA_PATH=""

mkdir -p "$(dirname "$PDNS_DB")"

if [ ! -f "$PDNS_DB" ]; then
  for candidate in \
    /usr/share/doc/pdns-backend-sqlite3/schema.sqlite3.sql \
    /usr/share/doc/pdns-backend-sqlite3/schema.sqlite3.sql.gz \
    /usr/share/pdns-backend-sqlite3/schema.sqlite3.sql; do
    if [ -f "$candidate" ]; then
      SCHEMA_PATH="$candidate"
      break
    fi
  done

  if [ -z "$SCHEMA_PATH" ]; then
    echo "PowerDNS SQLite schema not found" >&2
    exit 1
  fi

  case "$SCHEMA_PATH" in
    *.gz) gzip -dc "$SCHEMA_PATH" | sqlite3 "$PDNS_DB" ;;
    *) sqlite3 "$PDNS_DB" < "$SCHEMA_PATH" ;;
  esac
fi

exec pdns_server \
  --guardian=no \
  --daemon=no \
  --launch=gsqlite3 \
  --gsqlite3-database="$PDNS_DB" \
  --local-address=0.0.0.0 \
  --local-port=53 \
  --webserver=yes \
  --webserver-address=0.0.0.0 \
  --webserver-port=8081 \
  --webserver-allow-from=0.0.0.0/0,::/0 \
  --api=yes \
  --api-key="$PDNS_API_KEY" \
  --default-soa-name=ns1.mango.test \
  --default-soa-mail=hostmaster.mango.test
