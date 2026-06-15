FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates pdns-server pdns-backend-sqlite3 sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY pdns-entrypoint.sh /usr/local/bin/pdns-entrypoint.sh
RUN chmod +x /usr/local/bin/pdns-entrypoint.sh

EXPOSE 53/tcp 53/udp 8081/tcp

ENTRYPOINT ["/usr/local/bin/pdns-entrypoint.sh"]
