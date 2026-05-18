#!/bin/sh
set -eu

AUTH_DELAY_MS="${AUTH_DELAY_MS:-5000}"
AUTH_DELAY_IFACE="${AUTH_DELAY_IFACE:-eth0}"
: "${DNS_PORT:?missing DNS_PORT}"
: "${REAL_WEB_IP:?missing REAL_WEB_IP}"
: "${AUTH_IP:?missing AUTH_IP}"
export DNS_PORT REAL_WEB_IP AUTH_IP

envsubst '${DNS_PORT}' \
    < /etc/bind/named.conf.template \
    > /etc/bind/named.conf

envsubst '${REAL_WEB_IP} ${AUTH_IP}' \
    < /etc/bind/bank.test.zone.template \
    > /etc/bind/bank.test.zone

: > /etc/bind/named.conf.zones

if command -v tc >/dev/null 2>&1; then
    tc qdisc del dev "$AUTH_DELAY_IFACE" root 2>/dev/null || true
    tc qdisc add dev "$AUTH_DELAY_IFACE" root netem delay "${AUTH_DELAY_MS}ms"
fi

exec named -g -c /etc/bind/named.conf -u bind
