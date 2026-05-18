#!/bin/sh
set -e

: "${DNS_PORT:?missing DNS_PORT}"
: "${AUTH_IP:?missing AUTH_IP}"
: "${EXTERNAL_AUTH_IP:?missing EXTERNAL_AUTH_IP}"
: "${RESOLVER_ATTACK_UDP_PORT:?missing RESOLVER_ATTACK_UDP_PORT}"
export DNS_PORT AUTH_IP EXTERNAL_AUTH_IP RESOLVER_ATTACK_UDP_PORT

envsubst '${DNS_PORT} ${AUTH_IP} ${EXTERNAL_AUTH_IP} ${RESOLVER_ATTACK_UDP_PORT}' \
    < /etc/bind/named.conf.template \
    > /etc/bind/named.conf

python3 /listener.py &
exec named -g -c /etc/bind/named.conf -u bind
