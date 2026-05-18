#!/bin/sh
set -eu

: "${DNS_PORT:?missing DNS_PORT}"
: "${EXTERNAL_AUTH_IP:?missing EXTERNAL_AUTH_IP}"
: "${EXTERNAL_DOMAIN_SUFFIX:=external.test}"
: "${EXTERNAL_DOMAIN_COUNT:=1001}"
export DNS_PORT EXTERNAL_AUTH_IP EXTERNAL_DOMAIN_SUFFIX EXTERNAL_DOMAIN_COUNT

envsubst '${DNS_PORT} ${EXTERNAL_DOMAIN_SUFFIX}' \
    < /etc/bind/named.conf.template \
    > /etc/bind/named.conf

python3 /usr/local/bin/generate_external_zone.py \
    --suffix "$EXTERNAL_DOMAIN_SUFFIX" \
    --domain-count "$EXTERNAL_DOMAIN_COUNT" \
    --ns-ip "$EXTERNAL_AUTH_IP" \
    --output /etc/bind/db.external.test

named-checkconf /etc/bind/named.conf
named-checkzone "$EXTERNAL_DOMAIN_SUFFIX" /etc/bind/db.external.test

exec named -g -c /etc/bind/named.conf -u bind
