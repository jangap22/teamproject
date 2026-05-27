#!/bin/sh
set -e

: "${DNS_PORT:?missing DNS_PORT}"
: "${RESOLVER_IP:?missing RESOLVER_IP}"
: "${AUTH_IP:?missing AUTH_IP}"
: "${EXTERNAL_AUTH_IP:?missing EXTERNAL_AUTH_IP}"
: "${RESOLVER_ATTACK_UDP_PORT:?missing RESOLVER_ATTACK_UDP_PORT}"
: "${PCAP_CAPTURE_INTERFACE:=any}"
export DNS_PORT RESOLVER_IP AUTH_IP EXTERNAL_AUTH_IP RESOLVER_ATTACK_UDP_PORT

envsubst '${DNS_PORT} ${AUTH_IP} ${EXTERNAL_AUTH_IP} ${RESOLVER_ATTACK_UDP_PORT}' \
    < /etc/bind/named.conf.template \
    > /etc/bind/named.conf

capture_dir="${PCAP_CAPTURE_DIR:-/data/captures}"
mkdir -p "$capture_dir"

dataset_number=1
while :; do
    capture_file="$(printf '%s/dataset_v%06d.pcap' "$capture_dir" "$dataset_number")"
    if [ ! -e "$capture_file" ]; then
        break
    fi
    dataset_number=$((dataset_number + 1))
done

# Match sniffer input: DNS responses addressed to the resolver on monitored ports.
capture_filter="dst host ${RESOLVER_IP} and ((udp and (src port 10053 or dst port 10053 or src port 20053 or dst port 20053 or src port 30053 or dst port 30053 or src port 1025 or dst port 1025) and (udp[10] & 0x80 != 0)) or (tcp and (src port 10053 or dst port 10053 or src port 20053 or dst port 20053 or src port 30053 or dst port 30053 or src port 1025 or dst port 1025) and (tcp[((tcp[12] & 0xf0) >> 2) + 4] & 0x80 != 0)))"

listener_pid=""
capture_pid=""
named_pid=""

shutdown() {
    status="${1:-0}"
    trap - INT TERM
    for pid in "$named_pid" "$capture_pid" "$listener_pid"; do
        if [ -n "$pid" ]; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    for pid in "$named_pid" "$capture_pid" "$listener_pid"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done
    exit "$status"
}

trap 'shutdown 0' INT TERM

python3 /listener.py &
listener_pid=$!

echo "[*] Resolver upstream pcap capture: ${capture_file}"
tcpdump -i "$PCAP_CAPTURE_INTERFACE" -U -n -s 0 -w "$capture_file" "$capture_filter" &
capture_pid=$!

named -g -c /etc/bind/named.conf -u bind &
named_pid=$!

set +e
wait "$named_pid"
named_status=$?
set -e
shutdown "$named_status"
