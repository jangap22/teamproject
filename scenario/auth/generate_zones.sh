#!/bin/bash
set -e

BASE_DIR="/auth"
ZONE_DIR="${BASE_DIR}/zones"
NAMED_CONF="${BASE_DIR}/named.conf"
ZONES_CONF="${BASE_DIR}/named.conf.zones"
AUTH_NS_IP="10.10.10.53"
ZONE_COUNT=1000
SERIAL_DATE="20260518"

SUBDOMAINS=("api" "mail" "bank" "login" "portal" "intranet" "dev" "test" "admin")
TTLS=(60 120 300 600 1800)
ENVS=("prod" "dev" "stage" "test")
DEPTS=("finance" "hr" "sales" "rnd" "security" "infra")
INCLUDE_LINE="include \"${ZONES_CONF}\";"

random_ip() {
    echo "10.10.$((RANDOM % 254 + 1)).$((RANDOM % 254 + 1))"
}

pick_random() {
    local arr=("$@")
    echo "${arr[$RANDOM % ${#arr[@]}]}"
}

write_default_named_conf() {
    cat > "$NAMED_CONF" <<EOF
options {
    directory "/var/cache/bind";

    listen-on port 53 { any; };
    listen-on-v6 { none; };

    recursion no;
    allow-query { any; };

    dnssec-validation no;
};

${INCLUDE_LINE}
EOF
}

ensure_named_conf_include() {
    if [[ ! -f "$NAMED_CONF" ]]; then
        write_default_named_conf
        return
    fi

    if ! grep -Fxq "$INCLUDE_LINE" "$NAMED_CONF"; then
        {
            printf "\n"
            printf "%s\n" "$INCLUDE_LINE"
        } >> "$NAMED_CONF"
    fi
}

mkdir -p "$ZONE_DIR"
rm -f "${ZONE_DIR}"/db.domain*.test
> "$ZONES_CONF"

for i in $(seq -w 1 "$ZONE_COUNT"); do
    DOMAIN="domain${i}.test"
    ZONE_FILE="${ZONE_DIR}/db.${DOMAIN}"

    TTL=$(pick_random "${TTLS[@]}")
    SERIAL="${SERIAL_DATE}$(printf "%02d" $((10#$i % 100)))"
    ENV=$(pick_random "${ENVS[@]}")
    DEPT=$(pick_random "${DEPTS[@]}")
    WWW_IP=$(random_ip)

    cat > "$ZONE_FILE" <<EOF
\$TTL ${TTL}
@   IN  SOA ns1.${DOMAIN}. admin.${DOMAIN}. (
        ${SERIAL} ; serial
        300        ; refresh
        180        ; retry
        1209600    ; expire
        ${TTL} )   ; minimum

@       IN  NS      ns1.${DOMAIN}.
ns1     IN  A       ${AUTH_NS_IP}
www     IN  A       ${WWW_IP}
@       IN  A       $(random_ip)
@       IN  TXT     "env=${ENV};dept=${DEPT}"
EOF

    COUNT=$((RANDOM % 6 + 3))
    USED=()

    for n in $(seq 1 "$COUNT"); do
        SUB=$(pick_random "${SUBDOMAINS[@]}")

        if [[ " ${USED[*]} " == *" ${SUB} "* ]]; then
            continue
        fi
        USED+=("$SUB")

        TYPE=$((RANDOM % 4))

        case $TYPE in
            0)
                echo "${SUB}    IN  A       $(random_ip)" >> "$ZONE_FILE"
                ;;
            1)
                echo "${SUB}    IN  A       $(random_ip)" >> "$ZONE_FILE"
                echo "${SUB}    IN  A       $(random_ip)" >> "$ZONE_FILE"
                ;;
            2)
                echo "${SUB}    IN  CNAME   www.${DOMAIN}." >> "$ZONE_FILE"
                ;;
            3)
                echo "${SUB}    IN  A       $(random_ip)" >> "$ZONE_FILE"
                echo "_info.${SUB} IN TXT \"service=${SUB};ttl=${TTL}\"" >> "$ZONE_FILE"
                ;;
        esac
    done

    if (( RANDOM % 2 == 0 )); then
        if [[ " ${USED[*]} " != *" mail "* ]]; then
            echo "mail    IN  A       $(random_ip)" >> "$ZONE_FILE"
        fi
        echo "@       IN  MX 10   mail.${DOMAIN}." >> "$ZONE_FILE"
    fi

    cat >> "$ZONES_CONF" <<EOF
zone "${DOMAIN}" {
    type master;
    file "${ZONE_FILE}";
};

EOF
done

ensure_named_conf_include

GENERATED_COUNT=$(find "$ZONE_DIR" -maxdepth 1 -type f -name 'db.domain*.test' | wc -l | tr -d ' ')

echo "Generated ${GENERATED_COUNT} zone files in ${ZONE_DIR}"
echo "Generated ${ZONES_CONF}"
echo "Updated ${NAMED_CONF}"
echo "Test:"
echo "  named-checkconf ${NAMED_CONF}"
echo "  named-checkzone domain0001.test ${ZONE_DIR}/db.domain0001.test"
echo "  dig @127.0.0.1 domain0001.test A"
echo "  dig @127.0.0.1 www.domain0001.test A"
echo
echo "Validation commands are not run automatically. Run named-checkconf and named-checkzone with the commands above."
