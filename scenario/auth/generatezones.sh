#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZONE_DIR="${SCRIPT_DIR}/zones"
CONF_FILE="${SCRIPT_DIR}/named.conf.generated"

AUTH_NS_IP="10.10.10.53"

mkdir -p "$ZONE_DIR"
> "$CONF_FILE"

SUBDOMAINS=("www" "api" "mail" "bank" "login" "portal" "intranet" "dev" "test" "admin")
TTLS=(60 120 300 600 1800)
ENVS=("prod" "dev" "stage" "test")
DEPTS=("finance" "hr" "sales" "rnd" "security" "infra")

random_ip() {
    echo "10.10.$((RANDOM % 254 + 1)).$((RANDOM % 254 + 1))"
}

pick_random() {
    local arr=("$@")
    echo "${arr[$RANDOM % ${#arr[@]}]}"
}

for i in $(seq -w 1 1000); do
    DOMAIN="domain${i}.test"
    ZONE_FILE="${ZONE_DIR}/db.${DOMAIN}"

    TTL=$(pick_random "${TTLS[@]}")
    SERIAL="20260518$(printf "%02d" $((10#$i % 100)))"
    ENV=$(pick_random "${ENVS[@]}")
    DEPT=$(pick_random "${DEPTS[@]}")

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
@       IN  A       $(random_ip)
@       IN  TXT     "env=${ENV};dept=${DEPT}"
EOF

    # 랜덤 서브도메인 개수: 3~8개
    COUNT=$((RANDOM % 6 + 3))

    USED=()

    for n in $(seq 1 "$COUNT"); do
        SUB=$(pick_random "${SUBDOMAINS[@]}")

        # 중복 방지
        if [[ " ${USED[*]} " == *" ${SUB} "* ]]; then
            continue
        fi
        USED+=("$SUB")

        TYPE=$((RANDOM % 4))

        case $TYPE in
            0)
                # 단순 A 레코드
                echo "${SUB}    IN  A       $(random_ip)" >> "$ZONE_FILE"
                ;;
            1)
                # 여러 개 A 레코드
                echo "${SUB}    IN  A       $(random_ip)" >> "$ZONE_FILE"
                echo "${SUB}    IN  A       $(random_ip)" >> "$ZONE_FILE"
                ;;
            2)
                # CNAME
                TARGET=$(pick_random "www" "portal" "intranet")
                echo "${SUB}    IN  CNAME   ${TARGET}.${DOMAIN}." >> "$ZONE_FILE"
                echo "${TARGET} IN  A       $(random_ip)" >> "$ZONE_FILE"
                ;;
            3)
                # TXT 포함
                echo "${SUB}    IN  A       $(random_ip)" >> "$ZONE_FILE"
                echo "_info.${SUB} IN TXT \"service=${SUB};ttl=${TTL}\"" >> "$ZONE_FILE"
                ;;
        esac
    done

    # MX는 일부 도메인에만 추가
    if (( RANDOM % 2 == 0 )); then
        echo "mail    IN  A       $(random_ip)" >> "$ZONE_FILE"
        echo "@       IN  MX 10   mail.${DOMAIN}." >> "$ZONE_FILE"
    fi

    cat >> "$CONF_FILE" <<EOF
zone "${DOMAIN}" {
    type master;
    file "/etc/bind/zones/db.${DOMAIN}";
};

EOF

done

echo "[+] Generated randomized 1000 DNS zones"
echo "[+] Zone directory: ${ZONE_DIR}"
echo "[+] Config file: ${CONF_FILE}"
