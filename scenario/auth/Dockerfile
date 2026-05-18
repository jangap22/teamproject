FROM ubuntu:22.04

ARG BIND9_PREFERRED_VERSION=9.18.39
ARG BIND9_FALLBACK_SERIES=9.18

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && bind9_version="$(apt-cache madison bind9 | awk -v preferred="$BIND9_PREFERRED_VERSION" 'index($3, "1:" preferred "-") == 1 { print $3; exit }')" \
    && if [ -z "$bind9_version" ]; then \
        bind9_version="$(apt-cache madison bind9 | awk -v series="$BIND9_FALLBACK_SERIES" 'index($3, "1:" series ".") == 1 { print $3; exit }')"; \
       fi \
    && if [ -z "$bind9_version" ]; then \
        echo "No bind9 ${BIND9_FALLBACK_SERIES}.x package found in apt repositories" >&2; \
        exit 1; \
       fi \
    && apt-get install -y --no-install-recommends "bind9=$bind9_version" dnsutils iproute2 gettext-base \
    && rm -rf /var/lib/apt/lists/*

COPY named.conf.template /etc/bind/named.conf.template
COPY bank.test.zone.template /etc/bind/bank.test.zone.template
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 53/tcp 53/udp

CMD ["/entrypoint.sh"]
