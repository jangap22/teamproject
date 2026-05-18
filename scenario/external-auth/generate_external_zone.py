#!/usr/bin/env python3
import argparse
import ipaddress
import random
from pathlib import Path


POPULAR_DOMAINS = ["google", "youtube", "naver"]
RANDOM_SEED = 20260519
SERIAL = 2026051901


def parse_args():
    parser = argparse.ArgumentParser(description="Generate the external.test BIND zone.")
    parser.add_argument("--suffix", default="external.test")
    parser.add_argument("--domain-count", type=int, default=1001)
    parser.add_argument("--ns-ip", default="172.20.0.80")
    parser.add_argument("--output", default="/etc/bind/db.external.test")
    return parser.parse_args()


def domain_labels(domain_count):
    return POPULAR_DOMAINS + [f"domain{i:04d}" for i in range(domain_count)]


def stable_ipv4(index, offset):
    second = 30 + ((index + offset) % 180)
    third = (index * 7 + offset * 11) % 256
    fourth = 10 + ((index * 13 + offset * 17) % 240)
    return f"10.{second}.{third}.{fourth}"


def stable_ipv6(index, offset):
    return str(ipaddress.IPv6Address(0x20010DB8000000000000000000000000 + index * 256 + offset))


def apex_ttl(label, rng):
    if label in POPULAR_DOMAINS:
        return 200
    if label.startswith("domain"):
        number = int(label.removeprefix("domain"))
        if 900 <= number <= 1000:
            return rng.randint(10, 30)
    return rng.randint(100, 300)


def weighted_ttl(label, owner, rng):
    if owner in ("api", "cdn", "static", "img"):
        return rng.randint(20, 60)
    if owner in ("www", "login", "account", "auth"):
        return rng.randint(100, 300)
    if owner in ("mail", "edge"):
        return apex_ttl(label, rng)
    return apex_ttl(label, rng)


def emit(lines, ttl, owner, rrtype, value):
    lines.append(f"{owner:<38} {ttl:<5} IN {rrtype:<6} {value}")


def generate_zone(suffix, domain_count, ns_ip):
    rng = random.Random(RANDOM_SEED)
    suffix = suffix.rstrip(".")
    labels = domain_labels(domain_count)
    lines = [
        "$ORIGIN .",
        "$TTL 300",
        f"{suffix}. 1200 IN SOA ns1.{suffix}. admin.{suffix}. (",
        f"        {SERIAL} ; serial",
        "        1200       ; refresh",
        "        300        ; retry",
        "        1209600    ; expire",
        "        1200 )     ; minimum",
        f"{suffix}. 1200 IN NS ns1.{suffix}.",
        f"ns1.{suffix}. 1200 IN A {ns_ip}",
        f"_spf.{suffix}. 1200 IN TXT \"v=spf1 -all\"",
        "",
        f"$ORIGIN {suffix}.",
    ]

    for index, label in enumerate(labels, start=1):
        base = label
        apex = apex_ttl(label, rng)
        emit(lines, apex, base, "A", stable_ipv4(index, 1))
        emit(lines, apex, base, "AAAA", stable_ipv6(index, 1))
        emit(lines, 1200, base, "MX", f"10 mail.{base}.{suffix}.")
        emit(lines, apex, base, "TXT", f"\"v=spf1 include:_spf.{suffix} ~all\"")

        for offset, owner in enumerate(("api", "cdn", "static", "img", "login", "account", "auth"), start=2):
            ttl = weighted_ttl(label, owner, rng)
            fqdn = f"{owner}.{base}"
            emit(lines, ttl, fqdn, "A", stable_ipv4(index, offset))
            emit(lines, ttl, fqdn, "AAAA", stable_ipv6(index, offset))

        emit(lines, weighted_ttl(label, "www", rng), f"www.{base}", "CNAME", f"edge.{base}.{suffix}.")
        emit(lines, weighted_ttl(label, "edge", rng), f"edge.{base}", "A", stable_ipv4(index, 20))
        emit(lines, weighted_ttl(label, "edge", rng), f"edge.{base}", "AAAA", stable_ipv6(index, 20))
        emit(lines, 1200, f"mail.{base}", "A", stable_ipv4(index, 30))
        emit(lines, 1200, f"mail.{base}", "AAAA", stable_ipv6(index, 30))
        lines.append("")

    return "\n".join(lines) + "\n"


def main():
    args = parse_args()
    zone = generate_zone(args.suffix, args.domain_count, args.ns_ip)
    Path(args.output).write_text(zone, encoding="ascii")
    total = len(domain_labels(args.domain_count))
    print(f"generated {total} external domains into {args.output}")


if __name__ == "__main__":
    main()
