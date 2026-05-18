#!/usr/bin/env python3
"""
DNS Query Traffic Generator

Install dependency:
    pip install dnspython

Run:
    cd /client
    python3 query_generator.py
"""

import random
import time
import os
from collections import Counter

import dns.resolver
import dns.exception


# =========================
# Editable Settings
# =========================

def require_env(name):
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value

RESOLVER_IP = require_env("RESOLVER_IP")
RESOLVER_PORT = int(require_env("RESOLVER_PORT"))

DOMAIN_COUNT = int(require_env("DOMAIN_COUNT"))
DOMAIN_PREFIX = require_env("DOMAIN_PREFIX")
DOMAIN_SUFFIX = require_env("DOMAIN_SUFFIX")

# Zipf parameter.
# 1.0 = normal Zipf-like distribution.
# Higher value = more traffic concentrated on domain0001, domain0002...
# Lower value = flatter distribution.
ZIPF_S = float(require_env("ZIPF_S"))

TOTAL_QUERIES = int(require_env("TOTAL_QUERIES"))
DURATION_SECONDS = int(require_env("DURATION_SECONDS"))

SUBDOMAINS = [
    "www",
    "api",
    "bank",
    "login",
    "portal",
    "mail",
    "intranet",
    "dev",
    "admin",
]

# A를 많이 보내고, MX/TXT는 일부만 섞음
QTYPES = [
    "A",
    "A",
    "A",
    "A",
    "A",
    "MX",
    "TXT",
]

TIMEOUT_SECONDS = float(require_env("TIMEOUT_SECONDS"))
PROGRESS_INTERVAL_SECONDS = int(require_env("PROGRESS_INTERVAL_SECONDS"))


# =========================
# Domain / Distribution
# =========================

def build_domains():
    """
    domain0001.test ~ domain1000.test 생성
    """
    return [
        f"{DOMAIN_PREFIX}{i:04d}.{DOMAIN_SUFFIX}"
        for i in range(1, DOMAIN_COUNT + 1)
    ]


def build_zipf_weights(domain_count, s):
    """
    rank 1 = domain0001.test
    rank 2 = domain0002.test
    ...
    weight = 1 / rank^s
    """
    weights = []

    for rank in range(1, domain_count + 1):
        weight = 1.0 / (rank ** s)
        weights.append(weight)

    total = sum(weights)
    normalized_weights = [w / total for w in weights]

    return normalized_weights


def choose_domain(domains, weights):
    """
    Zipf 가중치 기반 도메인 선택
    """
    return random.choices(domains, weights=weights, k=1)[0]


def choose_qtype():
    return random.choice(QTYPES)


def build_query_name(domain, qtype):
    """
    A 질의:
        www.domain0001.test
        bank.domain0002.test

    MX/TXT 질의:
        domain0001.test
    """
    if qtype == "A":
        subdomain = random.choice(SUBDOMAINS)
        return f"{subdomain}.{domain}"

    if qtype in ("MX", "TXT"):
        return domain

    return domain


# =========================
# DNS
# =========================

def build_resolver():
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [RESOLVER_IP]
    resolver.port = RESOLVER_PORT
    resolver.timeout = TIMEOUT_SECONDS
    resolver.lifetime = TIMEOUT_SECONDS
    return resolver


def send_dns_query(resolver, fqdn, qtype):
    """
    성공하면 True, 실패하면 False.
    NXDOMAIN, NoAnswer, Timeout 등은 실험 중 자연스러운 실패로 보고 계속 진행.
    """
    try:
        resolver.resolve(fqdn, qtype)
        return True
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return False
    except Exception:
        return False


# =========================
# Output
# =========================

def print_progress(
    start_time,
    sent_count,
    success_count,
    error_count,
    target_qps,
    domain_counter,
):
    now = time.monotonic()
    elapsed = now - start_time
    current_qps = sent_count / elapsed if elapsed > 0 else 0

    print()
    print("========== Progress ==========")
    print(f"elapsed seconds : {elapsed:.1f}")
    print(f"sent queries    : {sent_count}")
    print(f"success count   : {success_count}")
    print(f"error count     : {error_count}")
    print(f"current QPS     : {current_qps:.2f}")
    print(f"target QPS      : {target_qps:.2f}")
    print("top 10 domains  :")

    for domain, count in domain_counter.most_common(10):
        print(f"  {domain:<20} {count}")

    print("==============================")
    print()


def print_final_summary(
    start_time,
    sent_count,
    success_count,
    error_count,
    domain_counter,
):
    end_time = time.monotonic()
    duration = end_time - start_time
    average_qps = sent_count / duration if duration > 0 else 0

    print()
    print("========== Final Summary ==========")
    print(f"total sent    : {sent_count}")
    print(f"success count : {success_count}")
    print(f"error count   : {error_count}")
    print(f"duration      : {duration:.2f} seconds")
    print(f"average QPS   : {average_qps:.2f}")
    print()
    print("top 20 queried domains:")

    for domain, count in domain_counter.most_common(20):
        print(f"  {domain:<20} {count}")

    print("===================================")
    print()


# =========================
# Main Loop
# =========================

def main():
    domains = build_domains()
    weights = build_zipf_weights(DOMAIN_COUNT, ZIPF_S)
    resolver = build_resolver()

    target_qps = TOTAL_QUERIES / DURATION_SECONDS
    interval = DURATION_SECONDS / TOTAL_QUERIES

    print("DNS query generator started.")
    print(f"resolver        : {RESOLVER_IP}:{RESOLVER_PORT}")
    print(f"domain count    : {DOMAIN_COUNT}")
    print(f"zipf s          : {ZIPF_S}")
    print(f"total queries   : {TOTAL_QUERIES}")
    print(f"duration        : {DURATION_SECONDS} seconds")
    print(f"target QPS      : {target_qps:.2f}")
    print(f"interval        : {interval:.6f} seconds")
    print()

    sent_count = 0
    success_count = 0
    error_count = 0

    domain_counter = Counter()

    start_time = time.monotonic()
    next_send_time = start_time
    next_progress_time = start_time + PROGRESS_INTERVAL_SECONDS

    try:
        while sent_count < TOTAL_QUERIES:
            now = time.monotonic()

            # 목표 전송 시간보다 빠르면 잠깐 대기
            if now < next_send_time:
                time.sleep(next_send_time - now)

            domain = choose_domain(domains, weights)
            qtype = choose_qtype()
            fqdn = build_query_name(domain, qtype)

            ok = send_dns_query(resolver, fqdn, qtype)

            sent_count += 1
            domain_counter[domain] += 1

            if ok:
                success_count += 1
            else:
                error_count += 1

            # 다음 전송 예정 시간
            next_send_time = start_time + (sent_count * interval)

            # 진행 상황 출력
            now = time.monotonic()
            if now >= next_progress_time:
                print_progress(
                    start_time=start_time,
                    sent_count=sent_count,
                    success_count=success_count,
                    error_count=error_count,
                    target_qps=target_qps,
                    domain_counter=domain_counter,
                )
                next_progress_time = now + PROGRESS_INTERVAL_SECONDS

    except KeyboardInterrupt:
        print()
        print("[!] Interrupted by user.")

    finally:
        print_final_summary(
            start_time=start_time,
            sent_count=sent_count,
            success_count=success_count,
            error_count=error_count,
            domain_counter=domain_counter,
        )


if __name__ == "__main__":
    main()
