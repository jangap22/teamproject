#!/usr/bin/env python3
"""
Closed-lab normal DNS traffic generator for external.test.
"""

import os
import random
import time
from collections import Counter

import dns.exception
import dns.resolver


RANDOM_SEED = 20260519
POPULAR_DOMAINS = ["google", "youtube", "naver"]
QTYPE_WEIGHTS = [
    ("A", 80),
    ("AAAA", 12),
    ("MX", 2),
    ("TXT", 2),
    ("NS", 2),
    ("CNAME", 1),
    ("SOA", 1),
]
NAME_PATTERN_WEIGHTS = [
    ("apex", 15),
    ("www", 35),
    ("asset", 30),
    ("mail", 5),
    ("login", 5),
]


def require_env(name):
    value = os.getenv(name)
    if value is None or value == "":
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def optional_int(name, default=None):
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return int(value)


def optional_float(name, default=None):
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return float(value)


RESOLVER_IP = require_env("RESOLVER_IP")
RESOLVER_PORT = int(require_env("RESOLVER_PORT"))

EXTERNAL_DOMAIN_SUFFIX = os.getenv("EXTERNAL_DOMAIN_SUFFIX", os.getenv("DOMAIN_SUFFIX", "external.test"))
EXTERNAL_DOMAIN_COUNT = int(os.getenv("EXTERNAL_DOMAIN_COUNT", os.getenv("DOMAIN_COUNT", "1001")))

ZIPF_S = optional_float("ZIPF_S", optional_float("CLIENT_ZIPF_S", 1.1))
NXDOMAIN_RATIO = optional_float("NXDOMAIN_RATIO", 0.10)

WARMUP_SECONDS = optional_int("WARMUP_SECONDS", 300)
ATTACK_WINDOW_SECONDS = optional_int("ATTACK_WINDOW_SECONDS", 60)
COOLDOWN_SECONDS = optional_int("COOLDOWN_SECONDS", 300)
NORMAL_QPS = optional_float("NORMAL_QPS", 200.0)

DURATION_SECONDS = optional_int(
    "DURATION_SECONDS",
    WARMUP_SECONDS + ATTACK_WINDOW_SECONDS + COOLDOWN_SECONDS,
)
TOTAL_QUERIES = optional_int("TOTAL_QUERIES", int(DURATION_SECONDS * NORMAL_QPS))

TIMEOUT_SECONDS = optional_float("TIMEOUT_SECONDS", 1.0)
PROGRESS_INTERVAL_SECONDS = optional_int("PROGRESS_INTERVAL_SECONDS", 10)


def build_domains():
    domains = [f"{name}.{EXTERNAL_DOMAIN_SUFFIX}" for name in POPULAR_DOMAINS]
    domains.extend(
        f"domain{i:04d}.{EXTERNAL_DOMAIN_SUFFIX}"
        for i in range(EXTERNAL_DOMAIN_COUNT)
    )
    return domains


def build_zipf_weights(domain_count, s):
    weights = [1.0 / (rank ** s) for rank in range(1, domain_count + 1)]
    total = sum(weights)
    return [weight / total for weight in weights]


def choose_weighted(weighted_items):
    items = [item for item, _ in weighted_items]
    weights = [weight for _, weight in weighted_items]
    return random.choices(items, weights=weights, k=1)[0]


def choose_domain(domains, weights):
    return random.choices(domains, weights=weights, k=1)[0]


def random_nxdomain(domain):
    label = domain.split(".", 1)[0]
    styles = [
        f"xj{random.randint(10, 99)}.{domain}",
        f"typo-{label}.{EXTERNAL_DOMAIN_SUFFIX}",
        f"random{random.randint(100, 999)}.{domain}",
    ]
    return random.choice(styles)


def choose_qtype():
    return choose_weighted(QTYPE_WEIGHTS)


def build_query_name(domain, qtype):
    if random.random() < NXDOMAIN_RATIO:
        return random_nxdomain(domain)

    pattern = choose_weighted(NAME_PATTERN_WEIGHTS)
    if qtype in ("MX", "TXT", "NS", "SOA"):
        return domain
    if qtype == "CNAME":
        return f"www.{domain}"
    if pattern == "apex":
        return domain
    if pattern == "www":
        return f"www.{domain}"
    if pattern == "asset":
        return f"{random.choice(['api', 'cdn', 'static', 'img'])}.{domain}"
    if pattern == "mail":
        return f"mail.{domain}"
    if pattern == "login":
        return f"{random.choice(['login', 'account', 'auth'])}.{domain}"
    return domain


def build_resolver():
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [RESOLVER_IP]
    resolver.port = RESOLVER_PORT
    resolver.timeout = TIMEOUT_SECONDS
    resolver.lifetime = TIMEOUT_SECONDS
    return resolver


def send_dns_query(resolver, fqdn, qtype):
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


def print_progress(start_time, sent_count, success_count, error_count, target_qps, domain_counter, qtype_counter):
    now = time.monotonic()
    elapsed = now - start_time
    current_qps = sent_count / elapsed if elapsed > 0 else 0

    print()
    print("========== Normal DNS Traffic Progress ==========")
    print(f"elapsed seconds : {elapsed:.1f}")
    print(f"sent queries    : {sent_count}")
    print(f"success count   : {success_count}")
    print(f"error count     : {error_count}")
    print(f"current QPS     : {current_qps:.2f}")
    print(f"target QPS      : {target_qps:.2f}")
    print("top 10 domains  :")
    for domain, count in domain_counter.most_common(10):
        print(f"  {domain:<34} {count}")
    print("qtype counts    :")
    for qtype, count in qtype_counter.most_common():
        print(f"  {qtype:<6} {count}")
    print("=================================================")
    print()


def print_final_summary(start_time, sent_count, success_count, error_count, domain_counter, qtype_counter):
    duration = time.monotonic() - start_time
    average_qps = sent_count / duration if duration > 0 else 0

    print()
    print("========== Normal DNS Traffic Final Summary ==========")
    print(f"total sent    : {sent_count}")
    print(f"success count : {success_count}")
    print(f"error count   : {error_count}")
    print(f"duration      : {duration:.2f} seconds")
    print(f"average QPS   : {average_qps:.2f}")
    print("top 20 queried domains:")
    for domain, count in domain_counter.most_common(20):
        print(f"  {domain:<34} {count}")
    print("qtype counts:")
    for qtype, count in qtype_counter.most_common():
        print(f"  {qtype:<6} {count}")
    print("======================================================")
    print()


def main():
    random.seed(RANDOM_SEED)
    domains = build_domains()
    weights = build_zipf_weights(len(domains), ZIPF_S)
    resolver = build_resolver()

    target_qps = NORMAL_QPS
    interval = 1.0 / target_qps if target_qps > 0 else 0

    print("Normal DNS query generator started.")
    print(f"resolver          : {RESOLVER_IP}:{RESOLVER_PORT}")
    print(f"domain suffix     : {EXTERNAL_DOMAIN_SUFFIX}")
    print(f"ranked domains    : {len(domains)}")
    print(f"zipf s            : {ZIPF_S}")
    print(f"nxdomain ratio    : {NXDOMAIN_RATIO}")
    print(f"warmup seconds    : {WARMUP_SECONDS}")
    print(f"attack window     : {ATTACK_WINDOW_SECONDS}")
    print(f"cooldown seconds  : {COOLDOWN_SECONDS}")
    print(f"duration          : {DURATION_SECONDS} seconds")
    print(f"normal QPS        : {NORMAL_QPS:.2f}")
    print(f"total queries     : {TOTAL_QUERIES}")
    print()

    sent_count = 0
    success_count = 0
    error_count = 0
    domain_counter = Counter()
    qtype_counter = Counter()

    start_time = time.monotonic()
    next_send_time = start_time
    next_progress_time = start_time + PROGRESS_INTERVAL_SECONDS

    try:
        while sent_count < TOTAL_QUERIES:
            now = time.monotonic()
            if now < next_send_time:
                time.sleep(next_send_time - now)

            domain = choose_domain(domains, weights)
            qtype = choose_qtype()
            fqdn = build_query_name(domain, qtype)
            ok = send_dns_query(resolver, fqdn, qtype)

            sent_count += 1
            domain_counter[domain] += 1
            qtype_counter[qtype] += 1
            if ok:
                success_count += 1
            else:
                error_count += 1

            next_send_time = start_time + (sent_count * interval)
            now = time.monotonic()
            if now >= next_progress_time:
                print_progress(
                    start_time,
                    sent_count,
                    success_count,
                    error_count,
                    target_qps,
                    domain_counter,
                    qtype_counter,
                )
                next_progress_time = now + PROGRESS_INTERVAL_SECONDS

    except KeyboardInterrupt:
        print()
        print("[!] Interrupted by user.")
    finally:
        print_final_summary(start_time, sent_count, success_count, error_count, domain_counter, qtype_counter)


if __name__ == "__main__":
    main()
