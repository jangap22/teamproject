#!/usr/bin/env python3
"""
Closed-lab normal DNS traffic generator for external.test.
"""

import os
import math
import random
import socket
import time
from collections import Counter, deque

import dns.exception
import dns.message
import dns.resolver
import dns.rdatatype


RANDOM_SEED = 20260519
POPULAR_DOMAINS = ["google", "youtube", "naver"]
SHORT_DOMAIN_LABELS = ["api", "cdn", "gw", "db", "app", "dev", "log", "auth", "mail", "vpn", "sso"]
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
SCENARIO_WEIGHTS = [
    ("regular_a", 20),
    ("short_a", 20),
    ("long_a", 8),
    ("cname_a", 12),
    ("additional_a", 12),
    ("authority_soa", 7),
    ("aaaa", 6),
    ("multi_answer", 5),
    ("nxdomain", 5),
    ("legacy", 5),
]
MIN_ADDITIONAL_A_RATIO = 0.10
BANK_NORMAL_RATIO = 0.10
BANK_NORMAL_NAMES = [
    "bank.test",
    "login.bank.test",
    "api.bank.test",
    "static.bank.test",
    "cdn.bank.test",
    "sso.bank.test",
    "domain0000.bank.test",
    "domain00000000.bank.test",
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

# Burst mode is the default manual run path: three hundred thousand queries per session.
TOTAL_QUERIES = optional_int("BURST_TOTAL_QUERIES", 300_000)
DURATION_SECONDS = optional_int("BURST_DURATION_SECONDS", 300)
NORMAL_QPS = TOTAL_QUERIES / DURATION_SECONDS if DURATION_SECONDS > 0 else 0

TIMEOUT_SECONDS = optional_float("TIMEOUT_SECONDS", 1.0)
PROGRESS_INTERVAL_SECONDS = optional_int("PROGRESS_INTERVAL_SECONDS", 10)


def build_domains():
    domains = [f"{name}.{EXTERNAL_DOMAIN_SUFFIX}" for name in POPULAR_DOMAINS]
    domains.extend(
        f"domain{i:04d}.{EXTERNAL_DOMAIN_SUFFIX}"
        for i in range(EXTERNAL_DOMAIN_COUNT)
    )
    domains.extend(f"{name}.{EXTERNAL_DOMAIN_SUFFIX}" for name in SHORT_DOMAIN_LABELS)
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


def build_short_domains():
    return [f"{name}.{EXTERNAL_DOMAIN_SUFFIX}" for name in SHORT_DOMAIN_LABELS]


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


def cache_distinct_label(query_number):
    suffix = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=3))
    return f"q{query_number:x}{suffix}"


def build_scenario_query(scenario, domains, weights, short_domains, query_number):
    if scenario == "bank_normal":
        fqdn = random.choice(BANK_NORMAL_NAMES)
        return fqdn, "A", fqdn

    domain = choose_domain(domains, weights)
    nonce = cache_distinct_label(query_number)

    if scenario == "short_a":
        domain = random.choice(short_domains)
        return domain, "A", domain
    if scenario == "regular_a":
        domain = random.choice(short_domains)
        return f"{nonce}.{domain}", "A", domain
    if scenario == "long_a":
        return f"telemetrycollector{nonce}.fresh.{domain}", "A", domain
    if scenario == "cname_a":
        domain = random.choice(short_domains)
        return f"{nonce}.alias.{domain}", random.choice(("A", "AAAA")), domain
    if scenario == "additional_a":
        return f"{nonce}.mailroute.{domain}", "MX", domain
    if scenario == "authority_soa":
        return f"{nonce}.authority-missing.{domain}", "A", domain
    if scenario == "aaaa":
        domain = random.choice(short_domains)
        return f"{nonce}.{domain}", "AAAA", domain
    if scenario == "multi_answer":
        return f"{nonce}.multi.{domain}", random.choice(("A", "AAAA")), domain
    if scenario == "nxdomain":
        return f"{nonce}.missing.{domain}", "A", domain

    qtype = choose_qtype()
    return build_query_name(domain, qtype), qtype, domain


def build_resolver():
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [RESOLVER_IP]
    resolver.port = RESOLVER_PORT
    resolver.timeout = TIMEOUT_SECONDS
    resolver.lifetime = TIMEOUT_SECONDS
    return resolver


def send_dns_query(resolver, fqdn, qtype):
    try:
        answer = resolver.resolve(fqdn, qtype, raise_on_no_answer=False)
        return True, answer.response
    except dns.resolver.NXDOMAIN as error:
        try:
            return False, next(iter(error.responses().values()), None)
        except Exception:
            return False, None
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return False, None
    except Exception:
        return False, None


def query_length_bucket(fqdn):
    length = len(fqdn.rstrip("."))
    if length <= 18:
        return "short"
    if length <= 35:
        return "medium"
    if length <= 55:
        return "long"
    return "very_long"


def observe_response(response, ttl_counter):
    additional_a_count = 0
    if response is None:
        return additional_a_count

    for section in (response.answer, response.authority, response.additional):
        for rrset in section:
            ttl_counter[int(rrset.ttl)] += len(rrset)

    for rrset in response.additional:
        if rrset.rdtype == dns.rdatatype.A:
            additional_a_count += len(rrset)
    return additional_a_count


def prepare_queries(domains, weights, short_domains):
    prepared_queries = []
    domain_counter = Counter()
    qtype_counter = Counter()
    scenario_counter = Counter()
    domain_length_counter = Counter()

    scenarios = [choose_weighted(SCENARIO_WEIGHTS) for _ in range(TOTAL_QUERIES)]
    required_bank = math.ceil(TOTAL_QUERIES * BANK_NORMAL_RATIO)
    for index in random.sample(range(TOTAL_QUERIES), required_bank):
        scenarios[index] = "bank_normal"

    required_additional = math.ceil(TOTAL_QUERIES * MIN_ADDITIONAL_A_RATIO)
    missing_additional = required_additional - scenarios.count("additional_a")
    if missing_additional > 0:
        replaceable = deque(
            index
            for index, scenario in enumerate(scenarios)
            if scenario not in ("additional_a", "bank_normal")
        )
        for _ in range(missing_additional):
            scenarios[replaceable.popleft()] = "additional_a"

    for query_number, scenario in enumerate(scenarios):
        fqdn, qtype, domain = build_scenario_query(
            scenario,
            domains,
            weights,
            short_domains,
            query_number,
        )
        wire = dns.message.make_query(fqdn, qtype).to_wire()
        prepared_queries.append(wire)
        domain_counter[domain] += 1
        qtype_counter[qtype] += 1
        scenario_counter[scenario] += 1
        domain_length_counter[query_length_bucket(fqdn)] += 1

    return (
        prepared_queries,
        domain_counter,
        qtype_counter,
        scenario_counter,
        domain_length_counter,
    )


def send_prepared_queries(prepared_queries, target_qps):
    sent_count = 0
    error_count = 0
    start_time = time.monotonic()
    next_progress_time = start_time + PROGRESS_INTERVAL_SECONDS
    destination = (RESOLVER_IP, RESOLVER_PORT)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            while sent_count < len(prepared_queries):
                now = time.monotonic()
                elapsed = now - start_time
                target_sent = min(
                    len(prepared_queries),
                    int(elapsed * target_qps) + 1 if target_qps > 0 else len(prepared_queries),
                )

                while sent_count < target_sent:
                    try:
                        sock.sendto(prepared_queries[sent_count], destination)
                    except OSError:
                        error_count += 1
                    sent_count += 1

                now = time.monotonic()
                if now >= next_progress_time:
                    current_qps = sent_count / (now - start_time) if now > start_time else 0
                    print(
                        f"[burst] elapsed={now - start_time:.1f}s "
                        f"sent={sent_count} qps={current_qps:.2f} errors={error_count}",
                        flush=True,
                    )
                    next_progress_time = now + PROGRESS_INTERVAL_SECONDS

                if sent_count < len(prepared_queries) and target_qps > 0:
                    next_send_time = start_time + (sent_count / target_qps)
                    sleep_seconds = next_send_time - time.monotonic()
                    if sleep_seconds > 0:
                        time.sleep(min(sleep_seconds, 0.001))
    except KeyboardInterrupt:
        print()
        print("[!] Interrupted by user.")

    return start_time, sent_count, error_count


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


def print_final_summary(
    start_time,
    sent_count,
    success_count,
    error_count,
    domain_counter,
    qtype_counter,
    scenario_counter,
    ttl_counter,
    domain_length_counter,
    observed_additional_a_count,
):
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
    print(f"total_queries_sent          : {sent_count}")
    print(f"duration_seconds             : {duration:.2f}")
    print(f"estimated_qps                : {average_qps:.2f}")
    print(f"scenario_counts              : {dict(scenario_counter)}")
    print(f"ttl_distribution             : {dict(sorted(ttl_counter.items()))}")
    print(f"domain_length_distribution   : {dict(domain_length_counter)}")
    short_ratio = domain_length_counter["short"] / sent_count if sent_count else 0
    print(f"short_domain_ratio           : {short_ratio:.4f}")
    print(f"additional_A_scenario_count  : {scenario_counter['additional_a']}")
    print(f"observed_additional_A_records: {observed_additional_a_count}")
    print(f"nxdomain_count               : {scenario_counter['nxdomain']}")
    print("src_port diversity           : excluded; environment structure requires separate confirmation")
    print("======================================================")
    print()


def main():
    random.seed(RANDOM_SEED)
    domains = build_domains()
    weights = build_zipf_weights(len(domains), ZIPF_S)
    short_domains = build_short_domains()

    target_qps = NORMAL_QPS

    print("Normal DNS query generator burst mode preparing.")
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
    print(f"short domains     : {len(short_domains)} under {EXTERNAL_DOMAIN_SUFFIX}")
    print(f"min additional A  : {MIN_ADDITIONAL_A_RATIO:.0%} scenario share")
    print(f"bank normal ratio : {BANK_NORMAL_RATIO:.0%} scenario share")
    print("response features : inspect resolver upstream pcap after burst")
    print()

    (
        prepared_queries,
        domain_counter,
        qtype_counter,
        scenario_counter,
        domain_length_counter,
    ) = prepare_queries(domains, weights, short_domains)
    print(f"prepared queries  : {len(prepared_queries)}")
    print("Normal DNS query generator burst sending started.", flush=True)

    start_time, sent_count, error_count = send_prepared_queries(prepared_queries, target_qps)

    print_final_summary(
        start_time,
        sent_count,
        sent_count - error_count,
        error_count,
        domain_counter,
        qtype_counter,
        scenario_counter,
        Counter(),
        domain_length_counter,
        0,
    )


if __name__ == "__main__":
    main()
