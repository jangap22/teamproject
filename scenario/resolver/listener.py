#!/usr/bin/env python3
import json
import os
import socket

def require_env(name):
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value

UDP_IP = require_env("ALERT_BIND_HOST")
UDP_PORT = int(require_env("ALERT_PORT"))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print("[*] Resolver Alert Listener is active...")
print(f"[*] Waiting for emergency signals on {UDP_IP}:{UDP_PORT}/udp")
print("-" * 50)

while True:
    # 스나이퍼로부터 메시지가 올 때까지 대기
    data, addr = sock.recvfrom(65535)
    message = data.decode('utf-8', errors='replace')
    
    try:
        payload = json.loads(message)
        print(
            "[IDS ALERT] "
            f"{payload.get('type', 'unknown_alert')} "
            f"qname={payload.get('qname')} "
            f"src_ip={payload.get('src_ip')} "
            f"dns_id={payload.get('dns_id')} "
            f"reason={payload.get('reason')} "
            f"severity={payload.get('severity')}",
            flush=True,
        )
    except json.JSONDecodeError:
        print(f"[EMERGENCY PUSH from {addr[0]}:{addr[1]}] {message}", flush=True)
