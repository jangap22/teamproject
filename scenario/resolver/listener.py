#!/usr/bin/env python3
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
    data, addr = sock.recvfrom(1024)
    message = data.decode('utf-8')
    
    # 알람 수신 시 터미널에 강력하게 경고 표출
    print(f"[EMERGENCY PUSH from {addr[0]}:{addr[1]}] {message}")
