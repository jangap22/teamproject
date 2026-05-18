#!/usr/bin/env python3
from scapy.all import sniff, DNS, IP
import os
import random
import socket
import time

def require_env(name):
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"[!] Missing required environment variable: {name}")
    return value

INTERFACE = require_env("SNIFF_INTERFACE")
ALERT_HOST = require_env("ALERT_HOST")
ALERT_PORT = int(require_env("ALERT_PORT"))
AUTH_IP = require_env("AUTH_IP")
RESOLVER_IP = require_env("RESOLVER_IP")
DNS_PORT = int(require_env("DNS_PORT"))

alert_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

last_sec = int(time.time())
current_sec_pkt_count = 0
last_sec_pkt_rate = 0

def get_sample_probability(rate):
    return max(0.005, 100.0 / (rate + 100.0))

def dummy_ai_model(packet):
    return random.choices([0, 1], weights=[0.995, 0.005])[0]

def extract_injected_zone(packet):
    if packet.haslayer(DNS) and packet[DNS].arcount > 0:
        ar_record = packet[DNS].ar
        if hasattr(ar_record, 'rrname') and hasattr(ar_record, 'rdata'):
            try:
                domain = ar_record.rrname.decode('utf-8') if isinstance(ar_record.rrname, bytes) else str(ar_record.rrname)
                fake_ip = ar_record.rdata.decode('utf-8') if isinstance(ar_record.rdata, bytes) else str(ar_record.rdata)
                return f"{domain} -> {fake_ip}"
            except Exception:
                return "Parsing Error"
    return "No Additional Record"

def send_alert(message):
    alert_sock.sendto(message.encode("utf-8"), (ALERT_HOST, ALERT_PORT))

def process_packet(packet):
    global last_sec, current_sec_pkt_count, last_sec_pkt_rate
    
    now = int(time.time())
    if now != last_sec:
        last_sec_pkt_rate = current_sec_pkt_count
        current_sec_pkt_count = 0
        last_sec = now
        
    if packet.haslayer(DNS) and packet.haslayer(IP):
        if packet[IP].src == AUTH_IP and packet[IP].dst == RESOLVER_IP:
            current_sec_pkt_count += 1
            
            prob = get_sample_probability(last_sec_pkt_rate)
            
            if random.random() <= prob:
                is_attack = dummy_ai_model(packet)
                
                if is_attack == 1:
                    zone_info = extract_injected_zone(packet)
                    message = f"DNS injection suspected: {zone_info}"
                    send_alert(message)
                    print(f"1 | {message}")
                else:
                    print("0")

print("[*] Sniffer NIDS Daemon is running...")
print(f"[*] Monitoring UDP port {DNS_PORT} on {INTERFACE}")
print(f"[*] Sending alerts to {ALERT_HOST}:{ALERT_PORT}/udp")
sniff(iface=INTERFACE, filter=f"udp port {DNS_PORT}", prn=process_packet, store=False)
