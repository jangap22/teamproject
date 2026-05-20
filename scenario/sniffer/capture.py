from __future__ import annotations

from scapy.all import DNS, TCP, UDP, bind_layers, sniff


HARDCODED_DNS_PORTS = (10053, 20053, 30053, 1025)


def bind_dns_ports() -> None:
    for port in HARDCODED_DNS_PORTS:
        bind_layers(UDP, DNS, sport=port)
        bind_layers(UDP, DNS, dport=port)
        bind_layers(TCP, DNS, sport=port)
        bind_layers(TCP, DNS, dport=port)


def start_capture(interface: str, bpf_filter: str, on_dns_packet) -> None:
    bind_dns_ports()
    print(f"[sniffer] capture interface: {interface}", flush=True)
    print(f"[sniffer] bpf filter: {bpf_filter or '<none>'}", flush=True)
    print(f"[sniffer] dns decode ports: {HARDCODED_DNS_PORTS}", flush=True)

    def _handle(packet):
        udp = packet[UDP] if packet.haslayer(UDP) else None
        tcp = packet[TCP] if packet.haslayer(TCP) else None
        src_port = int(udp.sport if udp else tcp.sport if tcp else 0)
        dst_port = int(udp.dport if udp else tcp.dport if tcp else 0)
        if src_port not in HARDCODED_DNS_PORTS and dst_port not in HARDCODED_DNS_PORTS:
            return
        if packet.haslayer(DNS):
            on_dns_packet(packet)

    sniff_filter = bpf_filter or None
    sniff(iface=interface, filter=sniff_filter, prn=_handle, store=False)
