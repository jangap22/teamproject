from __future__ import annotations

from scapy.all import DNS, sniff


def start_capture(interface: str, bpf_filter: str, on_dns_packet) -> None:
    print(f"[sniffer] capture interface: {interface}", flush=True)
    print(f"[sniffer] bpf filter: {bpf_filter}", flush=True)

    def _handle(packet):
        if packet.haslayer(DNS):
            on_dns_packet(packet)

    sniff(iface=interface, filter=bpf_filter, prn=_handle, store=False)
