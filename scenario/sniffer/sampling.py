from __future__ import annotations

import random
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field

from scapy.all import DNS, DNSRR, IP, TCP, UDP


@dataclass
class RuntimeSamplingConfig:
    enabled: bool = True
    base_sample_rate: float = 1.0
    inspect_all_responses: bool = True
    response_sample_rate: float = 1.0
    query_sample_rate: float = 0.1
    always_inspect_suspicious: bool = True
    random_seed: int | None = 42
    rate_limit_window_seconds: float = 1.0
    max_per_qname_per_window: int = 50
    max_per_signature_per_window: int = 100
    duplicate_dns_id_window_seconds: float = 2.0
    duplicate_dns_id_threshold: int = 2
    response_burst_window_seconds: float = 1.0
    response_burst_threshold: int = 100
    large_section_count_threshold: int = 10
    extreme_ttl_low: int = 0
    extreme_ttl_high: int = 86400
    check_abnormal_opcode_rcode: bool = True


@dataclass
class PacketSketch:
    is_dns: bool = False
    timestamp: float = 0.0
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    transport: str | None = None
    qname: str = ""
    qtype: int = 0
    dns_id: int | None = None
    is_response: bool = False
    opcode: int = 0
    rcode: int = 0
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0
    signature: tuple = field(default_factory=tuple)


def _normalize_name(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value).rstrip(".")


def _first_question(dns):
    question = dns.qd
    if hasattr(question, "qname"):
        return question
    if isinstance(question, (list, tuple)) and question and hasattr(question[0], "qname"):
        return question[0]
    return None


def _iter_rr_limited(rrset, count, limit=8):
    current = rrset
    for _ in range(min(int(count or 0), limit)):
        if current is None:
            return
        yield current
        current = getattr(current, "payload", None)
        if not isinstance(current, DNSRR):
            return


class RuntimeSampler:
    def __init__(self, config: RuntimeSamplingConfig):
        self.config = config
        self.random = random.Random(config.random_seed)
        self.qname_events: defaultdict[str, deque] = defaultdict(deque)
        self.signature_events: defaultdict[tuple, deque] = defaultdict(deque)
        self.response_key_events: defaultdict[tuple, deque] = defaultdict(deque)
        self.response_events: deque = deque()
        self.stats = Counter()
        self.reasons = Counter()

    def should_inspect_packet(self, pkt) -> tuple[bool, str]:
        self.stats["seen"] += 1
        sketch = self._sketch(pkt)
        if not sketch.is_dns:
            return self._decision(False, "not_dns")

        self.update_state(sketch)
        suspicious, suspicious_reason = self.cheap_suspicious_check(sketch)
        if suspicious and self.config.always_inspect_suspicious:
            return self._decision(True, suspicious_reason)

        if not self.config.enabled:
            return self._decision(True, "sampling_disabled")

        if sketch.is_response:
            if self.config.inspect_all_responses:
                return self._decision(True, "dns_response_always_inspect")
            if self._sample(self.config.response_sample_rate):
                return self._decision(True, "sampled_response")
            return self._decision(False, "sample_dropped")

        if self._qname_rate_limited(sketch):
            return self._decision(False, "qname_rate_limited")
        if self._signature_rate_limited(sketch):
            return self._decision(False, "signature_rate_limited")

        query_rate = self.config.query_sample_rate * self.config.base_sample_rate
        if self._sample(query_rate):
            return self._decision(True, "sampled_query")
        return self._decision(False, "sample_dropped")

    def cheap_suspicious_check(self, pkt) -> tuple[bool, str]:
        sketch = pkt if isinstance(pkt, PacketSketch) else self._sketch(pkt)
        if not sketch.is_dns:
            return False, "not_dns"
        if not sketch.is_response:
            return False, "not_suspicious_query"

        key = (sketch.qname, sketch.dns_id)
        if len(self.response_key_events[key]) >= self.config.duplicate_dns_id_threshold:
            return True, "cheap_rule_duplicate_dns_id"

        if len(self.response_events) >= self.config.response_burst_threshold:
            return True, "cheap_rule_response_burst"

        section_count = sketch.ancount + sketch.nscount + sketch.arcount
        if section_count >= self.config.large_section_count_threshold:
            return True, "cheap_rule_large_section_count"

        if self.config.check_abnormal_opcode_rcode:
            if sketch.opcode != 0:
                return True, "cheap_rule_abnormal_opcode"
            if sketch.rcode not in {0, 2, 3, 5}:
                return True, "cheap_rule_abnormal_rcode"

        ttl_reason = self._extreme_ttl_reason(sketch.raw_packet)
        if ttl_reason:
            return True, ttl_reason

        return False, "cheap_rule_no_alert"

    def update_state(self, pkt) -> None:
        sketch = pkt if isinstance(pkt, PacketSketch) else self._sketch(pkt)
        if not sketch.is_dns:
            return

        now = sketch.timestamp
        self._append_pruned(
            self.qname_events[sketch.qname],
            now,
            self.config.rate_limit_window_seconds,
        )
        self._append_pruned(
            self.signature_events[sketch.signature],
            now,
            self.config.rate_limit_window_seconds,
        )

        if sketch.is_response:
            self._append_pruned(
                self.response_key_events[(sketch.qname, sketch.dns_id)],
                now,
                self.config.duplicate_dns_id_window_seconds,
            )
            self._append_pruned(
                self.response_events,
                now,
                self.config.response_burst_window_seconds,
            )

    def get_stats(self) -> dict:
        seen = int(self.stats["seen"])
        inspected = int(self.stats["inspected"])
        dropped = int(self.stats["dropped"])
        return {
            "seen": seen,
            "inspected": inspected,
            "dropped": dropped,
            "inspect_rate": inspected / seen if seen else 0.0,
            "reasons": dict(self.reasons),
        }

    def packet_summary(self, pkt, reason: str) -> dict:
        sketch = self._sketch(pkt)
        return {
            "timestamp": sketch.timestamp,
            "src_ip": sketch.src_ip,
            "dst_ip": sketch.dst_ip,
            "src_port": sketch.src_port,
            "dst_port": sketch.dst_port,
            "transport": sketch.transport,
            "qname": sketch.qname,
            "dns_id": sketch.dns_id,
            "is_response": int(sketch.is_response),
            "sampling_reason": reason,
        }

    def _decision(self, inspect: bool, reason: str) -> tuple[bool, str]:
        self.stats["inspected" if inspect else "dropped"] += 1
        self.reasons[reason] += 1
        return inspect, reason

    def _sample(self, rate: float) -> bool:
        return self.random.random() <= max(0.0, min(1.0, rate))

    def _qname_rate_limited(self, sketch: PacketSketch) -> bool:
        return len(self.qname_events[sketch.qname]) > self.config.max_per_qname_per_window

    def _signature_rate_limited(self, sketch: PacketSketch) -> bool:
        return len(self.signature_events[sketch.signature]) > self.config.max_per_signature_per_window

    def _append_pruned(self, queue: deque, timestamp: float, window_seconds: float) -> None:
        cutoff = timestamp - window_seconds
        while queue and queue[0] < cutoff:
            queue.popleft()
        queue.append(timestamp)

    def _sketch(self, pkt) -> PacketSketch:
        sketch = PacketSketch(timestamp=float(getattr(pkt, "time", time.time())))
        sketch.raw_packet = pkt
        if not pkt.haslayer(DNS):
            return sketch

        dns = pkt[DNS]
        udp = pkt[UDP] if pkt.haslayer(UDP) else None
        tcp = pkt[TCP] if pkt.haslayer(TCP) else None
        ip = pkt[IP] if pkt.haslayer(IP) else None
        question = _first_question(dns)
        qtype = int(getattr(question, "qtype", 0) or 0)

        sketch.is_dns = True
        sketch.src_ip = str(ip.src) if ip else None
        sketch.dst_ip = str(ip.dst) if ip else None
        sketch.transport = "udp" if udp else "tcp" if tcp else None
        sketch.src_port = int(udp.sport if udp else tcp.sport if tcp else 0)
        sketch.dst_port = int(udp.dport if udp else tcp.dport if tcp else 0)
        sketch.qname = _normalize_name(getattr(question, "qname", ""))
        sketch.qtype = qtype
        sketch.dns_id = int(dns.id)
        sketch.is_response = int(dns.qr or 0) == 1
        sketch.opcode = int(dns.opcode or 0)
        sketch.rcode = int(dns.rcode or 0)
        sketch.qdcount = int(dns.qdcount or 0)
        sketch.ancount = int(dns.ancount or 0)
        sketch.nscount = int(dns.nscount or 0)
        sketch.arcount = int(dns.arcount or 0)
        sketch.signature = (
            int(sketch.is_response),
            sketch.opcode,
            sketch.rcode,
            sketch.qdcount,
            sketch.ancount,
            sketch.nscount,
            sketch.arcount,
            sketch.qtype,
        )
        return sketch

    def _extreme_ttl_reason(self, pkt) -> str | None:
        if not pkt.haslayer(DNS):
            return None
        dns = pkt[DNS]
        for section, count in ((dns.an, dns.ancount), (dns.ns, dns.nscount), (dns.ar, dns.arcount)):
            for rr in _iter_rr_limited(section, count):
                ttl = getattr(rr, "ttl", None)
                if ttl is None:
                    continue
                ttl = int(ttl)
                if ttl <= self.config.extreme_ttl_low:
                    return "cheap_rule_extreme_low_ttl"
                if ttl >= self.config.extreme_ttl_high:
                    return "cheap_rule_extreme_high_ttl"
        return None
