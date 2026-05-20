from __future__ import annotations

import math
import time
from collections import Counter
from dataclasses import dataclass

from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6, TCP, UDP

from schema import CSV_COLUMNS


@dataclass
class FeatureContext:
    target_domain: str | None = None
    fake_ip: str | None = None
    window_seconds: float = 1.0


def to_float(value, default=-1):
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def to_int(value, default=-1):
    try:
        if value is None:
            return default
        return int(str(value), 0)
    except Exception:
        return default


def entropy(value: str) -> float:
    if not value:
        return 0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def normalize_domain(value) -> str:
    if not isinstance(value, str):
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        else:
            return ""
    return value.strip().lower().rstrip(".")


def same_or_subdomain(child, parent) -> int:
    child = normalize_domain(child)
    parent = normalize_domain(parent)
    if not child or not parent:
        return 0
    return int(child == parent or child.endswith("." + parent))


def _iter_rr(rrset, count):
    current = rrset
    for _ in range(int(count or 0)):
        if current is None:
            return
        yield current
        current = getattr(current, "payload", None)
        if not isinstance(current, DNSRR):
            return


def _first_question(dns):
    question = dns.qd
    if question is None or int(getattr(dns, "qdcount", 0) or 0) <= 0:
        return None
    try:
        if getattr(question, "qname", None) is not None:
            return question
    except (IndexError, AttributeError, TypeError):
        return None
    try:
        first = question[0]
    except (IndexError, TypeError, KeyError):
        return None
    if getattr(first, "qname", None) is not None:
        return first
    return None


def _dns_type_value(rr) -> str:
    value = getattr(rr, "type", "")
    return str(int(value)) if isinstance(value, int) else str(value)


def _record_name(rr) -> str:
    for attr in ("rrname", "qname"):
        value = getattr(rr, attr, None)
        if value:
            return normalize_domain(value)
    return ""


def _record_addr(rr) -> str:
    value = getattr(rr, "rdata", "")
    if value is None:
        return ""
    return str(value)


def _record_cname(rr) -> str:
    if _dns_type_value(rr) != "5":
        return ""
    return normalize_domain(getattr(rr, "rdata", ""))


def _record_ns(rr) -> str:
    if _dns_type_value(rr) != "2":
        return ""
    return normalize_domain(getattr(rr, "rdata", ""))


def collect_dns_records_from_scapy(dns) -> list[dict]:
    records = []
    sections = (
        ("answer", dns.an, dns.ancount),
        ("authority", dns.ns, dns.nscount),
        ("additional", dns.ar, dns.arcount),
    )
    for section, rrset, count in sections:
        for rr in _iter_rr(rrset, count):
            records.append(
                {
                    "section": section,
                    "name": _record_name(rr),
                    "type": _dns_type_value(rr),
                    "ttl": to_float(getattr(rr, "ttl", None), default=math.nan),
                    "addr": _record_addr(rr),
                    "cname": _record_cname(rr),
                    "ns": _record_ns(rr),
                }
            )
    return records


def get_query_name_from_scapy(dns) -> str:
    question = _first_question(dns)
    return normalize_domain(getattr(question, "qname", ""))


def _ttl_stats(ttls: list[float]) -> tuple[float, float, float, float]:
    if not ttls:
        return -1, -1, -1, -1
    ttl_min = min(ttls)
    ttl_max = max(ttls)
    ttl_mean = sum(ttls) / len(ttls)
    ttl_std = math.sqrt(sum((ttl - ttl_mean) ** 2 for ttl in ttls) / len(ttls))
    return ttl_min, ttl_max, ttl_mean, ttl_std


def packet_to_dns_features(packet, fake_ip: str | None = None) -> dict:
    dns = packet[DNS]
    ip = packet[IP] if packet.haslayer(IP) else None
    ipv6 = packet[IPv6] if packet.haslayer(IPv6) else None
    udp = packet[UDP] if packet.haslayer(UDP) else None
    tcp = packet[TCP] if packet.haslayer(TCP) else None

    query_name = get_query_name_from_scapy(dns)
    records = collect_dns_records_from_scapy(dns)

    src_ip = str(ip.src if ip else ipv6.src if ipv6 else "")
    dst_ip = str(ip.dst if ip else ipv6.dst if ipv6 else "")
    if fake_ip and src_ip == fake_ip:
        src_ip = ""
    if fake_ip and dst_ip == fake_ip:
        dst_ip = ""

    section_count = Counter(record["section"] for record in records)
    type_count = Counter((record["section"], record["type"]) for record in records)
    ttls = [record["ttl"] for record in records if not math.isnan(record["ttl"])]
    ttl_min, ttl_max, ttl_mean, ttl_std = _ttl_stats(ttls)

    answer_names = [record["name"] for record in records if record["section"] == "answer" and record["name"]]
    authority_names = [record["name"] for record in records if record["section"] == "authority" and record["name"]]
    additional_names = [record["name"] for record in records if record["section"] == "additional" and record["name"]]
    all_names = answer_names + authority_names + additional_names

    additional_out_of_bailiwick = sum(
        1 for name in additional_names if query_name and not same_or_subdomain(name, query_name)
    )
    answer_matches_query = sum(1 for name in answer_names if same_or_subdomain(name, query_name))

    ip_len = to_float(getattr(ip, "len", None), default=-1) if ip else -1
    ip_ttl = to_float(getattr(ip, "ttl", None), default=-1) if ip else -1
    ip_proto = to_float(getattr(ip, "proto", None), default=-1) if ip else -1
    udp_length = to_float(getattr(udp, "len", None), default=-1) if udp else -1
    tcp_len = to_float(len(tcp.payload), default=-1) if tcp else -1
    src_port = to_float(udp.sport if udp else tcp.sport if tcp else None)
    dst_port = to_float(udp.dport if udp else tcp.dport if tcp else None)

    return {
        "frame_len": to_float(len(packet)),
        "frame_cap_len": to_float(len(packet)),
        "ip_len": ip_len,
        "ip_ttl": ip_ttl,
        "ip_proto": ip_proto,
        "udp_length": udp_length,
        "tcp_len": tcp_len,
        "src_port": src_port,
        "dst_port": dst_port,
        "dns_id": to_int(dns.id),
        "dns_flags_authoritative": to_int(dns.aa),
        "dns_flags_truncated": to_int(dns.tc),
        "dns_flags_recdesired": to_int(dns.rd),
        "dns_flags_recavail": to_int(dns.ra),
        "dns_flags_rcode": to_int(dns.rcode),
        "dns_count_queries": to_int(dns.qdcount),
        "dns_count_answers": to_int(dns.ancount),
        "dns_count_auth_rr": to_int(dns.nscount),
        "dns_count_add_rr": to_int(dns.arcount),
        "record_total": len(records),
        "answer_record_count": section_count["answer"],
        "authority_record_count": section_count["authority"],
        "additional_record_count": section_count["additional"],
        "answer_A_count": type_count[("answer", "1")],
        "answer_NS_count": type_count[("answer", "2")],
        "answer_CNAME_count": type_count[("answer", "5")],
        "answer_AAAA_count": type_count[("answer", "28")],
        "authority_NS_count": type_count[("authority", "2")],
        "authority_SOA_count": type_count[("authority", "6")],
        "additional_A_count": type_count[("additional", "1")],
        "additional_AAAA_count": type_count[("additional", "28")],
        "additional_NS_count": type_count[("additional", "2")],
        "additional_CNAME_count": type_count[("additional", "5")],
        "ttl_min": ttl_min,
        "ttl_max": ttl_max,
        "ttl_mean": ttl_mean,
        "ttl_std": ttl_std,
        "query_name_len": len(query_name),
        "query_label_count": query_name.count(".") + 1 if query_name else 0,
        "query_entropy": entropy(query_name),
        "unique_record_name_count": len(set(all_names)),
        "answer_matches_query_count": answer_matches_query,
        "additional_out_of_bailiwick_count": additional_out_of_bailiwick,
        "has_answer": int(section_count["answer"] > 0),
        "has_authority": int(section_count["authority"] > 0),
        "has_additional": int(section_count["additional"] > 0),
        "has_additional_A": int(type_count[("additional", "1")] > 0),
        "has_authority_NS": int(type_count[("authority", "2")] > 0),
    }


def _collect_answer_ips(dns) -> list[str]:
    values = []
    for rr in _iter_rr(dns.an, dns.ancount):
        if getattr(rr, "type", None) in {1, 28}:
            values.append(str(getattr(rr, "rdata", "")))
    return values


def extract_dns_features(
    packet,
    packet_index: int,
    context: FeatureContext | None = None,
    label: str | int | None = None,
    attack_type: str | None = None,
    scenario_tag: str | None = None,
) -> dict | None:
    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]
    ip = packet[IP] if packet.haslayer(IP) else None
    ipv6 = packet[IPv6] if packet.haslayer(IPv6) else None
    udp = packet[UDP] if packet.haslayer(UDP) else None
    tcp = packet[TCP] if packet.haslayer(TCP) else None

    model_features = packet_to_dns_features(packet, fake_ip=context.fake_ip if context else None)
    qname = get_query_name_from_scapy(dns)
    answer_ips = _collect_answer_ips(dns)
    src_ip = str(ip.src if ip else ipv6.src if ipv6 else "")
    dst_ip = str(ip.dst if ip else ipv6.dst if ipv6 else "")
    transport = "udp" if udp else "tcp" if tcp else "other"
    src_port = int(udp.sport if udp else tcp.sport if tcp else 0)
    dst_port = int(udp.dport if udp else tcp.dport if tcp else 0)

    row = {
        "packet_index": packet_index,
        "timestamp": float(getattr(packet, "time", time.time())),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "transport": transport,
        "qname": qname,
        "answer_ips": ";".join(answer_ips),
        "dns_id": int(dns.id),
        "label": label,
        "attack_type": attack_type,
        "scenario_tag": scenario_tag,
        **model_features,
        # Compatibility fields for IDS fallback rules and logs. These are not used
        # by the model unless the artifact explicitly asks for them.
        "is_response": int(dns.qr or 0),
        "opcode": int(dns.opcode or 0),
        "rcode": int(dns.rcode or 0),
        "structural_rr_count": int((dns.ancount or 0) + (dns.nscount or 0) + (dns.arcount or 0)),
        "min_ttl": model_features["ttl_min"],
        "max_ttl": model_features["ttl_max"],
    }
    return {column: row.get(column) for column in CSV_COLUMNS}
