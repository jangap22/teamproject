#!/usr/bin/env python3
from __future__ import annotations

import os
import time
import traceback

from alert import AlertSender, build_alert_payload
from capture import start_capture
from detector import ModelDetector
from features import FeatureContext, extract_dns_features
from sampling import RuntimeSampler, RuntimeSamplingConfig
from schema import CSV_COLUMNS, DETECTION_COLUMNS, SAMPLING_DROP_COLUMNS
from writer import CsvAppender, JsonlAppender


HARDCODED_BPF_FILTER = (
    "host 192.168.219.112 and "
    "(udp port 10053 or tcp port 10053 or "
    "udp port 20053 or tcp port 20053 or "
    "udp port 30053 or tcp port 30053)"
)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def env_value(*names: str, default: str | None = None) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value is not None and value != "":
            return value
    return default


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    return default if value is None or value == "" else int(value)


def env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    return default if value is None or value == "" else float(value)


def env_set(name: str, default: set[str] | None = None) -> set[str]:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default or set()
    return {item.strip() for item in value.split(",") if item.strip()}


def build_detection_row(feature_row: dict, prediction: dict) -> dict:
    row = {
        "timestamp": feature_row.get("timestamp"),
        "src_ip": feature_row.get("src_ip"),
        "dst_ip": feature_row.get("dst_ip"),
        "qname": feature_row.get("qname"),
        "dns_id": feature_row.get("dns_id"),
        "src_port": feature_row.get("src_port"),
        "dst_port": feature_row.get("dst_port"),
        "transport": feature_row.get("transport"),
        "label": feature_row.get("label"),
        "attack_type": feature_row.get("attack_type"),
        "scenario_tag": feature_row.get("scenario_tag"),
    }
    row.update(prediction)
    return row


def add_sampler_stats(row: dict, sampler: RuntimeSampler, sampling_enabled: bool, inspected: bool, reason: str) -> dict:
    stats = sampler.get_stats()
    row.update(
        {
            "sampling_enabled": sampling_enabled,
            "inspected": inspected,
            "sampling_reason": reason,
            "sampler_seen_count": stats["seen"],
            "sampler_inspected_count": stats["inspected"],
            "sampler_dropped_count": stats["dropped"],
        }
    )
    return row


def main() -> None:
    dns_port = int(env_value("DNS_PORT", default="53"))
    resolver_ip = env_value("SNIFFER_RESOLVER_IP", "RESOLVER_IP")
    resolver_port = int(env_value("SNIFFER_RESOLVER_PORT", "DNS_PORT", default=str(dns_port)))
    interface = env_value("SNIFFER_INTERFACE", "SNIFF_INTERFACE", default="eth0")
    bpf_filter = HARDCODED_BPF_FILTER
    mode = env_value("SNIFFER_MODE", default="ids").lower()
    save_feature_csv = env_bool("SNIFFER_SAVE_FEATURE_CSV", default=False)
    save_detection_csv = env_bool("SNIFFER_SAVE_DETECTION_CSV", default=True)
    log_sampling_drops = env_bool("SNIFFER_LOG_SAMPLING_DROPS", default=False)
    output_csv = env_value("SNIFFER_FEATURE_CSV", "SNIFFER_OUTPUT_CSV", default="/data/captures/features.csv")
    detection_csv = env_value("SNIFFER_DETECTION_CSV", default="/data/detections/detection_results.csv")
    sampling_drop_csv = env_value("SNIFFER_SAMPLING_DROP_LOG", default="/data/detections/sampling_drops.csv")
    alert_file = env_value("SNIFFER_ALERT_FILE", default="/data/alerts/ids_alerts.jsonl")
    model_path = env_value("SNIFFER_MODEL_PATH", default="/models/randomforest_model.joblib")
    label = env_value("SNIFFER_LABEL")
    attack_type = env_value("SNIFFER_ATTACK_TYPE")
    scenario_tag = env_value("SNIFFER_SCENARIO_TAG")

    if mode not in {"ids", "detect"}:
        raise SystemExit(f"Unsupported SNIFFER_MODE={mode}. Use ids or detect.")

    authoritative_ips = env_set("SNIFFER_AUTH_IPS", default=env_set("AUTH_IPS"))
    for ip_name in ("AUTH_IP", "EXTERNAL_AUTH_IP"):
        ip_value = env_value(ip_name)
        if ip_value:
            authoritative_ips.add(ip_value)

    detector = ModelDetector(
        model_path,
        resolver_ip=resolver_ip,
        authoritative_ips=authoritative_ips,
        window_seconds=env_float("SNIFFER_WINDOW_SECONDS", 2.0),
        duplicate_txid_threshold=env_int("SNIFFER_DUPLICATE_TXID_THRESHOLD", 3),
        response_burst_threshold=env_int("SNIFFER_RESPONSE_BURST_THRESHOLD", 50),
        rf_proba_threshold=env_float("SNIFFER_RF_PROBA_THRESHOLD", 0.7),
        rr_count_threshold=env_int("SNIFFER_RR_COUNT_THRESHOLD", 25),
        ttl_low_threshold=env_int("SNIFFER_TTL_LOW_THRESHOLD", 0),
        ttl_high_threshold=env_int("SNIFFER_TTL_HIGH_THRESHOLD", 86400),
    )
    feature_writer = CsvAppender(output_csv if save_feature_csv else None, CSV_COLUMNS)
    detection_writer = CsvAppender(detection_csv if save_detection_csv else None, DETECTION_COLUMNS)
    sampling_drop_writer = CsvAppender(sampling_drop_csv if log_sampling_drops else None, SAMPLING_DROP_COLUMNS)
    alert_log_writer = JsonlAppender(alert_file)
    alert_sender = AlertSender(
        enabled=env_bool("SNIFFER_ALERT_ENABLED", True),
        method=env_value("SNIFFER_ALERT_METHOD", default="udp").lower(),
        host=env_value("SNIFFER_ALERT_HOST", "ALERT_HOST", default="127.0.0.1"),
        port=env_int("SNIFFER_ALERT_PORT", int(env_value("ALERT_PORT", default="9999"))),
        url=env_value("SNIFFER_ALERT_URL"),
        file_path=alert_file,
        cooldown_seconds=env_float("SNIFFER_ALERT_COOLDOWN_SECONDS", 1.0),
    )
    context = FeatureContext(
        target_domain=env_value("SNIFFER_TARGET_DOMAIN", "TARGET_DOMAIN"),
        fake_ip=env_value("SNIFFER_FAKE_IP", "FAKE_WEB_IP"),
        window_seconds=env_float("SNIFFER_WINDOW_SECONDS", 2.0),
    )
    sampling_enabled = parse_bool(
        env_value("SNIFFER_SAMPLING_ENABLED", "SNIFFER_ENABLE_SAMPLING"),
        default=True,
    )
    sampler = RuntimeSampler(
        RuntimeSamplingConfig(
            enabled=sampling_enabled,
            base_sample_rate=env_float("SNIFFER_BASE_SAMPLE_RATE", 1.0),
            inspect_all_responses=env_bool("SNIFFER_INSPECT_ALL_RESPONSES", True),
            response_sample_rate=env_float("SNIFFER_RESPONSE_SAMPLE_RATE", 1.0),
            query_sample_rate=env_float("SNIFFER_QUERY_SAMPLE_RATE", 0.1),
            always_inspect_suspicious=env_bool("SNIFFER_ALWAYS_INSPECT_SUSPICIOUS", True),
            random_seed=env_int("SNIFFER_SAMPLING_RANDOM_SEED", 42),
            rate_limit_window_seconds=env_float("SNIFFER_RATE_LIMIT_WINDOW_SECONDS", 1.0),
            max_per_qname_per_window=env_int("SNIFFER_MAX_PER_QNAME_PER_WINDOW", 50),
            max_per_signature_per_window=env_int("SNIFFER_MAX_PER_SIGNATURE_PER_WINDOW", 100),
            duplicate_dns_id_window_seconds=env_float("SNIFFER_DUPLICATE_DNS_ID_WINDOW_SECONDS", 2.0),
            duplicate_dns_id_threshold=env_int("SNIFFER_DUPLICATE_DNS_ID_THRESHOLD", 2),
            response_burst_window_seconds=env_float("SNIFFER_RESPONSE_BURST_WINDOW_SECONDS", 1.0),
            response_burst_threshold=env_int("SNIFFER_RESPONSE_BURST_THRESHOLD", 100),
            large_section_count_threshold=env_int("SNIFFER_LARGE_SECTION_COUNT_THRESHOLD", 10),
            extreme_ttl_low=env_int("SNIFFER_EXTREME_TTL_LOW", 0),
            extreme_ttl_high=env_int("SNIFFER_EXTREME_TTL_HIGH", 86400),
        )
    )
    stats_interval_seconds = env_float("SNIFFER_STATS_INTERVAL_SECONDS", 10.0)
    state = {"packet_index": 0, "last_stats_at": time.monotonic()}

    print("[sniffer] DNS IDS sniffer started", flush=True)
    print(f"[sniffer] mode={mode}", flush=True)
    print(f"[sniffer] resolver={resolver_ip}:{resolver_port}", flush=True)
    print(f"[sniffer] authoritative_ips={sorted(authoritative_ips)}", flush=True)
    print(f"[sniffer] sampling_enabled={sampling_enabled}", flush=True)
    print(f"[sniffer] feature csv={output_csv if feature_writer.is_enabled() else 'disabled'}", flush=True)
    print(f"[sniffer] detection csv={detection_csv if detection_writer.is_enabled() else 'disabled'}", flush=True)
    print(f"[sniffer] alert file={alert_file}", flush=True)
    print(f"[sniffer] alert method={alert_sender.method}", flush=True)
    print(f"[sniffer] model_status={detector.model_status}", flush=True)

    def on_packet(packet) -> None:
        try:
            inspect, sampling_reason = sampler.should_inspect_packet(packet)
            now_monotonic = time.monotonic()
            if now_monotonic - state["last_stats_at"] >= stats_interval_seconds:
                print(f"[sniffer] sampling_stats={sampler.get_stats()}", flush=True)
                state["last_stats_at"] = now_monotonic

            if not inspect:
                if sampling_drop_writer.is_enabled():
                    sampling_drop_writer.append(sampler.packet_summary(packet, sampling_reason))
                return

            state["packet_index"] += 1
            row = extract_dns_features(
                packet,
                packet_index=state["packet_index"],
                context=context,
                label=label,
                attack_type=attack_type,
                scenario_tag=scenario_tag,
            )
            if row is None:
                return
            row["sampling_reason"] = sampling_reason

            if feature_writer.is_enabled():
                feature_writer.append(row)

            detection = detector.detect(row, sampled=True)
            detection["sampled"] = True
            detection["sampling_reason"] = sampling_reason
            detection_row = build_detection_row(row, detection)
            add_sampler_stats(detection_row, sampler, sampling_enabled, True, sampling_reason)
            detection_writer.append(detection_row)

            status_bit = 1 if detection.get("suspicious") else 0
            print(
                "[sniffer] "
                f"{status_bit} "
                f"suspicious={detection.get('suspicious')} "
                f"inspected=True "
                f"sampling_reason={sampling_reason} "
                f"{row.get('src_ip')}:{row.get('src_port')} -> {row.get('dst_ip')}:{row.get('dst_port')} "
                f"qname={row.get('qname')} "
                f"dns_id={row.get('dns_id')} "
                f"prediction={detection.get('predicted_label')} "
                f"probability={detection.get('predicted_probability')} "
                f"status={detection.get('model_status')} "
                f"reason={detection.get('reason')}",
                flush=True,
            )

            if detection.get("suspicious"):
                payload = build_alert_payload(row, detection)
                sent = alert_sender.send(payload)
                if sent and alert_sender.method != "file":
                    payload["alert_sent"] = True
                    alert_log_writer.append(payload)
                print(f"[sniffer] alert_sent={sent} reason={payload.get('reason')}", flush=True)
        except Exception:
            print("[sniffer] packet processing failed", flush=True)
            traceback.print_exc()

    start_capture(interface=interface, bpf_filter=bpf_filter, on_dns_packet=on_packet)


if __name__ == "__main__":
    main()
