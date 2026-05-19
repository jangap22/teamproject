from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path


class AlertSender:
    def __init__(
        self,
        *,
        enabled: bool,
        method: str,
        host: str | None = None,
        port: int | None = None,
        url: str | None = None,
        file_path: str | None = None,
        cooldown_seconds: float = 1.0,
    ):
        self.enabled = enabled
        self.method = method
        self.host = host
        self.port = port
        self.url = url
        self.file_path = Path(file_path) if file_path else None
        self.cooldown_seconds = cooldown_seconds
        self.last_sent_at: dict[str, float] = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _cooldown_key(self, payload: dict) -> str:
        return "|".join(
            str(payload.get(name) or "")
            for name in ("type", "src_ip", "dst_ip", "qname", "dns_id", "reason")
        )

    def _is_suppressed(self, payload: dict) -> bool:
        now = time.monotonic()
        key = self._cooldown_key(payload)
        previous = self.last_sent_at.get(key)
        if previous is not None and now - previous < self.cooldown_seconds:
            return True
        self.last_sent_at[key] = now
        return False

    def send(self, payload: dict) -> bool:
        if not self.enabled:
            return False
        if self._is_suppressed(payload):
            return False

        try:
            if self.method == "udp":
                return self._send_udp(payload)
            if self.method == "http":
                return self._send_http(payload)
            if self.method == "file":
                return self._send_file(payload)
            print(f"[sniffer] unsupported alert method: {self.method}", flush=True)
        except Exception as exc:
            print(f"[sniffer] alert send failed: {exc}", flush=True)
        return False

    def _send_udp(self, payload: dict) -> bool:
        if not self.host or not self.port:
            print("[sniffer] UDP alert host/port not configured", flush=True)
            return False
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.sock.sendto(data, (self.host, self.port))
        return True

    def _send_http(self, payload: dict) -> bool:
        if not self.url:
            print("[sniffer] HTTP alert URL not configured", flush=True)
            return False
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=2.0) as response:
                return 200 <= response.status < 300
        except urllib.error.URLError as exc:
            print(f"[sniffer] HTTP alert failed: {exc}", flush=True)
            return False

    def _send_file(self, payload: dict) -> bool:
        if self.file_path is None:
            print("[sniffer] file alert path not configured", flush=True)
            return False
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        with self.file_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
        return True


def build_alert_payload(row: dict, detection: dict) -> dict:
    return {
        "timestamp": row.get("timestamp"),
        "severity": "high",
        "type": "dns_cache_poisoning_suspected",
        "src_ip": row.get("src_ip"),
        "dst_ip": row.get("dst_ip"),
        "src_port": row.get("src_port"),
        "dst_port": row.get("dst_port"),
        "transport": row.get("transport"),
        "qname": row.get("qname"),
        "dns_id": row.get("dns_id"),
        "predicted_label": detection.get("predicted_label"),
        "predicted_probability": detection.get("predicted_probability"),
        "model_status": detection.get("model_status"),
        "rule_alert": detection.get("rule_alert"),
        "reason": detection.get("reason"),
        "recommended_action": "flush_cache_or_drop_source",
    }
