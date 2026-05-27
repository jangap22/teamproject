from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from pathlib import Path

import joblib
import pandas as pd

from schema import DROP_COLUMNS, FEATURE_COLUMNS


VERSIONED_MODEL_PATTERN = re.compile(r"^randomforest_v(\d+)\.joblib$")


class ModelDetector:
    def __init__(
        self,
        model_path: str | None,
        *,
        resolver_ip: str | None = None,
        authoritative_ips: set[str] | None = None,
        window_seconds: float = 2.0,
        duplicate_txid_threshold: int = 3,
        response_burst_threshold: int = 50,
        rf_proba_threshold: float = 0.7,
        rr_count_threshold: int = 25,
        ttl_low_threshold: int = 0,
        ttl_high_threshold: int = 86400,
    ):
        self.model_path = model_path
        self.loaded_model_path = None
        self.model = None
        self.feature_columns = None
        self.best_params = None
        self.model_status = "model_path_not_set" if not model_path else "not_loaded"
        self.warned_missing_sets = set()
        self.resolver_ip = resolver_ip
        self.authoritative_ips = authoritative_ips or set()
        self.window_seconds = window_seconds
        self.duplicate_txid_threshold = duplicate_txid_threshold
        self.response_burst_threshold = response_burst_threshold
        self.rf_proba_threshold = rf_proba_threshold
        self.rr_count_threshold = rr_count_threshold
        self.ttl_low_threshold = ttl_low_threshold
        self.ttl_high_threshold = ttl_high_threshold
        self.recent_responses = deque()
        self.response_keys = defaultdict(deque)
        self.response_answers = defaultdict(set)
        self.load_model()

    def load_model(self) -> None:
        if not self.model_path:
            self.model_status = "model_path_not_set"
            return

        path = self._resolve_model_path(Path(self.model_path))
        if not path.exists() and path.name == "random_forest_model.joblib":
            fallback_path = path.with_name("randomforest_model.joblib")
            if fallback_path.exists():
                path = fallback_path
        if not path.exists():
            self.model_status = "model_file_not_found"
            print(f"[sniffer] model file not found: {path}", flush=True)
            return

        try:
            artifact = joblib.load(path)
            if isinstance(artifact, dict):
                self.model = artifact.get("model")
                self.feature_columns = artifact.get("feature_columns")
                self.best_params = artifact.get("best_params")
                if self.model is None:
                    self.model_status = "model_missing_in_artifact"
                    return
                if not self.feature_columns:
                    self.feature_columns = self._infer_feature_columns(self.model)
                if not self.feature_columns:
                    self.model_status = "feature_columns_missing"
                    print("[sniffer] artifact has no feature_columns or feature_names_in_; prediction disabled", flush=True)
                    return
            else:
                self.model = artifact
                self.feature_columns = self._infer_feature_columns(self.model)
                if not self.feature_columns:
                    self.model_status = "feature_columns_missing"
                    print("[sniffer] raw model artifact has no feature_names_in_; prediction disabled", flush=True)
                    return

            self.feature_columns = list(self.feature_columns)
            self.loaded_model_path = str(path)
            self.model_status = "model_loaded"
            print(f"[sniffer] model loaded: {path}", flush=True)
        except Exception as exc:
            self.model = None
            self.feature_columns = None
            self.model_status = "model_load_failed"
            print(f"[sniffer] model load failed: {exc}", flush=True)

    def _resolve_model_path(self, configured_path: Path) -> Path:
        versioned_models = []
        for candidate in configured_path.parent.glob("randomforest_v*.joblib"):
            match = VERSIONED_MODEL_PATTERN.match(candidate.name)
            if match:
                versioned_models.append((int(match.group(1)), candidate))
        if versioned_models:
            version, path = max(versioned_models, key=lambda item: item[0])
            print(f"[sniffer] selected latest versioned model: v{version:06d} ({path})", flush=True)
            return path
        return configured_path

    def _infer_feature_columns(self, model) -> list[str] | None:
        columns = getattr(model, "feature_names_in_", None)
        if columns is not None:
            return list(columns)
        named_steps = getattr(model, "named_steps", None)
        if named_steps:
            for step in reversed(list(named_steps.values())):
                columns = getattr(step, "feature_names_in_", None)
                if columns is not None:
                    return list(columns)
        return None

    def is_available(self) -> bool:
        return self.model is not None and bool(self.feature_columns) and self.model_status == "model_loaded"

    def _empty_result(self) -> dict:
        return {
            "model_status": self.model_status,
            "predicted_label": None,
            "predicted_probability": None,
            "rule_alert": False,
            "suspicious": False,
            "reason": "model_not_available",
        }

    def _build_frame(self, row: dict) -> pd.DataFrame:
        source = {key: value for key, value in row.items() if key not in DROP_COLUMNS}
        for column in FEATURE_COLUMNS:
            source.setdefault(column, 0)
        missing = [column for column in self.feature_columns if column not in source]
        if missing:
            key = tuple(missing)
            if key not in self.warned_missing_sets:
                print(f"[sniffer] filling missing model columns with -1: {missing}", flush=True)
                self.warned_missing_sets.add(key)
            for column in missing:
                source[column] = -1
        return pd.DataFrame([{column: source.get(column) for column in self.feature_columns}])

    def predict(self, row: dict) -> dict:
        if not self.is_available():
            return self._empty_result()

        try:
            frame = self._build_frame(row)
            prediction = self.model.predict(frame)
            probability = None
            if hasattr(self.model, "predict_proba"):
                proba = self.model.predict_proba(frame)
                if len(proba) and len(proba[0]):
                    classes = getattr(self.model, "classes_", None)
                    if classes is not None and 1 in list(classes):
                        probability = float(proba[0][list(classes).index(1)])
                    else:
                        probability = float(max(proba[0]))
            predicted_label = prediction[0].item() if hasattr(prediction[0], "item") else prediction[0]
            return {
                "model_status": self.model_status,
                "predicted_label": predicted_label,
                "predicted_probability": probability,
                "rule_alert": False,
                "suspicious": False,
                "reason": "model_predicted_normal",
            }
        except Exception as exc:
            print(f"[sniffer] prediction failed: {exc}", flush=True)
            return {
                "model_status": "prediction_failed",
                "predicted_label": None,
                "predicted_probability": None,
                "rule_alert": False,
                "suspicious": False,
                "reason": "prediction_failed",
            }

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self.recent_responses and self.recent_responses[0] < cutoff:
            self.recent_responses.popleft()
        for key in list(self.response_keys.keys()):
            queue = self.response_keys[key]
            while queue and queue[0] < cutoff:
                queue.popleft()
            if not queue:
                del self.response_keys[key]
                self.response_answers.pop(key, None)

    def evaluate_rules(self, row: dict) -> tuple[bool, str]:
        if int(row.get("is_response") or 0) != 1:
            return False, "rule_no_alert"

        now = float(row.get("timestamp") or time.time())
        self._prune(now)
        self.recent_responses.append(now)

        qname = row.get("qname") or ""
        dns_id = row.get("dns_id")
        answer_ips = row.get("answer_ips") or ""
        key = (qname, dns_id)
        self.response_keys[key].append(now)
        if answer_ips:
            self.response_answers[key].add(answer_ips)

        if self.resolver_ip and row.get("dst_ip") == self.resolver_ip:
            src_ip = row.get("src_ip")
            if self.authoritative_ips and src_ip not in self.authoritative_ips:
                return True, "rule_untrusted_dns_response_source"

        if len(self.response_answers[key]) > 1:
            return True, "rule_conflicting_answers_same_qname_txid"

        if len(self.response_keys[key]) >= self.duplicate_txid_threshold:
            return True, "rule_duplicate_dns_response"

        if len(self.recent_responses) >= self.response_burst_threshold:
            return True, "rule_dns_response_burst"

        rr_count = int(row.get("structural_rr_count") or 0)
        if rr_count >= self.rr_count_threshold:
            return True, "rule_abnormal_rr_count"

        ttl_min = int(row.get("min_ttl") or 0)
        ttl_max = int(row.get("max_ttl") or 0)
        if ttl_min and ttl_min <= self.ttl_low_threshold:
            return True, "rule_extreme_low_ttl"
        if ttl_max and ttl_max >= self.ttl_high_threshold:
            return True, "rule_extreme_high_ttl"

        return False, "rule_no_alert"

    def detect(self, row: dict, sampled: bool = True) -> dict:
        rule_alert, rule_reason = self.evaluate_rules(row)
        result = self.predict(row) if sampled else self._empty_result()
        if not sampled and self.is_available():
            result["model_status"] = "model_loaded_skipped_by_sampling"
            result["reason"] = "sampled_out"

        suspicious = bool(rule_alert)
        reason = rule_reason if rule_alert else result.get("reason", "model_not_available")

        predicted_label = result.get("predicted_label")
        predicted_probability = result.get("predicted_probability")
        if predicted_label == 1 or predicted_label == "1":
            suspicious = True
            reason = "rf_model_predicted_attack"
        elif predicted_probability is not None and predicted_probability >= self.rf_proba_threshold:
            suspicious = True
            reason = "rf_model_probability_threshold"

        result.update(
            {
                "rule_alert": rule_alert,
                "suspicious": suspicious,
                "sampled": sampled,
                "reason": reason,
            }
        )
        return result
