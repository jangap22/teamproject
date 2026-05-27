# Sniffer IDS Container

The sniffer is an IDS sidecar for the resolver. It watches DNS responses addressed to the resolver, extracts the same feature row used by offline training, runs a saved joblib model when available, applies defensive fallback rules, logs detections, and sends alerts to the resolver.

It does not train a random forest model. Training, validation, F1-score, FPR, and confusion matrix work belong in offline scripts such as `scripts/train_random_forest.py`, `scripts/evaluate_model.py`, or notebooks.

## IDS Runtime Flow

```text
DNS response addressed to the resolver
  -> packet capture
  -> cheap pre-filter and runtime sampling
  -> full inspection only for selected packets
  -> feature extraction
  -> model.predict() when inspected and model is available
  -> fallback IDS rules
  -> suspicious true/false
  -> terminal log and detection CSV
  -> resolver alert when suspicious
```

The Docker Compose setup currently uses `network_mode: host`. The sniffer watches resolver-bound traffic with the hardcoded resolver DNS port below.

## Hardcoded Lab Ports

The compose file intentionally hardcodes these lab ports instead of reading them from `.env`:

- Resolver DNS: `10053/tcp`, `10053/udp`
- Authoritative DNS: `20053/tcp`, `20053/udp`
- External authoritative DNS: `30053/tcp`, `30053/udp`
- Resolver IDS alert UDP socket: `9999/udp`
- Resolver attack UDP port: `1025/udp`
- Real web service env value: `80/tcp`
- Fake web service env value: `80/tcp`

Sniffer-specific hardcoded values:

- `DNS_PORT=10053`
- `SNIFFER_RESOLVER_PORT=10053`
- Sniffer code hardcoded BPF filter: empty string, so Scapy receives all packets from the interface and the code processes DNS responses addressed to `SNIFFER_RESOLVER_IP` only.
- `SNIFFER_ALERT_PORT=9999`

## Separate Resolver/Sniffer VMs

For a split setup where the resolver container runs in one VM and the sniffer container runs in another VM:

- Resolver VM: run the resolver container and listen on `10053`.
- Sniffer VM: run the sniffer container with `network_mode: host`, `NET_ADMIN`, and `NET_RAW`.
- Sniffer capture filter is hardcoded as empty in `sniffer/main.py`; the code receives all interface packets and processes DNS responses addressed to `SNIFFER_RESOLVER_IP` only.
- `SNIFFER_INTERFACE` must be the sniffer VM interface that can actually see resolver traffic.

This only works if the sniffer VM can observe the resolver VM's packets on its NIC. If the traffic is switched as normal unicast and not mirrored/promiscuous-visible, the sniffer container will run but will not see resolver packets.

## Same Ubuntu Server

For the recommended Ubuntu server setup, run both resolver and sniffer containers on the same Ubuntu VM with `network_mode: host`.

The compose file uses:

- `SNIFFER_INTERFACE=enp0s1`
- BPF filter is hardcoded as empty in `sniffer/main.py`.
- `SNIFFER_ALERT_HOST=127.0.0.1`
- `SNIFFER_ALERT_PORT=9999`

This lab currently uses `enp0s1` as the Ubuntu server NIC. If the VM interface changes, confirm the real NIC with:

```bash
ip route get 8.8.8.8
ip addr
```

Before debugging the sniffer, verify packet visibility on the Ubuntu VM:

```bash
sudo tcpdump -i any "host <resolver_ip> and (udp port 10053 or tcp port 10053 or udp port 20053 or tcp port 20053 or udp port 30053 or tcp port 30053)"
```

For the current `enp0s1` setting:

```bash
sudo tcpdump -i enp0s1 "host <resolver_ip> and (udp port 10053 or tcp port 10053 or udp port 20053 or tcp port 20053 or udp port 30053 or tcp port 30053)"
```

## Alert Delivery

The resolver already has a UDP alert listener on `9999/udp`. The sniffer sends JSON alerts to `${RESOLVER_IP}:9999`.

Resolver logs should show lines like:

```text
[IDS ALERT] dns_cache_poisoning_suspected qname=bank.test src_ip=... reason=...
```

The same alert payload is appended to:

```text
/data/alerts/ids_alerts.jsonl
```

## Model Artifact

Place the trained model at:

```text
/models/randomforest_model.joblib
```

Expected joblib structure:

```python
{
    "model": trained_sklearn_pipeline,
    "feature_columns": list_of_columns_used_for_training,
    "best_params": optional_best_params,
}
```

`model` may be a full scikit-learn `Pipeline`, so the sniffer does not recreate preprocessing such as `OneHotEncoder`. It creates a one-row pandas `DataFrame`, orders columns by `feature_columns`, and calls `predict()` and, when available, `predict_proba()`.

If the model path is unset, missing, or invalid, the sniffer keeps running. It records `model_status` and still applies rule-based fallback detection.

## Fallback Rules

The IDS includes defensive rules for:

- duplicate DNS responses for the same `qname + dns_id`
- conflicting answers for the same `qname + dns_id`
- resolver-bound DNS responses from sources outside configured authoritative IPs
- short-window DNS response bursts
- abnormal total RR counts
- extreme TTL values

Rules and the model are combined. Any model attack prediction, probability over threshold, or rule alert marks the event as suspicious.

## Runtime Sampling

Runtime sampling is for IDS load reduction, not offline training. It decides which live packets receive full feature extraction and model/rule detection. Dropping a packet here means the IDS skips expensive analysis for that packet; it does not block or alter the network packet.

The default policy is conservative:

- suspicious packets are always inspected
- DNS responses are inspected at 100% by default
- DNS queries are sampled at 10% by default
- qname/signature rate limits reduce repeated benign-looking traffic

Sampling too aggressively can increase missed-detection risk. Keep `SNIFFER_INSPECT_ALL_RESPONSES=true` and `SNIFFER_ALWAYS_INSPECT_SUSPICIOUS=true` unless you are deliberately stress-testing throughput.

Relevant variables:

- `SNIFFER_SAMPLING_ENABLED=true|false`
- `SNIFFER_BASE_SAMPLE_RATE`: global multiplier
- `SNIFFER_INSPECT_ALL_RESPONSES=true|false`
- `SNIFFER_RESPONSE_SAMPLE_RATE`: response sample rate when responses are not forced
- `SNIFFER_QUERY_SAMPLE_RATE`: query sample rate, default `0.1`
- `SNIFFER_ALWAYS_INSPECT_SUSPICIOUS=true|false`
- `SNIFFER_RATE_LIMIT_WINDOW_SECONDS`
- `SNIFFER_MAX_PER_QNAME_PER_WINDOW`
- `SNIFFER_MAX_PER_SIGNATURE_PER_WINDOW`
- `SNIFFER_STATS_INTERVAL_SECONDS`
- `SNIFFER_LOG_SAMPLING_DROPS`
- `SNIFFER_SAMPLING_DROP_LOG`

Cheap pre-filter checks include duplicate `qname + dns_id` responses, response bursts, large DNS sections, abnormal opcode/rcode values, and extreme TTL values. These checks use Scapy DNS header and minimal DNS section reads only; they do not build pandas DataFrames or call the random forest.

Stats are printed periodically:

```text
[sniffer] sampling_stats={'seen': 100000, 'inspected': 12000, 'dropped': 88000, ...}
```

## Environment Variables

- `SNIFFER_INTERFACE`: capture interface. Defaults to `SNIFF_INTERFACE`, then `eth0`.
- `SNIFFER_BPF_FILTER`: ignored. The packet filter is hardcoded as empty in `sniffer/main.py` for this lab.
- `SNIFFER_RESOLVER_IP`: resolver IP used by capture and rules.
- `SNIFFER_RESOLVER_PORT`: resolver DNS port. Defaults to `DNS_PORT`, then `53`.
- `SNIFFER_AUTH_IPS`: comma-separated trusted authoritative server IPs.
- `SNIFFER_SAMPLING_ENABLED`: runtime sampling toggle.
- `SNIFFER_INSPECT_ALL_RESPONSES`: inspect every DNS response.
- `SNIFFER_QUERY_SAMPLE_RATE`: query sampling rate.
- `SNIFFER_RESPONSE_SAMPLE_RATE`: response sampling rate when not forcing all responses.
- `SNIFFER_ALWAYS_INSPECT_SUSPICIOUS`: never drop cheap-rule suspicious packets.
- `SNIFFER_MODEL_PATH`: joblib model path. Defaults to `/models/randomforest_model.joblib`.
- `SNIFFER_RF_PROBA_THRESHOLD`: probability threshold for model alerts.
- `SNIFFER_WINDOW_SECONDS`: rule sliding window.
- `SNIFFER_DUPLICATE_TXID_THRESHOLD`: duplicate response threshold.
- `SNIFFER_RESPONSE_BURST_THRESHOLD`: response burst threshold.
- `SNIFFER_ALERT_ENABLED`: enable resolver alerts.
- `SNIFFER_ALERT_METHOD`: `udp`, `http`, or `file`. Compose defaults to `udp`.
- `SNIFFER_ALERT_HOST`: UDP alert host. Compose defaults to `127.0.0.1`.
- `SNIFFER_ALERT_PORT`: UDP alert port.
- `SNIFFER_ALERT_FILE`: JSONL alert log path.
- `SNIFFER_ALERT_COOLDOWN_SECONDS`: suppress repeated identical alerts.
- `SNIFFER_SAVE_FEATURE_CSV`: optional feature row CSV.
- `SNIFFER_FEATURE_CSV`: feature CSV path.
- `SNIFFER_SAVE_DETECTION_CSV`: detection CSV toggle.
- `SNIFFER_DETECTION_CSV`: detection CSV path.

## Docker Usage

From the `scenario` directory:

```bash
docker compose up --build resolver sniffer
docker compose logs -f sniffer
docker compose logs -f resolver
```

Detection results are appended to:

```text
../data/detections/detection_results.csv
```

Optional feature rows are appended to:

```text
../data/captures/features.csv
```
