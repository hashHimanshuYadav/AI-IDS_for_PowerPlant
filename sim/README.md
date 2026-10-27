# Power Plant ICS Telemetry Simulator (`sim/`)

This directory contains the synthetic cyber-physical simulation engine designed to generate realistic, multi-node industrial SCADA telemetry for evaluating the AI-IDS without data leakage or artificial ground-truth shortcuts.

## Purpose & Design Justification
Academic cybersecurity benchmarks (e.g., KDD99) and raw, unconditioned Kaggle datasets often exhibit zero natural feature-to-label correlation ($\approx 0.50\text{ ROC-AUC}$), which previously led to flawed synthetic per-row label-conditioning loops. 

This simulator replaces artificial label-conditioning with **domain-grounded cyber-physical dynamics**:
1. **Per-Node Temporal Continuity:** Features evolve as an **Autoregressive AR(1) process** around node-specific baselines, capturing realistic device persistence and sensor drift.
2. **Daily Power Load Cycle:** Active power consumption ($\text{kW}$) follows a diurnal load curve ($24\text{-hour}$ sinusoidal phase), mirroring grid demand fluctuations.
3. **Realistic Benign Transients:** Normal operations include brief operational anomalies (capacitor bank switching, inductive motor startups, and network buffer flushes), creating natural operational variance and realistic false-positive opportunities.
4. **Episodic Multi-Stage Cyber Attacks:** Malicious events occur in contiguous episodes ($5$ to $60$ packets per node) with an onset ramp and a per-episode intensity drawn from a $\text{Beta}(2, 5)$ distribution.
5. **No Clean Single-Feature Separation:** Attack signatures shift feature subsets by modest amounts ($+0.8\sigma$ to $+1.8\sigma$), ensuring all distributions overlap with normal bounds and capping maximum single-feature ROC-AUC below $0.85$.

---

## Dataset Profiles & Seeds

| Profile | File | Seed | Nodes | Class Balance | Characteristics |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TRAIN** | `data/sim/train.csv` | 11 | `Node_01`–`Node_08` | ~70% Normal, ~30% Attack | Baseline training corpus for fitting encoders, scalers, and models. |
| **VAL** | `data/sim/val.csv` | 22 | `Node_01`–`Node_08` | ~70% Normal, ~30% Attack | Held-out validation corpus for threshold calibration and LSTM usefulness testing. |
| **TEST (In-Dist)** | `data/sim/test.csv` | 33 | `Node_09`–`Node_12` | ~70% Normal, ~30% Attack | In-distribution evaluation on unseen substation nodes. |
| **SHIFTED TEST** | `data/sim/test_shifted.csv` | 44 | `Node_13`–`Node_16` | ~70% Normal, ~30% Attack | Stress test: Noise $\times 1.5$, intensity $\times 0.75$, $2.4\times$ transient rate, phase-shifted load cycle. |
| **LIVE** | `data/sim/live.csv` | 55 | `Node_01`–`Node_04` | ~70% Normal, ~30% Attack | Dedicated streaming pool for `stream_generator.py`. |

---

## Simulated Feature Specification (37 Features)

The simulator outputs the exact 37 features defined in `feature_cols.json`:

### 1. Categorical Features (11 Stable Network & Device Attributes)
* `region`: Geographic grid zone (`North`, `South`, `East`, `West`, `Central`).
* `substation_type`: Functional classification (`Transmission`, `Distribution`, `Generation`, `Renewable`).
* `device_type`: Field asset category (`RTU`, `PLC`, `IED`, `SCADA_Server`).
* `communication_protocol`: Industrial bus protocol (`DNP3`, `Modbus_TCP`, `IEC61850`, `MQTT`).
* `user_role`: Operator credential level (`Operator`, `Supervisor`, `Admin`, `Engineer`).
* `device_trust_level`: Hardware security profile (`Trusted`, `Medium`, `Low`, `Guest`).
* `firmware_version`: Installed firmware revision (`v1.0`, `v1.2`, `v2.0`, `v2.3`, `v3.0`).
* `event_severity`: System log classification (`Low`, `Medium`, `High`, `Critical`).
* `alert_priority`: Relay triage priority (`P1`, `P2`, `P3`, `P4`).
* `encryption_algorithm`: Cipher suite (`AES256`, `RSA2048`, `DES`, `None`).
* `certificate_status`: X.509 status (`Valid`, `Expired`, `Revoked`, `SelfSigned`).

### 2. Physical & Thermodynamic Metrics (6 Features)
* `power_consumption_kw`: Mean $245.0\text{ kW}$, $\sigma=35.0$, diurnal cycle $\pm 22\%$.
* `voltage_deviation_percent`: Grid voltage stability around nominal $1.0\text{ p.u.}$, Mean $0.0\%$, $\sigma=0.45\%$.
* `frequency_deviation_hz`: Turbine governor frequency around $50.00\text{ Hz}$, Mean $0.0\text{ Hz}$, $\sigma=0.035\text{ Hz}$.
* `control_signal_frequency`: Control loop rate, Mean $60.0\text{ Hz}$, $\sigma=0.08\text{ Hz}$.
* `measurement_variance`: Analog transducer variance, Mean $0.045$, $\sigma=0.02$.
* `cpu_utilization_percent`: RTU CPU load, Mean $38.0\%$, $\sigma=12.0\%$.

### 3. Cyber & Network Metrics (20 Features)
* `packet_size_bytes`, `packet_rate_per_sec`, `network_latency_ms`, `bandwidth_usage_mbps`, `jitter_ms`, `packet_loss_percent`, `connection_duration_sec`, `active_connection_count`, `failed_connection_count`, `authentication_attempts`, `failed_login_count`, `memory_utilization_percent`, `sensor_update_interval_ms`, `telemetry_volume_mb`, `scada_command_count`, `intrusion_signature_score`, `behavior_anomaly_score`, `traffic_entropy`, `session_risk_score`, `federated_round`.

---

## Attack Signatures & Subsets

| Attack Class | Targeted Feature Subsets | Physical & Operational Manifestation |
| :--- | :--- | :--- |
| **DoS_Attack** | `packet_rate_per_sec` ($+1.5\sigma$), `network_latency_ms` ($+1.4\sigma$), `packet_loss_percent` ($+1.6\sigma$) | Telemetry packet flooding inducing buffer exhaustion and latency spikes. |
| **Replay_Attack** | `measurement_variance` ($-1.5\sigma$), `traffic_entropy` ($-1.2\sigma$), `jitter_ms` ($-1.0\sigma$) | Stale sensor replay resulting in unnaturally static variance and low entropy. |
| **False_Data_Injection** | `frequency_deviation_hz` ($+1.5\sigma$), `voltage_deviation_percent` ($+1.6\sigma$), `measurement_variance` ($+1.3\sigma$) | Sensor signal spoofing designed to trip protective generator breaker relays. |
| **Command_Injection** | `scada_command_count` ($+1.6\sigma$), `control_signal_frequency` ($+1.3\sigma$), `cpu_utilization_percent` ($+1.2\sigma$) | Unauthorized actuator overrides and unauthorized valve commands. |
| **Insider_Threat** | `failed_login_count` ($+1.6\sigma$), `authentication_attempts` ($+1.5\sigma$), `session_risk_score` ($+1.6\sigma$) | Brute-force privilege escalation from within substation subnets. |
| **Spoofing_Attack** | `packet_size_bytes` ($+1.2\sigma$), `jitter_ms` ($+1.4\sigma$), `session_risk_score` ($+1.3\sigma$) | Rogue RTU masquerade generating non-standard packet sizes. |
| **Malware** | `cpu_utilization_percent` ($+1.6\sigma$), `memory_utilization_percent` ($+1.5\sigma$), `traffic_entropy` ($+1.4\sigma$) | Malicious firmware payload consuming embedded RTU memory and CPU cycles. |
| **Reconnaissance** | `active_connection_count` ($+1.5\sigma$), `failed_connection_count` ($+1.6\sigma$), `connection_duration_sec` ($-1.2\sigma$) | Rapid port scans and Modbus register mapping across substation nodes. |

---

## Regenerating Data
```bash
python3 sim/generator.py
```
Outputs datasets to `data/sim/*.csv`.
