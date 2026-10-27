import os
import time
import json
import joblib
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STREAM_BUFFER_FILE = os.path.join(BASE_DIR, 'live_stream.json')
CONFIG_FILE = os.path.join(BASE_DIR, 'stream_config.json')
TEST_CSV_FILE = os.path.join(BASE_DIR, 'test_stream.csv')
FEATURE_COLS_FILE = os.path.join(BASE_DIR, 'feature_cols.json')
ENCODERS_FILE = os.path.join(BASE_DIR, 'label_encoders.pkl')

if not os.path.exists(TEST_CSV_FILE):
    raise SystemExit(f"[!] Critical Error: Held-out test stream file not found at {TEST_CSV_FILE}")

# Load feature order
if os.path.exists(FEATURE_COLS_FILE):
    with open(FEATURE_COLS_FILE, 'r') as f:
        feature_cols = json.load(f)
else:
    feature_cols = [
        'region', 'substation_type', 'device_type', 'communication_protocol', 'packet_size_bytes',
        'packet_rate_per_sec', 'network_latency_ms', 'bandwidth_usage_mbps', 'jitter_ms', 'packet_loss_percent',
        'connection_duration_sec', 'active_connection_count', 'failed_connection_count', 'authentication_attempts',
        'failed_login_count', 'user_role', 'device_trust_level', 'firmware_version', 'cpu_utilization_percent',
        'memory_utilization_percent', 'power_consumption_kw', 'sensor_update_interval_ms', 'telemetry_volume_mb',
        'scada_command_count', 'control_signal_frequency', 'measurement_variance', 'voltage_deviation_percent',
        'frequency_deviation_hz', 'event_severity', 'alert_priority', 'encryption_algorithm', 'certificate_status',
        'intrusion_signature_score', 'behavior_anomaly_score', 'traffic_entropy', 'session_risk_score', 'federated_round'
    ]

# Load categorical encoders
encoders = {}
if os.path.exists(ENCODERS_FILE):
    encoders = joblib.load(ENCODERS_FILE)

# Load held-out test data
df_test = pd.read_csv(TEST_CSV_FILE)
target_col = 'attack_type'

# Encode categoricals matching training pipeline
df_proc = df_test.copy()
for col, le in encoders.items():
    if col in df_proc.columns:
        df_proc[col] = le.transform(df_proc[col].astype(str))

# Group records into contiguous sequential rows per attack type
grouped_data = {}
class_pointers = {}

for cls in df_proc[target_col].unique():
    sub_df = df_proc[df_proc[target_col] == cls]
    records = []
    for idx, row in sub_df.iterrows():
        feat_vals = row[feature_cols].values.astype(float).tolist()
        records.append({
            "attack_type": str(cls),
            "features": feat_vals,
            "node_id": str(row.get('energy_node_id', 'Node_01')),
            "record_id": int(row.get('record_id', idx))
        })
    grouped_data[cls] = records
    class_pointers[cls] = 0

all_test_classes = list(grouped_data.keys())

print("=" * 65)
print("  🏭 POWER PLANT ICS TEST TELEMETRY STREAM GENERATOR (37 FEATURES)")
print("=" * 65)
print(f"[*] Streaming strictly from held-out test dataset: {os.path.basename(TEST_CSV_FILE)}")
print(f"[*] Available classes: {len(all_test_classes)} ({', '.join(all_test_classes[:4])}...)")
print(f"[*] Feature Dimension: {len(feature_cols)} features matching scaler_powerplant_ids.pkl.")
print(f"[*] Total Held-Out Test Records: {len(df_proc)}")
print(f"[*] Destination buffer: {STREAM_BUFFER_FILE}\n")

def get_stream_config():
    interval = 5.0
    is_active = True
    selected_attack = 'Normal'
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
                interval = max(0.2, float(cfg.get('interval', 5.0)))
                is_active = bool(cfg.get('is_streaming', True))
                selected_attack = str(cfg.get('selected_attack', 'Normal'))
        except Exception:
            pass
    return interval, is_active, selected_attack

packet_id = 1
try:
    while True:
        interval, is_active, selected_attack = get_stream_config()
        if not is_active:
            time.sleep(0.2)
            continue

        # Select stream candidates matching active mode
        if selected_attack in grouped_data and len(grouped_data[selected_attack]) > 0:
            active_class = selected_attack
        elif 'Normal' in grouped_data:
            active_class = 'Normal'
        else:
            active_class = all_test_classes[0]

        candidates = grouped_data[active_class]
        ptr = class_pointers[active_class]
        sample = candidates[ptr % len(candidates)]
        class_pointers[active_class] = (ptr + 1) % len(candidates)

        actual_class = sample['attack_type']
        features = sample['features']

        payload = {
            "packet_id": packet_id,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "simulated_class": actual_class,
            "features": features
        }

        temp = STREAM_BUFFER_FILE + '.tmp'
        with open(temp, 'w') as f:
            json.dump(payload, f)
        os.replace(temp, STREAM_BUFFER_FILE)

        print(f"[PACKET #{packet_id:04d}] {payload['timestamp']} | Mode: {actual_class:<22} | Features: {len(features)} | Interval: {interval:.1f}s")
        packet_id += 1

        start_time = time.time()
        while time.time() - start_time < interval:
            time.sleep(0.05)
            new_interval, is_active, new_selected_attack = get_stream_config()
            interval = new_interval
            if not is_active or new_selected_attack != selected_attack:
                break

except KeyboardInterrupt:
    print("\n[!] Stream generator stopped by operator.")
