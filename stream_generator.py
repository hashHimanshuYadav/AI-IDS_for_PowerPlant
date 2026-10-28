import os
import sys
import time
import json
import math
import random

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from sim.profiles import (
    CATEGORICAL_DOMAINS,
    NUMERIC_SPEC,
    ATTACK_CLASSES,
    ATTACK_SIGNATURES
)
from sim.generator import NodeState, load_feature_cols

STREAM_BUFFER_FILE = os.path.join(BASE_DIR, 'live_stream.json')
CONFIG_FILE = os.path.join(BASE_DIR, 'stream_config.json')
FEATURE_COLS_FILE = os.path.join(BASE_DIR, 'feature_cols.json')
ENCODERS_FILE = os.path.join(BASE_DIR, 'label_encoders.pkl')
ENCODERS_MAP_FILE = os.path.join(BASE_DIR, 'encoders_map.json')

print("=" * 65)
print("  🏭 POWER PLANT ICS LIVE TELEMETRY SIMULATION STREAM (SEED 55)")
print("=" * 65)

# 1. Load Feature Order Specifications
feature_cols = load_feature_cols()
print(f"[+] Loaded feature specifications ({len(feature_cols)} features).")

# 2. Load Categorical Label Encoders (fitted strictly on TRAIN)
encoders_map = {}
if os.path.exists(ENCODERS_MAP_FILE):
    with open(ENCODERS_MAP_FILE, 'r') as f:
        encoders_map = json.load(f)
    print(f"[+] Loaded {len(encoders_map)} categorical encoders from {os.path.basename(ENCODERS_MAP_FILE)}.")
elif os.path.exists(ENCODERS_FILE):
    try:
        import joblib
        encoders = joblib.load(ENCODERS_FILE)
        for col, le in encoders.items():
            encoders_map[col] = {cls_name: idx for idx, cls_name in enumerate(le.classes_)}
        print(f"[+] Loaded {len(encoders_map)} categorical label encoders from {os.path.basename(ENCODERS_FILE)}.")
    except Exception as e:
        print(f"[!] Warning loading label_encoders.pkl: {e}")

# 3. Initialize Multi-Node Topology for LIVE stream (Seed 55)
LIVE_SEED = 55
rng = random.Random(LIVE_SEED)
live_nodes = ["Node_01", "Node_02", "Node_03", "Node_04"]
node_states = {}
for i, nid in enumerate(live_nodes):
    node_states[nid] = NodeState(
        node_id=nid,
        rng=rng,
        noise_scale=1.0,
        phase_shift=(i * math.pi / 4.0)
    )

print(f"[+] Initialized {len(node_states)} telemetry nodes: {', '.join(live_nodes)}")
print(f"[*] Stream Destination: {STREAM_BUFFER_FILE}")
print(f"[*] Stream Config Watcher: {CONFIG_FILE}\n")

def get_stream_config():
    interval = 3.0
    is_active = True
    selected_attack = 'Normal'
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
                interval = max(0.2, float(cfg.get('interval', 3.0)))
                is_active = bool(cfg.get('is_streaming', True))
                selected_attack = str(cfg.get('selected_attack', 'Normal'))
        except Exception:
            pass
    return interval, is_active, selected_attack

def run_stream():
    packet_id = 1
    t_sec = 0.0

    # Attack Episode Management
    current_episode_attack = 'Normal'
    episode_remaining_packets = 0
    episode_total_length = 0
    episode_intensity = 0.0
    episode_ramp_length = 0

    try:
        while True:
            interval, is_active, selected_attack = get_stream_config()
            if not is_active:
                time.sleep(0.2)
                continue

            # Handle Attack Selection Changes or Episode Continuation
            if selected_attack != current_episode_attack or episode_remaining_packets <= 0:
                is_operator_inject = (selected_attack != current_episode_attack and selected_attack != 'Normal')
                current_episode_attack = selected_attack
                if current_episode_attack == 'Normal':
                    episode_total_length = 50
                    episode_remaining_packets = 50
                    episode_intensity = 0.0
                    episode_ramp_length = 0
                else:
                    # Contiguous attack episode
                    episode_total_length = rng.randint(20, 50)
                    episode_remaining_packets = episode_total_length
                    # If manually selected by operator from Inject tab, immediately apply detectable intensity
                    if is_operator_inject:
                        episode_intensity = rng.uniform(0.75, 1.0)
                        episode_ramp_length = 1
                    else:
                        episode_intensity = rng.betavariate(2.0, 2.0)
                        episode_ramp_length = max(2, int(episode_total_length * 0.25))

            # Calculate onset ramp factor
            step_in_episode = episode_total_length - episode_remaining_packets
            if episode_ramp_length > 0 and step_in_episode < episode_ramp_length:
                ramp_factor = (step_in_episode + 1) / float(episode_ramp_length)
            else:
                ramp_factor = 1.0

            # Inject rare benign transient if nominal traffic (3% probability)
            benign_transient = None
            if current_episode_attack == 'Normal' and rng.random() < 0.03:
                benign_transient = rng.choice(['capacitor_switching', 'motor_startup', 'network_buffer_flush'])

            # Select a node round-robin
            active_node_id = live_nodes[packet_id % len(live_nodes)]
            node_state = node_states[active_node_id]

            # Generate realistic physics & cyber state
            raw_record = node_state.step(
                t_sec=t_sec,
                attack_type=current_episode_attack,
                attack_intensity=episode_intensity,
                ramp_factor=ramp_factor,
                benign_transient_type=benign_transient
            )

            episode_remaining_packets -= 1
            t_sec += interval

            # Encode categorical features for model consumption
            encoded_record = dict(raw_record)
            for cat_col, mapping in encoders_map.items():
                if cat_col in encoded_record:
                    val_str = str(encoded_record[cat_col])
                    encoded_record[cat_col] = mapping.get(val_str, 0)

            # Build feature vector in exact order of feature_cols.json
            features = [float(encoded_record[col]) for col in feature_cols]

            # Real physical and network telemetry metrics for dashboard
            freq_dev = float(raw_record.get('frequency_deviation_hz', 0.0))
            volt_dev = float(raw_record.get('voltage_deviation_percent', 0.0))
            power_kw = float(raw_record.get('power_consumption_kw', 0.0))
            latency = float(raw_record.get('network_latency_ms', 0.0))
            packet_rate = int(raw_record.get('packet_rate_per_sec', 0))
            scada_cmds = int(raw_record.get('scada_command_count', 0))
            entropy = float(raw_record.get('traffic_entropy', 0.0))

            payload = {
                "packet_id": packet_id,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "simulated_class": current_episode_attack,
                "node_id": active_node_id,
                "substation": str(raw_record.get('substation_type', 'Generation')),
                "protocol": str(raw_record.get('communication_protocol', 'DNP3')),
                "device_type": str(raw_record.get('device_type', 'RTU')),
                "source": "simulator",
                "features": features,
                "physical": {
                    "frequency_deviation_hz": freq_dev,
                    "voltage_deviation_percent": volt_dev,
                    "power_consumption_kw": power_kw,
                    "network_latency_ms": latency,
                    "packet_rate_per_sec": packet_rate,
                    "scada_command_count": scada_cmds,
                    "traffic_entropy": entropy
                },
                # Top-level mirrors for contract flexibility
                "frequency_deviation_hz": freq_dev,
                "voltage_deviation_percent": volt_dev,
                "power_consumption_kw": power_kw,
                "network_latency_ms": latency,
                "packet_rate_per_sec": packet_rate,
                "scada_command_count": scada_cmds,
                "traffic_entropy": entropy
            }

            # Atomic file write to avoid partial reads
            temp_file = STREAM_BUFFER_FILE + '.tmp'
            with open(temp_file, 'w') as f_out:
                json.dump(payload, f_out)
            os.replace(temp_file, STREAM_BUFFER_FILE)

            status_tag = f"[ATTACK: {current_episode_attack} (I={episode_intensity:.2f})]" if current_episode_attack != 'Normal' else "[NORMAL]"
            if benign_transient:
                status_tag += f" (Transient: {benign_transient})"
            print(f"[STREAM #{packet_id:04d}] {payload['timestamp']} | {active_node_id} | {status_tag:<38} | Intv: {interval:.1f}s")
            packet_id += 1

            # Responsive sleep honoring stream_config.json modifications
            start_time = time.time()
            while time.time() - start_time < interval:
                time.sleep(0.05)
                new_interval, is_active, new_selected_attack = get_stream_config()
                interval = new_interval
                if not is_active or new_selected_attack != selected_attack:
                    break

    except KeyboardInterrupt:
        print("\n[!] Stream generator terminated by user.")

if __name__ == '__main__':
    run_stream()
