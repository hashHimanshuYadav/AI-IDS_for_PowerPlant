import os
import sys
import json
import csv
import math
import random
import time
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from sim.profiles import (
    CATEGORICAL_DOMAINS,
    NUMERIC_SPEC,
    ATTACK_CLASSES,
    ATTACK_SIGNATURES
)
FEATURE_COLS_FILE = os.path.join(BASE_DIR, 'feature_cols.json')

def load_feature_cols():
    if os.path.exists(FEATURE_COLS_FILE):
        with open(FEATURE_COLS_FILE, 'r') as f:
            return json.load(f)
    raise FileNotFoundError(f"Missing {FEATURE_COLS_FILE}")

class NodeState:
    """Maintains consistent topology and temporal state per energy node."""
    def __init__(self, node_id, rng, noise_scale=1.0, phase_shift=0.0):
        self.node_id = node_id
        self.rng = rng
        self.noise_scale = noise_scale
        self.phase_shift = phase_shift
        
        # Stable categorical identities per node
        self.categoricals = {}
        for cat, values in CATEGORICAL_DOMAINS.items():
            self.categoricals[cat] = rng.choice(values)

        # Node-specific baseline mean offsets (+/- 5% to 10%)
        self.node_offsets = {}
        self.current_values = {}
        for feat, spec in NUMERIC_SPEC.items():
            offset = rng.gauss(0, 0.08 * spec['std'])
            self.node_offsets[feat] = offset
            self.current_values[feat] = spec['mean'] + offset

    def step(self, t_sec, attack_type, attack_intensity, ramp_factor, benign_transient_type=None):
        out = {}
        
        # Copy stable categoricals
        for cat, val in self.categoricals.items():
            out[cat] = val

        # Handle specific categorical attack tweaks if applicable
        if attack_type == 'Insider_Threat' and attack_intensity > 0.8:
            out['user_role'] = 'Operator' # Stolen operator credentials
        elif attack_type == 'Spoofing_Attack' and attack_intensity > 0.7:
            out['certificate_status'] = 'Revoked'

        # Daily cycle for power consumption
        seconds_in_day = 86400.0
        daily_phase = (2.0 * math.pi * (t_sec % seconds_in_day) / seconds_in_day) - (math.pi / 2.0) + self.phase_shift
        daily_power_multiplier = 1.0 + 0.22 * math.sin(daily_phase)

        for feat, spec in NUMERIC_SPEC.items():
            target_mean = spec['mean'] + self.node_offsets[feat]
            if feat == 'power_consumption_kw':
                target_mean *= daily_power_multiplier

            # AR(1) state evolution: x_t = mu + phi*(x_{t-1} - mu) + sigma*sqrt(1-phi^2)*eps
            phi = spec['ar1']
            innov_std = spec['std'] * math.sqrt(max(0.01, 1.0 - phi * phi)) * self.noise_scale
            noise = self.rng.gauss(0, innov_std)
            new_val = target_mean + phi * (self.current_values[feat] - target_mean) + noise

            # Apply Benign Transient spikes (labelled Normal)
            if benign_transient_type == 'capacitor_switching':
                if feat in ['voltage_deviation_percent', 'frequency_deviation_hz']:
                    new_val += 1.25 * spec['std'] * self.rng.choice([-1.0, 1.0])
            elif benign_transient_type == 'motor_startup':
                if feat == 'power_consumption_kw':
                    new_val += 1.6 * spec['std']
                elif feat == 'voltage_deviation_percent':
                    new_val -= 1.1 * spec['std']
            elif benign_transient_type == 'network_buffer_flush':
                if feat in ['network_latency_ms', 'jitter_ms']:
                    new_val += 1.8 * spec['std']

            # Apply Attack Shift if attack is active
            if attack_type != 'Normal' and attack_type in ATTACK_SIGNATURES:
                shifts = ATTACK_SIGNATURES[attack_type]
                if feat in shifts:
                    shift_sigma = shifts[feat]
                    # Shift scaled by intensity, ramp, and feature standard deviation
                    delta = shift_sigma * spec['std'] * attack_intensity * ramp_factor
                    new_val += delta

            # Clamp to physical range
            new_val = max(spec['min'], min(spec['max'], new_val))
            self.current_values[feat] = new_val
            out[feat] = round(new_val, 4)

        return out

def generate_profile(
    seed,
    node_ids,
    total_packets,
    attack_fraction=0.30,
    noise_scale=1.0,
    intensity_scale=1.0,
    transient_rate=0.03,
    phase_shift=0.0,
    start_time=None
):
    rng = random.Random(seed)
    feature_cols = load_feature_cols()

    if start_time is None:
        start_time = datetime(2026, 10, 1, 8, 0, 0)

    nodes = {nid: NodeState(nid, rng, noise_scale, phase_shift) for nid in node_ids}
    node_list = list(node_ids)

    rows = []
    current_time = start_time
    packet_id = 1

    # Plan attack episodes per node
    # Episode: (start_idx, length, attack_type, intensity)
    node_episodes = {nid: [] for nid in node_ids}
    packets_per_node = total_packets // len(node_ids)

    for nid in node_ids:
        target_attack_packets = int(packets_per_node * attack_fraction)
        acc_attack_packets = 0
        curr_idx = 10 # start after brief warm-up

        while curr_idx < packets_per_node - 30 and acc_attack_packets < target_attack_packets:
            # Episode length: 5 to 60 packets
            ep_len = rng.randint(8, min(45, packets_per_node - curr_idx))
            attack_type = rng.choice(ATTACK_CLASSES)
            # Intensity drawn from Beta(2, 5) scaled to [0.4, 1.4] * intensity_scale
            raw_beta = rng.betavariate(2.0, 5.0)
            intensity = (0.40 + 1.8 * raw_beta) * intensity_scale
            node_episodes[nid].append({
                'start': curr_idx,
                'end': curr_idx + ep_len,
                'type': attack_type,
                'intensity': intensity,
                'len': ep_len
            })
            acc_attack_packets += ep_len
            # Normal quiet inter-arrival gap: 20 to 80 packets
            curr_idx += ep_len + rng.randint(20, 80)

    # Generate telemetry sequentially across nodes
    for step_i in range(packets_per_node):
        for nid in node_list:
            node = nodes[nid]
            t_sec = (current_time - start_time).total_seconds()

            # Determine active attack state for this node at step_i
            active_attack = 'Normal'
            intensity = 0.0
            ramp_factor = 0.0

            for ep in node_episodes[nid]:
                if ep['start'] <= step_i < ep['end']:
                    active_attack = ep['type']
                    intensity = ep['intensity']
                    offset_in_ep = step_i - ep['start']
                    # 4-packet onset ramp
                    ramp_factor = min(1.0, (offset_in_ep + 1) / 4.0)
                    break

            # Check for rare benign transient if Normal
            transient_type = None
            if active_attack == 'Normal' and rng.random() < transient_rate:
                transient_type = rng.choice(['capacitor_switching', 'motor_startup', 'network_buffer_flush'])

            feat_dict = node.step(t_sec, active_attack, intensity, ramp_factor, transient_type)

            # Construct row
            row = {
                'record_id': packet_id,
                'energy_node_id': nid,
                'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                'attack_type': active_attack
            }
            # Assign features in exact order of feature_cols
            for c in feature_cols:
                row[c] = feat_dict[c]

            rows.append(row)
            packet_id += 1
            current_time += timedelta(seconds=0.5)

    return rows

def compute_single_feature_auc(rows, feature_cols):
    """Computes non-parametric single-feature ROC AUC using Mann-Whitney U for every feature."""
    y = [1 if r['attack_type'] != 'Normal' else 0 for r in rows]
    n_pos = sum(y)
    n_neg = len(y) - n_pos

    if n_pos == 0 or n_neg == 0:
        return {}

    auc_scores = {}
    for col in feature_cols:
        vals = [r[col] for r in rows]
        # Skip categorical string features for raw numeric AUC ranking
        if isinstance(vals[0], str):
            continue

        # Rank values
        indexed = sorted(range(len(vals)), key=lambda k: vals[k])
        ranks = [0] * len(vals)
        i = 0
        while i < len(vals):
            j = i
            while j + 1 < len(vals) and vals[indexed[j + 1]] == vals[indexed[i]]:
                j += 1
            avg_rank = (i + 1 + j + 1) / 2.0
            for k in range(i, j + 1):
                ranks[indexed[k]] = avg_rank
            i = j + 1

        sum_rank_pos = sum(ranks[idx] for idx in range(len(y)) if y[idx] == 1)
        u = sum_rank_pos - (n_pos * (n_pos + 1)) / 2.0
        auc = u / (n_pos * n_neg)
        auc = max(auc, 1.0 - auc) # Direction-invariant discriminative power
        auc_scores[col] = round(auc, 4)

    return auc_scores

def save_csv(rows, filepath):
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] Saved {len(rows)} records to {filepath}")

def generate_all_datasets():
    print("=" * 65)
    print("  🏭 POWER PLANT ICS TELEMETRY SIMULATION GENERATOR")
    print("=" * 65)
    feature_cols = load_feature_cols()

    # 1. TRAIN Profile (Seed 11, Node_01 to Node_08, 10,000 packets)
    train_nodes = [f"Node_{i:02d}" for i in range(1, 9)]
    train_rows = generate_profile(
        seed=11,
        node_ids=train_nodes,
        total_packets=10000,
        attack_fraction=0.30,
        noise_scale=1.0,
        intensity_scale=1.0,
        transient_rate=0.025
    )
    save_csv(train_rows, os.path.join(BASE_DIR, 'data', 'sim', 'train.csv'))

    # Single-feature AUC assertion on TRAIN
    auc_scores = compute_single_feature_auc(train_rows, feature_cols)
    max_feat = max(auc_scores.items(), key=lambda x: x[1])
    print(f"[+] Single-Feature ROC AUC Check (TRAIN): Max = {max_feat[1]} on '{max_feat[0]}'")
    assert max_feat[1] < 0.85, f"Single-feature AUC too high: {max_feat}"

    # 2. VAL Profile (Seed 22, Node_01 to Node_08, 2,500 packets)
    val_rows = generate_profile(
        seed=22,
        node_ids=train_nodes,
        total_packets=2500,
        attack_fraction=0.30,
        noise_scale=1.0,
        intensity_scale=1.0,
        transient_rate=0.025
    )
    save_csv(val_rows, os.path.join(BASE_DIR, 'data', 'sim', 'val.csv'))

    # 3. TEST In-Distribution Profile (Seed 33, unseen Node_09 to Node_12, 2,500 packets)
    test_nodes = [f"Node_{i:02d}" for i in range(9, 13)]
    test_rows = generate_profile(
        seed=33,
        node_ids=test_nodes,
        total_packets=2500,
        attack_fraction=0.30,
        noise_scale=1.0,
        intensity_scale=1.0,
        transient_rate=0.025
    )
    save_csv(test_rows, os.path.join(BASE_DIR, 'data', 'sim', 'test.csv'))

    # 4. SHIFTED TEST Profile (Seed 44, unseen Node_13 to Node_16, noise x1.5, intensity x0.75, transient rate 0.06, phase shift)
    shifted_nodes = [f"Node_{i:02d}" for i in range(13, 17)]
    shifted_rows = generate_profile(
        seed=44,
        node_ids=shifted_nodes,
        total_packets=2500,
        attack_fraction=0.30,
        noise_scale=1.5,
        intensity_scale=0.75,
        transient_rate=0.06,
        phase_shift=math.pi / 3.0
    )
    save_csv(shifted_rows, os.path.join(BASE_DIR, 'data', 'sim', 'test_shifted.csv'))

    # 5. LIVE Streaming Pool (Seed 55, Node_01 to Node_04, 3,000 packets)
    live_nodes = [f"Node_{i:02d}" for i in range(1, 5)]
    live_rows = generate_profile(
        seed=55,
        node_ids=live_nodes,
        total_packets=3000,
        attack_fraction=0.30,
        noise_scale=1.0,
        intensity_scale=1.0,
        transient_rate=0.03
    )
    save_csv(live_rows, os.path.join(BASE_DIR, 'data', 'sim', 'live.csv'))

    # Print summary class counts
    for name, r_list in [('TRAIN', train_rows), ('VAL', val_rows), ('TEST', test_rows), ('SHIFTED', shifted_rows), ('LIVE', live_rows)]:
        counts = {}
        for r in r_list:
            at = r['attack_type']
            counts[at] = counts.get(at, 0) + 1
        n_norm = counts.get('Normal', 0)
        n_att = len(r_list) - n_norm
        print(f"[*] {name:<10}: Total={len(r_list)} | Normal={n_norm} ({n_norm/len(r_list)*100:.1f}%) | Attack={n_att} ({n_att/len(r_list)*100:.1f}%)")

if __name__ == '__main__':
    generate_all_datasets()
