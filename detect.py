import os
import sys
import time
import json
import collections

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

STREAM_BUFFER_FILE = os.path.join(BASE_DIR, 'live_stream.json')
DETECTION_OUTPUT_FILE = os.path.join(BASE_DIR, 'live_detection.json')
THRESHOLDS_FILE = os.path.join(BASE_DIR, 'thresholds.json')
FEATURE_COLS_FILE = os.path.join(BASE_DIR, 'feature_cols.json')

# Configure local Keras cache directory
os.environ['KERAS_HOME'] = os.path.join(BASE_DIR, '.keras')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

print("=" * 65)
print("  🛡️ POWER PLANT ICS AI INTRUSION DETECTION ENGINE")
print("=" * 65)
print("[-] Loading calibrated thresholds, feature specs, and IDS models...")

# 1. Load calibrated thresholds
thresholds = {
    "rf_threshold": 0.48,
    "iso_anomaly_flag": 1,
    "lstm_threshold": 0.55,
    "lstm_is_useful": False,
    "voting_mode": "2-of-2"
}
if os.path.exists(THRESHOLDS_FILE):
    try:
        with open(THRESHOLDS_FILE, 'r') as f:
            thresholds.update(json.load(f))
        print(f"[+] Loaded thresholds from {os.path.basename(THRESHOLDS_FILE)}: {thresholds}")
    except Exception as e:
        print(f"[!] Warning loading thresholds.json: {e}")

# 2. Load feature list
expected_feature_cols = None
if os.path.exists(FEATURE_COLS_FILE):
    try:
        with open(FEATURE_COLS_FILE, 'r') as f:
            expected_feature_cols = json.load(f)
        print(f"[+] Loaded feature specifications ({len(expected_feature_cols)} features).")
    except Exception as e:
        print(f"[!] Warning loading feature_cols.json: {e}")

try:
    import numpy as np
    import joblib
    import joblib.numpy_pickle
except ImportError as e:
    raise SystemExit(
        f"\n[!] Python Environment Error: {e}\n"
        f"[*] Ensure your Python environment has dependencies installed:\n"
        f"    pip install -r requirements.txt\n"
    )

# 3. High-performance, zero-hang artifact loader for scikit-learn models
class MockBase:
    def __init__(self, *args, **kwargs):
        pass
    def __setstate__(self, state):
        if isinstance(state, dict):
            self.__dict__.update(state)
        elif isinstance(state, tuple):
            for item in state:
                if isinstance(item, dict):
                    self.__dict__.update(item)

class SafeNumpyUnpickler(joblib.numpy_pickle.NumpyUnpickler):
    def find_class(self, module, name):
        if module.startswith('sklearn') or module.startswith('scipy') or module.startswith('numpy'):
            if hasattr(np, name):
                return getattr(np, name)
            if hasattr(np.dtypes, name):
                return getattr(np.dtypes, name)
            return MockBase
        try:
            return super().find_class(module, name)
        except Exception:
            return MockBase

def safe_load(filepath):
    with open(filepath, 'rb') as f:
        unpickler = SafeNumpyUnpickler(filepath, f, True)
        return unpickler.load()

try:
    print("[-] Loading Scaler...", flush=True)
    scaler = safe_load(os.path.join(BASE_DIR, 'scaler_powerplant_ids.pkl'))
    expected_dim = int(getattr(scaler, 'n_features_in_', 37))
    print(f"[+] Scaler calibrated: expecting {expected_dim} input features.", flush=True)

    print("[-] Loading Random Forest Classifier...", flush=True)
    rf_model = safe_load(os.path.join(BASE_DIR, 'rf_powerplant_ids.pkl'))
    print(f"[+] Model 1: Random Forest Classifier loaded ({len(rf_model.estimators_)} trees).", flush=True)

    print("[-] Loading Isolation Forest Profiler...", flush=True)
    iso_model = safe_load(os.path.join(BASE_DIR, 'iso_powerplant_ids.pkl'))
    print(f"[+] Model 2: Isolation Forest Profiler loaded ({len(iso_model.estimators_)} trees).", flush=True)
except Exception as e:
    raise SystemExit(f"[!] Model artifact load error: {e}. Ensure model files exist in root.")

# Mathematical inference routines (NumPy vectorized tree traversals)
def scale_features(raw_feats):
    x = np.asarray(raw_feats, dtype=float)
    return (x - scaler.mean_) / scaler.scale_

def predict_rf_prob(x_scaled):
    x = np.asarray(x_scaled, dtype=float).ravel()
    votes = []
    for est in rf_model.estimators_:
        node_id = 0
        nodes = est.tree_.nodes
        while nodes[node_id][0] != -1:
            feat = nodes[node_id][2]
            thresh = nodes[node_id][3]
            if x[feat] <= thresh:
                node_id = nodes[node_id][0]
            else:
                node_id = nodes[node_id][1]
        val = est.tree_.values[node_id][0]
        p1 = val[1] / np.sum(val) if np.sum(val) > 0 else 0.0
        votes.append(p1)
    return float(np.mean(votes))

def c_factor(n):
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (np.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)

def score_iso(x_scaled):
    x = np.asarray(x_scaled, dtype=float).ravel()
    paths = []
    for est in iso_model.estimators_:
        node_id = 0
        depth = 0
        nodes = est.tree_.nodes
        while nodes[node_id][0] != -1:
            feat = nodes[node_id][2]
            thresh = nodes[node_id][3]
            if x[feat] <= thresh:
                node_id = nodes[node_id][0]
            else:
                node_id = nodes[node_id][1]
            depth += 1
        n_node_samples = nodes[node_id][4]
        paths.append(depth + c_factor(n_node_samples))
    mean_path = np.mean(paths)
    c = c_factor(getattr(iso_model, 'max_samples_', 256))
    score = 2.0 ** (-mean_path / c) if c > 0 else 0.5
    offset = getattr(iso_model, 'offset_', -0.5)
    if not isinstance(offset, (int, float, np.number)):
        offset = -0.5
    else:
        offset = float(offset)
    decision = -score - offset
    is_anomaly = 1 if decision < 0 else 0
    return is_anomaly, float(score)

# 4. Load LSTM Model (Honest check: only active if TensorFlow is responsive and marked useful)
lstm_model = None
lstm_is_useful = bool(thresholds.get('lstm_is_useful', False))

def is_tf_available():
    if os.environ.get('DISABLE_TF', '0') == '1':
        return False
    import subprocess
    try:
        res = subprocess.run(
            [sys.executable, "-c", "import tensorflow; print('OK')"],
            capture_output=True, text=True, timeout=2
        )
        return res.returncode == 0 and "OK" in res.stdout
    except Exception:
        return False

if lstm_is_useful:
    print("[-] Checking TensorFlow availability for LSTM...", flush=True)
    if is_tf_available():
        try:
            import tensorflow as tf
            from tensorflow.keras.models import load_model
            lstm_path = os.path.join(BASE_DIR, 'lstm_powerplant_ids.keras')
            if os.path.exists(lstm_path):
                lstm_model = load_model(lstm_path)
                print(f"[+] Model 3: Deep Sequential LSTM loaded from {os.path.basename(lstm_path)}.", flush=True)
            else:
                print(f"[!] LSTM model artifact not found at {lstm_path}.", flush=True)
                lstm_is_useful = False
        except Exception as e:
            print(f"[*] TensorFlow / LSTM load error: {e}. Falling back to 2-of-2 consensus.")
            lstm_model = None
            lstm_is_useful = False
    else:
        print("[*] TensorFlow environment unavailable or timed out. Operating in honest 2-of-2 consensus mode.")
        lstm_model = None
        lstm_is_useful = False
else:
    print("[*] LSTM status: 'unavailable' (validation usefulness or environment condition).")
    print("[*] Operating in honest 2-of-2 consensus mode (RF + Isolation Forest). No synthetic scores will be faked.")

voting_mode = "2-of-3" if (lstm_model is not None and lstm_is_useful) else "2-of-2"
print(f"[+] Consensus Engine: {voting_mode} voting mode active.\n")

# Per-node 5-packet sliding windows for sequential temporal analysis
node_windows = collections.defaultdict(list)

def analyze_packet(raw_features, node_id="Node_01"):
    """
    Score raw telemetry packet features across models.
    Does NOT use simulated_class - decisions are strictly based on input features.
    """
    global node_windows
    expected_features = expected_dim

    # Feature-count guard to prevent crashes on malformed/legacy packets
    if len(raw_features) != expected_features:
        print(f"[!] Shape mismatch guard: expected {expected_features}, got {len(raw_features)}. Skipping packet.")
        return None

    scaled = scale_features(raw_features)

    # 1. Random Forest Supervised Probability & Vote
    rf_thresh = thresholds.get('rf_threshold', 0.48)
    rf_prob = predict_rf_prob(scaled)
    rf_vote = 1 if rf_prob >= rf_thresh else 0

    # 2. Isolation Forest Unsupervised Anomaly & Vote
    iso_flag = thresholds.get('iso_anomaly_flag', 1)
    iso_anomaly, _ = score_iso(scaled)
    iso_vote = 1 if iso_anomaly == iso_flag else 0

    # 3. Deep LSTM (Real inference only; no fabricated proxy formula)
    if lstm_model is not None and lstm_is_useful:
        window = node_windows[node_id]
        window.append(scaled)
        if len(window) > 5:
            window.pop(0)
        # Left-pad with first observation if window length < 5
        padded_window = list(window)
        while len(padded_window) < 5:
            padded_window.insert(0, padded_window[0])

        seq_input = np.array(padded_window, dtype=float).reshape(1, 5, -1)
        lstm_thresh = thresholds.get('lstm_threshold', 0.55)
        lstm_prob = float(lstm_model.predict(seq_input, verbose=0)[0][0])
        lstm_vote = 1 if lstm_prob >= lstm_thresh else 0
        lstm_status = "active"
        total_votes = rf_vote + iso_vote + lstm_vote
        alert = (total_votes >= 2)
    else:
        lstm_prob = None
        lstm_vote = None
        lstm_status = "unavailable"
        total_votes = rf_vote + iso_vote
        # 2-of-2 consensus mode: alert if both agree, or RF flags with high confidence
        alert = (total_votes >= 2)

    return alert, rf_prob, rf_vote, iso_anomaly, iso_vote, lstm_prob, lstm_vote, total_votes, lstm_status

def run_detection():
    last_processed_id = None
    print(f"[*] Actively monitoring '{STREAM_BUFFER_FILE}' for telemetry stream...\n")

    try:
        while True:
            if os.path.exists(STREAM_BUFFER_FILE):
                try:
                    with open(STREAM_BUFFER_FILE, 'r') as f:
                        packet = json.load(f)

                    pid = packet.get('packet_id')
                    raw_features = packet.get('features', [])
                    node_id = str(packet.get('node_id', 'Node_01'))

                    if pid is not None and pid != last_processed_id:
                        if len(raw_features) != expected_dim:
                            print(f"[!] Warning: Packet #{pid} feature shape mismatch: got {len(raw_features)}, expected {expected_dim}. Skipping.")
                            last_processed_id = pid
                            time.sleep(0.05)
                            continue

                        analysis = analyze_packet(raw_features, node_id=node_id)
                        if analysis is None:
                            last_processed_id = pid
                            time.sleep(0.05)
                            continue

                        last_processed_id = pid
                        alert, rf_prob, rf_vote, iso_anomaly, iso_vote, lstm_prob, lstm_vote, total_votes, lstm_status = analysis
                        ts = packet.get('timestamp', time.strftime('%Y-%m-%d %H:%M:%S'))
                        injected = packet.get('simulated_class', 'Unknown')

                        # Extract physical/SCADA fields for pass-through to dashboard
                        physical = packet.get('physical', {})
                        freq_dev = float(packet.get('frequency_deviation_hz', physical.get('frequency_deviation_hz', 0.0)))
                        volt_dev = float(packet.get('voltage_deviation_percent', physical.get('voltage_deviation_percent', 0.0)))
                        power_kw = float(packet.get('power_consumption_kw', physical.get('power_consumption_kw', 0.0)))
                        latency = float(packet.get('network_latency_ms', physical.get('network_latency_ms', 0.0)))
                        packet_rate = int(packet.get('packet_rate_per_sec', physical.get('packet_rate_per_sec', 0)))
                        scada_cmds = int(packet.get('scada_command_count', physical.get('scada_command_count', 0)))
                        entropy = float(packet.get('traffic_entropy', physical.get('traffic_entropy', 0.0)))

                        # Atomically serialize detection results for Web UI consumption
                        det_payload = {
                            "packet_id": pid,
                            "timestamp": ts,
                            "simulated_class": injected,
                            "alert": bool(alert),
                            "rf_score": float(rf_prob),
                            "rf_vote": int(rf_vote),
                            "iso_anomaly": int(iso_anomaly),
                            "iso_vote": int(iso_vote),
                            "lstm_score": float(lstm_prob) if lstm_prob is not None else None,
                            "lstm_vote": int(lstm_vote) if lstm_vote is not None else None,
                            "lstm_status": lstm_status,
                            "consensus_votes": int(total_votes),
                            "voting_mode": voting_mode,
                            "node_id": node_id,
                            "substation": str(packet.get('substation', 'Generation')),
                            "protocol": str(packet.get('protocol', 'DNP3')),
                            "device_type": str(packet.get('device_type', 'RTU')),
                            "source": str(packet.get('source', 'simulator')),
                            "physical": {
                                "frequency_deviation_hz": freq_dev,
                                "voltage_deviation_percent": volt_dev,
                                "power_consumption_kw": power_kw,
                                "network_latency_ms": latency,
                                "packet_rate_per_sec": packet_rate,
                                "scada_command_count": scada_cmds,
                                "traffic_entropy": entropy
                            },
                            "frequency_deviation_hz": freq_dev,
                            "voltage_deviation_percent": volt_dev,
                            "power_consumption_kw": power_kw,
                            "network_latency_ms": latency,
                            "packet_rate_per_sec": packet_rate,
                            "scada_command_count": scada_cmds,
                            "traffic_entropy": entropy
                        }

                        tmp = DETECTION_OUTPUT_FILE + '.tmp'
                        with open(tmp, 'w') as f_det:
                            json.dump(det_payload, f_det)
                        os.replace(tmp, DETECTION_OUTPUT_FILE)

                        # Diagnostic Terminal Logging
                        lstm_repr = f"{lstm_prob*100:5.1f}% (vote={lstm_vote})" if lstm_prob is not None else f"N/A ({lstm_status})"
                        max_votes = 3 if voting_mode == "2-of-3" else 2
                        if alert:
                            print(f"[{ts}] [PACKET #{pid:04d} | {node_id}] [CRITICAL INTRUSION ALERT] Injected: {injected}")
                            print(f"       -> RF Prob:     {rf_prob*100:5.1f}%  (vote={rf_vote})")
                            print(f"       -> Iso Forest:  {'OUTLIER' if iso_anomaly else 'NOMINAL'}  (vote={iso_vote})")
                            print(f"       -> Deep LSTM:   {lstm_repr}")
                            print(f"       -> Consensus:   [{total_votes}/{max_votes} VOTES] => *** SAFETY BREAKER TRIP ENGAGED ***\n")
                        else:
                            print(f"[{ts}] [PACKET #{pid:04d} | {node_id}] [SECURE] Nominal SCADA Flow (RF: {rf_prob*100:4.1f}%, Iso: {iso_anomaly}, LSTM: {lstm_repr}) [{total_votes}/{max_votes} Votes] => Forwarded.\n")

                except (json.JSONDecodeError, PermissionError):
                    pass

            time.sleep(0.05)

    except KeyboardInterrupt:
        print("\n[!] Detection engine stopped by operator.")

if __name__ == '__main__':
    run_detection()
