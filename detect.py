import os
import time
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STREAM_BUFFER_FILE = os.path.join(BASE_DIR, 'live_stream.json')
DETECTION_OUTPUT_FILE = os.path.join(BASE_DIR, 'live_detection.json')
THRESHOLDS_FILE = os.path.join(BASE_DIR, 'thresholds.json')
FEATURE_COLS_FILE = os.path.join(BASE_DIR, 'feature_cols.json')

print("=" * 65)
print("  🛡️ POWER PLANT ICS AI INTRUSION DETECTION ENGINE")
print("=" * 65)
print("[-] Loading calibrated thresholds, feature specs, and IDS models...")

# Load calibrated thresholds
thresholds = {
    "rf_threshold": 0.73,
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

# Load feature list
expected_feature_cols = None
if os.path.exists(FEATURE_COLS_FILE):
    try:
        with open(FEATURE_COLS_FILE, 'r') as f:
            expected_feature_cols = json.load(f)
        print(f"[+] Loaded feature specifications ({len(expected_feature_cols)} features).")
    except Exception as e:
        print(f"[!] Warning loading feature_cols.json: {e}")

try:
    import joblib
    import numpy as np
except ImportError as e:
    raise SystemExit(
        f"\n[!] Python Environment Error: {e}\n"
        f"[*] Ensure your Python environment has dependencies installed:\n"
        f"    pip install -r requirements.txt\n"
    )

try:
    rf_model = joblib.load(os.path.join(BASE_DIR, 'rf_powerplant_ids.pkl'))
    iso_model = joblib.load(os.path.join(BASE_DIR, 'iso_powerplant_ids.pkl'))
    scaler = joblib.load(os.path.join(BASE_DIR, 'scaler_powerplant_ids.pkl'))
    expected_dim = getattr(scaler, 'n_features_in_', 37)
    print(f"[+] Scaler calibrated: expecting {expected_dim} input features.")
    print(f"[+] Model 1: Random Forest Supervised Classifier loaded.")
    print(f"[+] Model 2: Isolation Forest Anomaly Profiler loaded.")
except Exception as e:
    raise SystemExit(f"[!] Scikit-Learn artifact load error: {e}. Ensure model files exist in root.")

lstm_model = None
lstm_is_useful = bool(thresholds.get('lstm_is_useful', False))

if lstm_is_useful:
    try:
        import tensorflow as tf
        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
        tf.get_logger().setLevel('ERROR')
        from tensorflow.keras.models import load_model
        lstm_path = os.path.join(BASE_DIR, 'lstm_powerplant_ids.keras')
        if os.path.exists(lstm_path):
            lstm_model = load_model(lstm_path)
            print(f"[+] Model 3: Deep Sequential LSTM loaded from {os.path.basename(lstm_path)}.")
    except Exception as e:
        print(f"[!] Notice: TensorFlow / Keras loader note: {e}")
        lstm_model = None
else:
    print("[*] LSTM marked 'not useful' based on validation performance (AUC < 0.60).")
    print("[*] Operating in 2-of-2 consensus mode (RF + Isolation Forest). No synthetic scores will be faked.")

voting_mode = "2-of-3" if (lstm_model is not None and lstm_is_useful) else "2-of-2"
print(f"[+] Consensus Engine: {voting_mode} voting mode active.\n")

packet_window = []

def analyze_packet(raw_features):
    global packet_window
    expected_features = getattr(scaler, 'n_features_in_', 37)

    # Feature-count guard to prevent crashes
    if len(raw_features) != expected_features:
        print(f"[!] Shape mismatch guard: expected {expected_features}, got {len(raw_features)}. Skipping.")
        return None

    scaled = scaler.transform(np.array(raw_features, dtype=float).reshape(1, -1))

    # 1. Random Forest Supervised Probability & Vote
    rf_thresh = thresholds.get('rf_threshold', 0.73)
    rf_prob = float(rf_model.predict_proba(scaled)[0][1])
    rf_vote = 1 if rf_prob >= rf_thresh else 0

    # 2. Isolation Forest Unsupervised Anomaly & Vote
    # Scikit-Learn IsolationForest returns -1 for outliers and 1 for nominal inliers
    iso_flag = thresholds.get('iso_anomaly_flag', 1)
    iso_raw = iso_model.predict(scaled)[0]
    iso_anomaly = 1 if iso_raw == -1 else 0
    iso_vote = 1 if iso_anomaly == iso_flag else 0

    # 3. Deep LSTM (Real inference only; no fabricated proxy formula)
    if lstm_model is not None and lstm_is_useful:
        packet_window.append(scaled[0])
        if len(packet_window) > 5:
            packet_window.pop(0)
        while len(packet_window) < 5:
            packet_window.insert(0, scaled[0])

        seq_input = np.array(packet_window, dtype=float).reshape(1, 5, -1)
        lstm_thresh = thresholds.get('lstm_threshold', 0.55)
        lstm_prob = float(lstm_model.predict(seq_input, verbose=0)[0][0])
        lstm_vote = 1 if lstm_prob >= lstm_thresh else 0
        lstm_status = "active"
        total_votes = rf_vote + iso_vote + lstm_vote
        alert = total_votes >= 2
    else:
        lstm_prob = None
        lstm_vote = None
        lstm_status = "unavailable"
        total_votes = rf_vote + iso_vote
        # 2-of-2 consensus mode: both affirmative votes required
        alert = (total_votes >= 2)

    return alert, rf_prob, rf_vote, iso_anomaly, iso_vote, lstm_prob, lstm_vote, total_votes, lstm_status

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

                if pid is not None and pid != last_processed_id:
                    expected_dim = getattr(scaler, 'n_features_in_', 37)
                    if len(raw_features) != expected_dim:
                        print(f"[!] Warning: Packet #{pid} feature shape mismatch: got {len(raw_features)}, expected {expected_dim}. Skipping.")
                        last_processed_id = pid
                        time.sleep(0.05)
                        continue

                    analysis = analyze_packet(raw_features)
                    if analysis is None:
                        last_processed_id = pid
                        time.sleep(0.05)
                        continue

                    last_processed_id = pid
                    alert, rf_prob, rf_vote, iso_anomaly, iso_vote, lstm_prob, lstm_vote, total_votes, lstm_status = analysis
                    ts = packet.get('timestamp', time.strftime('%Y-%m-%d %H:%M:%S'))
                    injected = packet.get('simulated_class', 'Unknown')

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
                        "voting_mode": voting_mode
                    }

                    tmp = DETECTION_OUTPUT_FILE + '.tmp'
                    with open(tmp, 'w') as f_det:
                        json.dump(det_payload, f_det)
                    os.replace(tmp, DETECTION_OUTPUT_FILE)

                    # Diagnostic Terminal Logging
                    lstm_repr = f"{lstm_prob*100:5.1f}% (vote={lstm_vote})" if lstm_prob is not None else f"N/A ({lstm_status})"
                    max_votes = 3 if voting_mode == "2-of-3" else 2
                    if alert:
                        print(f"[{ts}] [PACKET #{pid:04d}] [CRITICAL INTRUSION ALERT] Class: {injected}")
                        print(f"       -> RF Prob:     {rf_prob*100:5.1f}%  (vote={rf_vote})")
                        print(f"       -> Iso Forest:  {'OUTLIER' if iso_anomaly else 'NOMINAL'}  (vote={iso_vote})")
                        print(f"       -> Deep LSTM:   {lstm_repr}")
                        print(f"       -> Consensus:   [{total_votes}/{max_votes} VOTES] => *** SAFETY BREAKER TRIP ENGAGED ***\n")
                    else:
                        print(f"[{ts}] [PACKET #{pid:04d}] [SECURE] Nominal SCADA Flow (RF: {rf_prob*100:4.1f}%, Iso: {iso_anomaly}, LSTM: {lstm_repr}) [{total_votes}/{max_votes} Votes] => Forwarded.\n")

            except (json.JSONDecodeError, PermissionError):
                pass

        time.sleep(0.05)

except KeyboardInterrupt:
    print("\n[!] Detection engine stopped by operator.")
