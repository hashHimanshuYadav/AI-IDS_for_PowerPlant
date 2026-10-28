import os
import sys
import time
import json
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

print("=================================================================", flush=True)
print("  ⚖️ AI-IDS MODEL INFERENCE PARITY TEST (1000 TEST SAMPLES)", flush=True)
print("=================================================================", flush=True)

import csv

# 1. Load 1000 rows from data/sim/test.csv
test_csv = os.path.join(BASE_DIR, 'data', 'sim', 'test.csv')
print(f"[-] Loading 1000 rows from {os.path.relpath(test_csv, BASE_DIR)}...", flush=True)

feature_cols = json.load(open(os.path.join(BASE_DIR, 'feature_cols.json')))
encoders_map = json.load(open(os.path.join(BASE_DIR, 'encoders_map.json')))

X_raw_list = []
with open(test_csv, 'r', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for i, row in enumerate(reader):
        if i >= 1000:
            break
        row_vals = []
        for c in feature_cols:
            val = row[c]
            if c in encoders_map:
                row_vals.append(encoders_map[c].get(str(val), 0))
            else:
                row_vals.append(float(val))
        X_raw_list.append(row_vals)

X_raw = np.array(X_raw_list, dtype=float)
print(f"[+] Extracted X_raw shape: {X_raw.shape}", flush=True)

# 2. Score with detect.py NumPy engine
print("\n[-] Scoring 1000 rows with detect.py NumPy engine...", flush=True)
import detect
t0 = time.time()
rf_numpy_probs = []
iso_numpy_preds = []
for i in range(1000):
    res = detect.analyze_packet(X_raw[i])
    rf_numpy_probs.append(res[1])
    iso_numpy_preds.append(res[3])
t_numpy = time.time() - t0
print(f"[+] NumPy engine evaluated 1000 samples in {t_numpy*1000:.2f} ms ({t_numpy/1000*1000:.3f} ms/sample)", flush=True)

# 3. Score with scikit-learn
print("\n[-] Loading models via scikit-learn (joblib)...", flush=True)
import joblib

t1 = time.time()
print("    -> Loading Scaler (scaler_powerplant_ids.pkl)...", flush=True)
scaler_skl = joblib.load(os.path.join(BASE_DIR, 'scaler_powerplant_ids.pkl'))
print(f"    [+] Scaler loaded ({time.time() - t1:.2f} s)", flush=True)

t_rf = time.time()
print("    -> Loading Random Forest (rf_powerplant_ids.pkl)...", flush=True)
rf_skl = joblib.load(os.path.join(BASE_DIR, 'rf_powerplant_ids.pkl'))
print(f"    [+] Random Forest loaded ({time.time() - t_rf:.2f} s)", flush=True)

t_iso = time.time()
print("    -> Loading Isolation Forest (iso_powerplant_ids.pkl)...", flush=True)
iso_skl = joblib.load(os.path.join(BASE_DIR, 'iso_powerplant_ids.pkl'))
print(f"    [+] Isolation Forest loaded ({time.time() - t_iso:.2f} s)", flush=True)

print("\n[-] Scoring 1000 rows with scikit-learn...", flush=True)
t2 = time.time()
X_scaled_skl = scaler_skl.transform(X_raw)
rf_skl_probs = rf_skl.predict_proba(X_scaled_skl)[:, 1]
iso_skl_raw = iso_skl.predict(X_scaled_skl)
iso_skl_preds = np.where(iso_skl_raw == -1, 1, 0)
print(f"[+] Scikit-Learn evaluated 1000 samples in {(time.time() - t2)*1000:.2f} ms", flush=True)

# 4. Parity Verification
rf_abs_diff = np.abs(np.array(rf_numpy_probs) - rf_skl_probs)
max_rf_diff = float(np.max(rf_abs_diff))
mean_rf_diff = float(np.mean(rf_abs_diff))

iso_mismatches = int(np.sum(np.array(iso_numpy_preds) != iso_skl_preds))

# Also compare RF threshold votes
rf_numpy_votes = (np.array(rf_numpy_probs) >= 0.48).astype(int)
rf_skl_votes = (rf_skl_probs >= 0.48).astype(int)
rf_vote_mismatches = int(np.sum(rf_numpy_votes != rf_skl_votes))

print("\n" + "=" * 65, flush=True)
print("  PARITY VERIFICATION REPORT", flush=True)
print("=" * 65, flush=True)
print(f"Random Forest Probability Max Absolute Difference: {max_rf_diff:.8e}")
print(f"Random Forest Probability Mean Absolute Difference: {mean_rf_diff:.8e}")
print(f"Random Forest Decision Vote Mismatches (tau=0.48): {rf_vote_mismatches} / 1000")
print(f"Isolation Forest Anomaly Mismatches (outlier=1):    {iso_mismatches} / 1000")

if max_rf_diff < 1e-5 and iso_mismatches == 0 and rf_vote_mismatches == 0:
    print("\n>>> RESULT: PASS (100% Exact Mathematical Equivalence!) <<<")
    sys.exit(0)
else:
    print("\n>>> RESULT: FAIL (Predictions differ between scikit-learn and NumPy) <<<")
    sys.exit(1)
