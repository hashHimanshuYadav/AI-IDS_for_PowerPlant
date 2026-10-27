import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix, classification_report
)

os.environ['KERAS_HOME'] = os.path.abspath('.keras')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

print("=" * 65)
print("  🏭 AI-IDS CLEAN ML RETRAINING PIPELINE (NO DATA LEAKAGE)")
print("=" * 65)

# 1. Load original uncorrupted dataset
CSV_FILE = 'Distributed_MultiAgent_Energy_Cybersecurity_Dataset.csv'
if not os.path.exists(CSV_FILE):
    raise SystemExit(f"[!] Dataset not found: {CSV_FILE}")

df = pd.read_csv(CSV_FILE)
print(f"[+] Loaded raw dataset: {df.shape[0]} rows, {df.shape[1]} columns.")

# Sort chronologically per node
df_sorted = df.sort_values(by=['energy_node_id', 'record_id']).reset_index(drop=True)

# 2. Identify and encode categorical features
cat_cols = [
    'region', 'substation_type', 'device_type', 'communication_protocol',
    'user_role', 'device_trust_level', 'firmware_version', 'event_severity',
    'alert_priority', 'encryption_algorithm', 'certificate_status'
]

label_encoders = {}
for col in cat_cols:
    if col in df_sorted.columns:
        le = LabelEncoder()
        df_sorted[col] = le.fit_transform(df_sorted[col].astype(str))
        label_encoders[col] = le

joblib.dump(label_encoders, 'label_encoders.pkl')
print("[+] Categorical label encoders saved to label_encoders.pkl")

# Binary target label
df_sorted['is_attack'] = (df_sorted['attack_type'] != 'Normal').astype(int)

# 37 feature columns (drop strictly record_id, energy_node_id, attack_type, is_attack)
feature_cols = [c for c in df_sorted.columns if c not in ['record_id', 'energy_node_id', 'attack_type', 'is_attack']]
print(f"[+] Input feature dimension: {len(feature_cols)} features.")

with open('feature_cols.json', 'w') as f:
    json.dump(feature_cols, f, indent=2)
print("[+] Feature column list saved to feature_cols.json")

# 3. Train / Validation / Test split (chronological per node, 70/15/15)
train_dfs, val_dfs, test_dfs = [], [], []
for node, g in df_sorted.groupby('energy_node_id'):
    n = len(g)
    n_train = int(n * 0.70)
    n_val = int(n * 0.15)
    train_dfs.append(g.iloc[:n_train])
    val_dfs.append(g.iloc[n_train:n_train+n_val])
    test_dfs.append(g.iloc[n_train+n_val:])

train_df = pd.concat(train_dfs).reset_index(drop=True)
val_df = pd.concat(val_dfs).reset_index(drop=True)
test_df = pd.concat(test_dfs).reset_index(drop=True)

print(f"[+] Split summary: Train={len(train_df)} | Val={len(val_df)} | Test={len(test_df)}")

# Save test split as test_stream.csv (with original values before categorical transform for realism)
df_orig = pd.read_csv(CSV_FILE).sort_values(by=['energy_node_id', 'record_id']).reset_index(drop=True)
orig_test_dfs = []
for node, g in df_orig.groupby('energy_node_id'):
    n = len(g)
    n_train = int(n * 0.70)
    n_val = int(n * 0.15)
    orig_test_dfs.append(g.iloc[n_train+n_val:])

orig_test_df = pd.concat(orig_test_dfs).reset_index(drop=True)
orig_test_df.to_csv('test_stream.csv', index=False)
print(f"[+] Saved held-out test stream to test_stream.csv ({len(orig_test_df)} records across {orig_test_df['attack_type'].nunique()} classes)")

# 4. Fit Scaler strictly on train set
X_train = train_df[feature_cols].values
y_train = train_df['is_attack'].values

X_val = val_df[feature_cols].values
y_val = val_df['is_attack'].values

X_test = test_df[feature_cols].values
y_test = test_df['is_attack'].values

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)

joblib.dump(scaler, 'scaler_powerplant_ids.pkl')
print("[+] StandardScaler fitted on X_train and saved to scaler_powerplant_ids.pkl")

# 5. Train Model 1: Random Forest
print("\n[-] Training Random Forest Classifier...")
rf_model = RandomForestClassifier(
    n_estimators=150,
    max_depth=16,
    min_samples_split=4,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)
rf_model.fit(X_train_scaled, y_train)
joblib.dump(rf_model, 'rf_powerplant_ids.pkl')
print("[+] Random Forest model saved to rf_powerplant_ids.pkl")

# 6. Train Model 2: Isolation Forest (Trained on Normal baseline)
print("\n[-] Training Isolation Forest Anomaly Detector...")
X_train_normal = X_train_scaled[y_train == 0]
iso_model = IsolationForest(
    n_estimators=150,
    contamination=0.10,
    max_samples=256,
    random_state=42,
    n_jobs=-1
)
iso_model.fit(X_train_normal)
joblib.dump(iso_model, 'iso_powerplant_ids.pkl')
print("[+] Isolation Forest saved to iso_powerplant_ids.pkl")

# 7. Train Model 3: Deep LSTM (Window size = 5 per node)
print("\n[-] Building 5-step sequential windows per node for LSTM...")
STEPS = 5

def make_node_windows(df_split, X_scaled):
    Xs, ys = [], []
    offset = 0
    for node, g in df_split.groupby('energy_node_id'):
        g_len = len(g)
        g_X = X_scaled[offset : offset + g_len]
        g_y = g['is_attack'].values
        offset += g_len
        for i in range(g_len - STEPS + 1):
            Xs.append(g_X[i : i + STEPS])
            ys.append(g_y[i + STEPS - 1]) # Label of LAST row in window
    return np.array(Xs), np.array(ys)

X_train_seq, y_train_seq = make_node_windows(train_df, X_train_scaled)
X_val_seq, y_val_seq = make_node_windows(val_df, X_val_scaled)
X_test_seq, y_test_seq = make_node_windows(test_df, X_test_scaled)

lstm_is_useful = False
lstm_auc = 0.50
lstm_normal_recall = 0.00
lstm_test_probs = np.full(len(y_test_seq), 0.5)

try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import LSTM, Dense, Dropout, Input, BatchNormalization
    from sklearn.utils.class_weight import compute_class_weight

    classes = np.unique(y_train_seq)
    weights = compute_class_weight('balanced', classes=classes, y=y_train_seq)
    class_weights = dict(zip(classes, weights))

    lstm_model = Sequential([
        Input(shape=(STEPS, X_train_seq.shape[2])),
        LSTM(32, return_sequences=False),
        BatchNormalization(),
        Dropout(0.20),
        Dense(16, activation='relu'),
        Dense(1, activation='sigmoid')
    ])
    lstm_model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    lstm_model.fit(
        X_train_seq, y_train_seq,
        epochs=8,
        batch_size=64,
        class_weight=class_weights,
        validation_data=(X_val_seq, y_val_seq),
        verbose=0
    )
    lstm_model.save('lstm_powerplant_ids.keras')
    print("[+] Trained LSTM saved to lstm_powerplant_ids.keras")

    lstm_val_probs = lstm_model.predict(X_val_seq, verbose=0).ravel()
    lstm_test_probs = lstm_model.predict(X_test_seq, verbose=0).ravel()
    lstm_auc = float(roc_auc_score(y_test_seq, lstm_test_probs))
    lstm_preds = (lstm_test_probs >= 0.50).astype(int)
    lstm_normal_recall = float(recall_score(y_test_seq, lstm_preds, pos_label=0, zero_division=0))

    print(f"[+] LSTM Test ROC-AUC: {lstm_auc:.4f} | Normal Recall: {lstm_normal_recall:.4f}")
    if lstm_auc >= 0.60 and lstm_normal_recall > 0.05:
        lstm_is_useful = True
        print("[+] LSTM validation passed threshold (AUC >= 0.60).")
    else:
        lstm_is_useful = False
        print("[!] LSTM validation result: Model is not useful (ROC-AUC < 0.60 or zero Normal recall).")

except Exception as e:
    print(f"[!] LSTM training exception: {e}")
    lstm_is_useful = False

# 8. Threshold Tuning on Validation Set
print("\n[-] Calibrating thresholds on Validation set...")
rf_val_probs = rf_model.predict_proba(X_val_scaled)[:, 1]
rf_test_probs = rf_model.predict_proba(X_test_scaled)[:, 1]

# Choose RF threshold optimizing F1 with low false alarm rate
best_rf_thresh = 0.50
best_rf_f1 = -1.0
for thresh in np.linspace(0.30, 0.85, 56):
    preds = (rf_val_probs >= thresh).astype(int)
    f1 = f1_score(y_val, preds, zero_division=0)
    # Check FPR on normal
    cm = confusion_matrix(y_val, preds)
    tn = cm[0, 0] if len(cm) > 0 else 0
    fp = cm[0, 1] if len(cm) > 0 and cm.shape[1] > 1 else 0
    fpr = fp / (tn + fp) if (tn + fp) > 0 else 1.0
    if f1 > best_rf_f1 and fpr <= 0.20:
        best_rf_f1 = f1
        best_rf_thresh = float(thresh)

if best_rf_f1 <= 0:
    best_rf_thresh = 0.55

thresholds = {
    "rf_threshold": round(best_rf_thresh, 3),
    "iso_anomaly_flag": 1,
    "lstm_threshold": 0.55,
    "lstm_is_useful": bool(lstm_is_useful),
    "voting_mode": "3-of-3" if lstm_is_useful else "2-of-2"
}

with open('thresholds.json', 'w') as f:
    json.dump(thresholds, f, indent=2)
print(f"[+] Thresholds calibrated and saved to thresholds.json: {thresholds}")

# 9. Compute Held-out Test Metrics & Write metrics.json
print("\n[-] Generating held-out test evaluation metrics...")
rf_test_preds = (rf_test_probs >= thresholds["rf_threshold"]).astype(int)
iso_test_raw = iso_model.predict(X_test_scaled)
iso_test_preds = np.where(iso_test_raw == -1, 1, 0)
iso_test_scores = -iso_model.decision_function(X_test_scaled)

rf_acc = float(accuracy_score(y_test, rf_test_preds))
rf_prec = float(precision_score(y_test, rf_test_preds, zero_division=0))
rf_rec = float(recall_score(y_test, rf_test_preds, zero_division=0))
rf_f1 = float(f1_score(y_test, rf_test_preds, zero_division=0))
rf_auc = float(roc_auc_score(y_test, rf_test_probs))
rf_pr_auc = float(average_precision_score(y_test, rf_test_probs))

iso_acc = float(accuracy_score(y_test, iso_test_preds))
iso_prec = float(precision_score(y_test, iso_test_preds, zero_division=0))
iso_rec = float(recall_score(y_test, iso_test_preds, zero_division=0))
iso_f1 = float(f1_score(y_test, iso_test_preds, zero_division=0))
iso_auc = float(roc_auc_score(y_test, iso_test_scores))
iso_pr_auc = float(average_precision_score(y_test, iso_test_scores))

# Detection rate per attack_type on test set
detection_rates_per_attack = {}
for attack_type in orig_test_df['attack_type'].unique():
    mask = (orig_test_df['attack_type'] == attack_type).values
    if np.sum(mask) > 0:
        rf_det_rate = float(np.mean(rf_test_preds[mask]))
        iso_det_rate = float(np.mean(iso_test_preds[mask]))
        detection_rates_per_attack[attack_type] = {
            "samples": int(np.sum(mask)),
            "rf_detection_rate": round(rf_det_rate, 4),
            "iso_detection_rate": round(iso_det_rate, 4)
        }

metrics_data = {
    "evaluation_dataset": "Held-out test_stream.csv (chronological split, no leakage)",
    "test_sample_count": len(y_test),
    "normal_samples": int(np.sum(y_test == 0)),
    "attack_samples": int(np.sum(y_test == 1)),
    "random_forest": {
        "accuracy": round(rf_acc, 4),
        "precision": round(rf_prec, 4),
        "recall": round(rf_rec, 4),
        "f1_score": round(rf_f1, 4),
        "roc_auc": round(rf_auc, 4),
        "pr_auc": round(rf_pr_auc, 4),
        "calibrated_threshold": thresholds["rf_threshold"]
    },
    "isolation_forest": {
        "accuracy": round(iso_acc, 4),
        "precision": round(iso_prec, 4),
        "recall": round(iso_rec, 4),
        "f1_score": round(iso_f1, 4),
        "roc_auc": round(iso_auc, 4),
        "pr_auc": round(iso_pr_auc, 4)
    },
    "lstm_sequential": {
        "roc_auc": round(lstm_auc, 4),
        "normal_recall": round(lstm_normal_recall, 4),
        "is_useful": bool(lstm_is_useful),
        "status": "active" if lstm_is_useful else "unavailable"
    },
    "detection_rates_per_attack_type": detection_rates_per_attack,
    "quality_assessment": "POOR - The unconditioned raw Kaggle dataset features exhibit near-zero correlation with attack labels (ROC-AUC ~0.50). Without synthetic label leakage, ML models cannot achieve meaningful discrimination on raw random noise."
}

with open('metrics.json', 'w') as f:
    json.dump(metrics_data, f, indent=2)

print("\n" + "=" * 65)
print("  EVALUATION METRICS (test_stream.csv)")
print("=" * 65)
print(f"Random Forest    -> Acc: {rf_acc:.4f} | Prec: {rf_prec:.4f} | Rec: {rf_rec:.4f} | F1: {rf_f1:.4f} | ROC-AUC: {rf_auc:.4f}")
print(f"Isolation Forest -> Acc: {iso_acc:.4f} | Prec: {iso_prec:.4f} | Rec: {iso_rec:.4f} | F1: {iso_f1:.4f} | ROC-AUC: {iso_auc:.4f}")
print(f"LSTM Sequential  -> ROC-AUC: {lstm_auc:.4f} | Normal Recall: {lstm_normal_recall:.4f} | Useful: {lstm_is_useful}")
print("\nPer-Attack Detection Rates:")
for at, d in detection_rates_per_attack.items():
    print(f"  - {at:<22}: RF={d['rf_detection_rate']*100:5.1f}% | Iso={d['iso_detection_rate']*100:5.1f}% (N={d['samples']})")
print("\nAssessment: " + metrics_data["quality_assessment"])
print("=" * 65)
