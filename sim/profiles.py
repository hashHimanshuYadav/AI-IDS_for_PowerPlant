import math
import random

CATEGORICAL_DOMAINS = {
    'region': ['North', 'South', 'East', 'West', 'Central'],
    'substation_type': ['Transmission', 'Distribution', 'Generation', 'Renewable'],
    'device_type': ['RTU', 'PLC', 'IED', 'SCADA_Server'],
    'communication_protocol': ['DNP3', 'Modbus_TCP', 'IEC61850', 'MQTT'],
    'user_role': ['Operator', 'Supervisor', 'Admin', 'Engineer'],
    'device_trust_level': ['Trusted', 'Medium', 'Low', 'Guest'],
    'firmware_version': ['v1.0', 'v1.2', 'v2.0', 'v2.3', 'v3.0'],
    'event_severity': ['Low', 'Medium', 'High', 'Critical'],
    'alert_priority': ['P1', 'P2', 'P3', 'P4'],
    'encryption_algorithm': ['AES256', 'RSA2048', 'DES', 'None'],
    'certificate_status': ['Valid', 'Expired', 'Revoked', 'SelfSigned']
}

# Baseline ranges calibrated from power plant telemetry distributions
NUMERIC_SPEC = {
    'packet_size_bytes': {'mean': 520.0, 'std': 180.0, 'min': 64.0, 'max': 1500.0, 'ar1': 0.45},
    'packet_rate_per_sec': {'mean': 480.0, 'std': 150.0, 'min': 50.0, 'max': 2500.0, 'ar1': 0.60},
    'network_latency_ms': {'mean': 45.0, 'std': 15.0, 'min': 5.0, 'max': 350.0, 'ar1': 0.55},
    'bandwidth_usage_mbps': {'mean': 35.0, 'std': 12.0, 'min': 1.0, 'max': 100.0, 'ar1': 0.50},
    'jitter_ms': {'mean': 4.5, 'std': 2.2, 'min': 0.1, 'max': 50.0, 'ar1': 0.40},
    'packet_loss_percent': {'mean': 0.25, 'std': 0.35, 'min': 0.0, 'max': 10.0, 'ar1': 0.30},
    'connection_duration_sec': {'mean': 3600.0, 'std': 1200.0, 'min': 60.0, 'max': 86400.0, 'ar1': 0.65},
    'active_connection_count': {'mean': 18.0, 'std': 6.0, 'min': 1.0, 'max': 60.0, 'ar1': 0.70},
    'failed_connection_count': {'mean': 0.4, 'std': 0.8, 'min': 0.0, 'max': 25.0, 'ar1': 0.25},
    'authentication_attempts': {'mean': 2.0, 'std': 1.2, 'min': 1.0, 'max': 30.0, 'ar1': 0.30},
    'failed_login_count': {'mean': 0.15, 'std': 0.45, 'min': 0.0, 'max': 15.0, 'ar1': 0.20},
    'cpu_utilization_percent': {'mean': 38.0, 'std': 12.0, 'min': 5.0, 'max': 98.0, 'ar1': 0.65},
    'memory_utilization_percent': {'mean': 48.0, 'std': 10.0, 'min': 10.0, 'max': 95.0, 'ar1': 0.75},
    'power_consumption_kw': {'mean': 245.0, 'std': 35.0, 'min': 50.0, 'max': 500.0, 'ar1': 0.80},
    'sensor_update_interval_ms': {'mean': 1000.0, 'std': 250.0, 'min': 100.0, 'max': 5000.0, 'ar1': 0.50},
    'telemetry_volume_mb': {'mean': 120.0, 'std': 40.0, 'min': 5.0, 'max': 800.0, 'ar1': 0.60},
    'scada_command_count': {'mean': 14.0, 'std': 6.0, 'min': 0.0, 'max': 80.0, 'ar1': 0.55},
    'control_signal_frequency': {'mean': 60.0, 'std': 0.08, 'min': 58.5, 'max': 61.5, 'ar1': 0.70},
    'measurement_variance': {'mean': 0.045, 'std': 0.02, 'min': 0.001, 'max': 0.50, 'ar1': 0.40},
    'voltage_deviation_percent': {'mean': 0.0, 'std': 0.45, 'min': -5.0, 'max': 5.0, 'ar1': 0.65},
    'frequency_deviation_hz': {'mean': 0.0, 'std': 0.035, 'min': -1.5, 'max': 1.5, 'ar1': 0.70},
    'intrusion_signature_score': {'mean': 0.08, 'std': 0.06, 'min': 0.0, 'max': 1.0, 'ar1': 0.35},
    'behavior_anomaly_score': {'mean': 0.10, 'std': 0.07, 'min': 0.0, 'max': 1.0, 'ar1': 0.40},
    'traffic_entropy': {'mean': 4.2, 'std': 0.6, 'min': 0.5, 'max': 8.0, 'ar1': 0.50},
    'session_risk_score': {'mean': 12.0, 'std': 8.0, 'min': 0.0, 'max': 100.0, 'ar1': 0.45},
    'federated_round': {'mean': 50.0, 'std': 25.0, 'min': 1.0, 'max': 100.0, 'ar1': 0.80}
}

ATTACK_CLASSES = [
    'DoS_Attack',
    'Replay_Attack',
    'False_Data_Injection',
    'Command_Injection',
    'Insider_Threat',
    'Spoofing_Attack',
    'Malware',
    'Reconnaissance'
]

# Feature shifts per attack class measured in noise standard deviations (subtle shifts ensuring overlap)
# Shifts are intentionally kept moderate (+0.8 to +1.8 sigma) so single-feature AUC is capped < 0.85
ATTACK_SIGNATURES = {
    'DoS_Attack': {
        'packet_rate_per_sec': 1.5,
        'network_latency_ms': 1.4,
        'packet_loss_percent': 1.6,
        'bandwidth_usage_mbps': 1.2,
        'jitter_ms': 1.1,
        'behavior_anomaly_score': 1.3
    },
    'Replay_Attack': {
        'measurement_variance': -1.5, # Unnaturally low variance / identical readings
        'traffic_entropy': -1.2,
        'jitter_ms': -1.0,
        'behavior_anomaly_score': 1.1,
        'session_risk_score': 0.9
    },
    'False_Data_Injection': {
        'frequency_deviation_hz': 1.5,
        'voltage_deviation_percent': 1.6,
        'measurement_variance': 1.3,
        'control_signal_frequency': 1.2,
        'behavior_anomaly_score': 1.2
    },
    'Command_Injection': {
        'scada_command_count': 1.6,
        'control_signal_frequency': 1.3,
        'cpu_utilization_percent': 1.2,
        'intrusion_signature_score': 1.4,
        'session_risk_score': 1.2
    },
    'Insider_Threat': {
        'failed_login_count': 1.6,
        'authentication_attempts': 1.5,
        'session_risk_score': 1.6,
        'active_connection_count': 1.1,
        'intrusion_signature_score': 1.2
    },
    'Spoofing_Attack': {
        'packet_size_bytes': 1.2,
        'jitter_ms': 1.4,
        'network_latency_ms': 1.1,
        'session_risk_score': 1.3,
        'behavior_anomaly_score': 1.2
    },
    'Malware': {
        'cpu_utilization_percent': 1.6,
        'memory_utilization_percent': 1.5,
        'traffic_entropy': 1.4,
        'telemetry_volume_mb': 1.3,
        'intrusion_signature_score': 1.3
    },
    'Reconnaissance': {
        'active_connection_count': 1.5,
        'failed_connection_count': 1.6,
        'connection_duration_sec': -1.2, # Fast probe connections
        'traffic_entropy': 1.3,
        'intrusion_signature_score': 1.4
    }
}
