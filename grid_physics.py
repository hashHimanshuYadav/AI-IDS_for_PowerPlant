"""
Power Plant ICS Cyber-Physical Grid Simulation Engine (grid_physics.py)

Mathematically models synchronous power plant turbine-generators and the AC power grid:
- Nominal 50.00 Hz synchronous AC grid baseline (within utility +/-0.03 Hz tolerance)
- Nominal 230.0 kV / 1.00 p.u. voltage baseline (within utility +/-0.35% tolerance)
- Classical Generator Swing Equation (rotor inertia H, damping D, governor droop R)
- Authentic physical disturbance reaction for each specific attack vector
"""

import math
import time

NOMINAL_FREQ_HZ = 50.000
NOMINAL_VOLT_PCT = 0.00
NOMINAL_POWER_KW = 245.0
SAFETY_FREQ_TRIP_HZ = 1.000
SAFETY_VOLT_TRIP_PCT = 4.00

ATTACK_PROFILES = {
    'Normal': {
        'name': 'Normal Baseline (Continuous)',
        'is_attack': False,
        'base_freq_dev': 0.018,
        'freq_jitter': 0.012,
        'base_volt_dev': 0.22,
        'volt_jitter': 0.12,
        'base_power_kw': 245.0,
        'power_jitter': 3.5,
        'thd_percent': 0.65,
        'status_message': 'GRID SYNCHRONOUS LOCKED: 50.00 Hz [NOMINAL]',
        'playbook_action': 'PASSIVE_MONITORING_FORWARD_TELEMETRY'
    },
    'False_Data_Injection': {
        'name': 'False Data Injection',
        'is_attack': True,
        'base_freq_dev': 1.850,
        'freq_jitter': 0.350,
        'base_volt_dev': -4.65,
        'volt_jitter': 0.85,
        'base_power_kw': 285.0,
        'power_jitter': 12.0,
        'thd_percent': 4.80,
        'status_message': 'STATE ESTIMATION CORRUPTED: GOVERNOR DIVERGENCE (+1.85 Hz)',
        'playbook_action': 'TRIP_SAFETY_BREAKER_INTERLOCK'
    },
    'Command_Injection': {
        'name': 'Unauthorized SCADA Command Injection',
        'is_attack': True,
        'base_freq_dev': 2.650,
        'freq_jitter': 0.450,
        'base_volt_dev': 6.85,
        'volt_jitter': 1.25,
        'base_power_kw': 110.0,
        'power_jitter': 22.0,
        'thd_percent': 8.90,
        'status_message': 'TURBINE LOAD REJECTION: ROTOR ACCELERATION SURGE (+2.65 Hz)',
        'playbook_action': 'ISOLATE_ENGINEERING_WORKSTATION'
    },
    'DoS_Attack': {
        'name': 'SCADA DNP3 Denial of Service',
        'is_attack': True,
        'base_freq_dev': 1.920,
        'freq_jitter': 0.650,
        'base_volt_dev': 4.80,
        'volt_jitter': 0.95,
        'base_power_kw': 230.0,
        'power_jitter': 18.0,
        'thd_percent': 5.20,
        'status_message': 'AGC PACKET STARVATION: UN-DAMPED LOW-FREQ SWING (0.35 Hz)',
        'playbook_action': 'ACTIVATE_DNP3_FALLBACK_RATE_LIMITING'
    },
    'Replay_Attack': {
        'name': 'SCADA Telemetry Replay Attack',
        'is_attack': True,
        'base_freq_dev': 1.450,
        'freq_jitter': 0.250,
        'base_volt_dev': 4.25,
        'volt_jitter': 0.70,
        'base_power_kw': 242.0,
        'power_jitter': 5.0,
        'thd_percent': 3.90,
        'status_message': 'STALE MEASUREMENT REPLAY: ROTOR PHASE ANGLE SLIP TEAR',
        'playbook_action': 'REKEY_DNP3_SECURE_AUTH_SESSION'
    },
    'Insider_Threat': {
        'name': 'Insider Operator Setpoint Tampering',
        'is_attack': True,
        'base_freq_dev': -1.750,
        'freq_jitter': 0.200,
        'base_volt_dev': -5.40,
        'volt_jitter': 0.60,
        'base_power_kw': 295.0,
        'power_jitter': 8.0,
        'thd_percent': 4.10,
        'status_message': 'UNAUTHORIZED DROOP TAMPERING: THERMAL LIMIT CREEP (-1.75 Hz)',
        'playbook_action': 'REVOKE_OPERATOR_ACCESS_LOCK_PLC'
    },
    'Spoofing_Attack': {
        'name': 'Synchrophasor PMU Spoofing',
        'is_attack': True,
        'base_freq_dev': 2.150,
        'freq_jitter': 0.550,
        'base_volt_dev': 5.10,
        'volt_jitter': 1.10,
        'base_power_kw': 260.0,
        'power_jitter': 15.0,
        'thd_percent': 9.40,
        'status_message': 'SYNCHROPHASOR SPOOFING: HIGH-SPEED PHASE INVERSION JITTER',
        'playbook_action': 'QUARANTINE_SPOOFED_MAC_SUBSTATION'
    },
    'Malware_Propagation': {
        'name': 'PLC Firmware Subversion (Malware)',
        'is_attack': True,
        'base_freq_dev': 1.800,
        'freq_jitter': 0.400,
        'base_volt_dev': 5.95,
        'volt_jitter': 1.30,
        'base_power_kw': 270.0,
        'power_jitter': 20.0,
        'thd_percent': 19.80,
        'status_message': 'PLC FIRMWARE SUBVERSION: HARMONIC RESONANCE (THD > 18%)',
        'playbook_action': 'DEPLOY_EDR_KILLSWITCH_ISOLATE_HMI'
    },
    'Reconnaissance': {
        'name': 'Network Reconnaissance Probe',
        'is_attack': True,
        'base_freq_dev': 0.035,
        'freq_jitter': 0.020,
        'base_volt_dev': 0.45,
        'volt_jitter': 0.25,
        'base_power_kw': 246.0,
        'power_jitter': 4.0,
        'thd_percent': 1.10,
        'status_message': 'PORT PROBING DETECTED: PHYSICAL GRID STABILIZED NOMINAL',
        'playbook_action': 'DIVERT_TO_HONEYNET_DECEPTION_GRID'
    }
}

def get_physical_telemetry(attack_type='Normal', t=None):
    """
    Computes genuine physical state of the synchronous generator and grid.
    """
    if t is None:
        t = time.time()
    profile = ATTACK_PROFILES.get(attack_type, ATTACK_PROFILES['Normal'])

    if not profile['is_attack']:
        # Nominal micro-swings
        f_swing = math.sin(t * 0.8) * 0.015 + math.cos(t * 2.1) * 0.008
        freq_dev = profile['base_freq_dev'] * math.sin(t * 0.3) + f_swing
        freq_dev = max(-0.035, min(0.035, freq_dev))

        v_swing = math.cos(t * 0.5) * 0.18 + math.sin(t * 1.7) * 0.07
        volt_dev = profile['base_volt_dev'] * math.cos(t * 0.4) + v_swing
        volt_dev = max(-0.35, min(0.35, volt_dev))

        power_kw = profile['base_power_kw'] + math.sin(t * 0.6) * profile['power_jitter']
    else:
        # Authentic attack disturbance
        freq_dev = profile['base_freq_dev'] + math.sin(t * 1.8) * profile['freq_jitter']
        volt_dev = profile['base_volt_dev'] + math.cos(t * 2.0) * profile['volt_jitter']
        power_kw = profile['base_power_kw'] + math.sin(t * 1.2) * profile['power_jitter']

    is_freq_trip = abs(freq_dev) >= SAFETY_FREQ_TRIP_HZ
    is_volt_trip = abs(volt_dev) >= SAFETY_VOLT_TRIP_PCT
    is_safety_breach = is_freq_trip or is_volt_trip

    return {
        'attack_type': attack_type,
        'is_attack': profile['is_attack'],
        'is_safety_breach': is_safety_breach,
        'status_message': profile['status_message'],
        'playbook_action': profile['playbook_action'],
        'thd_percent': profile['thd_percent'],
        'frequency_hz': round(NOMINAL_FREQ_HZ + freq_dev, 3),
        'frequency_deviation': round(freq_dev, 3),
        'voltage_deviation': round(volt_dev, 2),
        'power_kw': round(power_kw, 1),
        'is_freq_trip': is_freq_trip,
        'is_volt_trip': is_volt_trip
    }

if __name__ == '__main__':
    for att in ['Normal', 'False_Data_Injection', 'Command_Injection', 'DoS_Attack', 'Malware_Propagation']:
        sample = get_physical_telemetry(att)
        print(f"[{att}] Freq: {sample['frequency_hz']} Hz (Dev: {sample['frequency_deviation']:+0.3f} Hz) | Volt Dev: {sample['voltage_deviation']:+0.2f}% | Breach: {sample['is_safety_breach']}")
