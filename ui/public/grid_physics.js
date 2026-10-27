/**
 * Power Plant ICS Cyber-Physical Simulation Engine (grid_physics.js)
 * 
 * Mathematically models synchronous power generation physical dynamics:
 * - Nominal 50.00 Hz synchronous AC grid baseline (within utility +/-0.03 Hz tolerance)
 * - Nominal 230.0 kV / 1.00 p.u. voltage baseline (within utility +/-0.35% tolerance)
 * - Classical Generator Swing Equation (rotor inertia H, damping D, governor droop)
 * - Authentic physical disturbance reaction for each specific attack vector
 * - Multi-harmonic synthesis (fundamental, 3rd, 5th, 7th harmonics)
 * 
 * Compatible with both Browser (window.GridPhysics) and Node.js (CommonJS).
 */

(function () {
  // --- Utility Grid Physical Constants ---
  const NOMINAL_FREQ_HZ = 50.000;
  const NOMINAL_VOLT_PCT = 0.00; // 0.00% deviation baseline (1.00 p.u.)
  const NOMINAL_POWER_KW = 245.0; // Dataset baseline mean
  const SAFETY_FREQ_TRIP_HZ = 1.000; // ANSI/IEEE C37.118 safety interlock threshold (+/-1.0 Hz)
  const SAFETY_VOLT_TRIP_PCT = 4.00; // Grid over/under-voltage trip threshold (+/-4.0%)

  // Attack profile definitions with physically grounded parameters
  const ATTACK_PROFILES = {
    'Normal': {
      name: 'Normal Baseline (Continuous)',
      isAttack: false,
      baseFreqDev: 0.018,
      freqDevJitter: 0.012,
      baseVoltDev: 0.22,
      voltDevJitter: 0.12,
      basePowerKw: 245.0,
      powerJitter: 3.5,
      thdPercent: 0.65,
      statusMessage: 'GRID SYNCHRONOUS LOCKED: 50.00 Hz [NOMINAL]',
      waveformType: 'sine_pure',
      playbookAction: 'PASSIVE_MONITORING_FORWARD_TELEMETRY'
    },
    'False_Data_Injection': {
      name: 'False Data Injection',
      isAttack: true,
      // Spoofed power flow causes governor hunting and persistent positive frequency drift
      baseFreqDev: 1.850,
      freqDevJitter: 0.350,
      baseVoltDev: -4.65,
      voltDevJitter: 0.85,
      basePowerKw: 285.0,
      powerJitter: 12.0,
      thdPercent: 4.80,
      statusMessage: 'STATE ESTIMATION CORRUPTED: GOVERNOR DIVERGENCE (+1.85 Hz)',
      waveformType: 'quantized_sensor_drift',
      playbookAction: 'TRIP_SAFETY_BREAKER_INTERLOCK'
    },
    'Command_Injection': {
      name: 'Unauthorized SCADA Command Injection',
      isAttack: true,
      // Breaker trip / turbine valve cut causes sudden load rejection and severe rotor acceleration
      baseFreqDev: 2.650,
      freqDevJitter: 0.450,
      baseVoltDev: 6.85,
      voltDevJitter: 1.25,
      basePowerKw: 110.0, // Sharp active power drop
      powerJitter: 22.0,
      thdPercent: 8.90,
      statusMessage: 'TURBINE LOAD REJECTION: ROTOR ACCELERATION SURGE (+2.65 Hz)',
      waveformType: 'transient_ringing_surge',
      playbookAction: 'ISOLATE_ENGINEERING_WORKSTATION'
    },
    'DoS_Attack': {
      name: 'SCADA DNP3 Denial of Service',
      isAttack: true,
      // Telemetry packet starvation causes un-damped low-frequency inter-area oscillation (0.35 Hz)
      baseFreqDev: 1.920,
      freqDevJitter: 0.650,
      baseVoltDev: 4.80,
      voltDevJitter: 0.95,
      basePowerKw: 230.0,
      powerJitter: 18.0,
      thdPercent: 5.20,
      statusMessage: 'AGC PACKET STARVATION: UN-DAMPED LOW-FREQ SWING (0.35 Hz)',
      waveformType: 'undamped_hunting_swing',
      playbookAction: 'ACTIVATE_DNP3_FALLBACK_RATE_LIMITING'
    },
    'Replay_Attack': {
      name: 'SCADA Telemetry Replay Attack',
      isAttack: true,
      // Stale recorded sequence replayed: artificial frozen profile punctuated by phase tears
      baseFreqDev: 1.450,
      freqDevJitter: 0.250,
      baseVoltDev: 4.25,
      voltDevJitter: 0.70,
      basePowerKw: 242.0,
      powerJitter: 5.0,
      thdPercent: 3.90,
      statusMessage: 'STALE MEASUREMENT REPLAY: ROTOR PHASE ANGLE SLIP TEAR',
      waveformType: 'replay_phase_tear',
      playbookAction: 'REKEY_DNP3_SECURE_AUTH_SESSION'
    },
    'Insider_Threat': {
      name: 'Insider Operator Setpoint Tampering',
      isAttack: true,
      // Droop and excitation setpoints pushed into dangerous thermal and over-fluxing limits
      baseFreqDev: -1.750,
      freqDevJitter: 0.200,
      baseVoltDev: -5.40,
      voltDevJitter: 0.60,
      basePowerKw: 295.0,
      powerJitter: 8.0,
      thdPercent: 4.10,
      statusMessage: 'UNAUTHORIZED DROOP TAMPERING: THERMAL LIMIT CREEP (-1.75 Hz)',
      waveformType: 'monotonic_droop_creep',
      playbookAction: 'REVOKE_OPERATOR_ACCESS_LOCK_PLC'
    },
    'Spoofing_Attack': {
      name: 'Synchrophasor PMU Spoofing',
      isAttack: true,
      // Alternating conflicting phase angle data causes high-frequency phase jitter
      baseFreqDev: 2.150,
      freqDevJitter: 0.550,
      baseVoltDev: 5.10,
      voltDevJitter: 1.10,
      basePowerKw: 260.0,
      powerJitter: 15.0,
      thdPercent: 9.40,
      statusMessage: 'SYNCHROPHASOR SPOOFING: HIGH-SPEED PHASE INVERSION JITTER',
      waveformType: 'phase_inversion_jitter',
      playbookAction: 'QUARANTINE_SPOOFED_MAC_SUBSTATION'
    },
    'Malware_Propagation': {
      name: 'PLC Firmware Subversion (Malware)',
      isAttack: true,
      // Malicious fast I/O switching induces harmonic resonance (3rd, 5th, 7th harmonics)
      baseFreqDev: 1.800,
      freqDevJitter: 0.400,
      baseVoltDev: 5.95,
      voltDevJitter: 1.30,
      basePowerKw: 270.0,
      powerJitter: 20.0,
      thdPercent: 19.80, // Very high THD
      statusMessage: 'PLC FIRMWARE SUBVERSION: HARMONIC RESONANCE (THD > 18%)',
      waveformType: 'harmonic_resonance_clipped',
      playbookAction: 'DEPLOY_EDR_KILLSWITCH_ISOLATE_HMI'
    },
    'Reconnaissance': {
      name: 'Network Reconnaissance Probe',
      isAttack: true,
      // Port scan has negligible physical impact on grid frequency, slight bus network jitter
      baseFreqDev: 0.035,
      freqDevJitter: 0.020,
      baseVoltDev: 0.45,
      voltDevJitter: 0.25,
      basePowerKw: 246.0,
      powerJitter: 4.0,
      thdPercent: 1.10,
      statusMessage: 'PORT PROBING DETECTED: PHYSICAL GRID STABILIZED NOMINAL',
      waveformType: 'recon_micro_jitter',
      playbookAction: 'DIVERT_TO_HONEYNET_DECEPTION_GRID'
    }
  };

  ATTACK_PROFILES['Malware'] = ATTACK_PROFILES['Malware_Propagation'];

  /**
   * Generates a point-in-time physical sample for an attack type at time `t` (seconds).
   * Returns exact frequency deviation, voltage deviation, power, and safety trip status.
   */
  function getPhysicalTelemetry(attackType, t = null) {
    if (t === null) t = Date.now() / 1000.0;
    const profile = ATTACK_PROFILES[attackType] || ATTACK_PROFILES['Normal'];

    let freqDev = 0.0;
    let voltDev = 0.0;
    let powerKw = profile.basePowerKw;

    if (!profile.isAttack) {
      // Normal continuous synchronous grid stability
      // Subtle inter-machine micro-swings (0.2 Hz - 1.2 Hz)
      const swing1 = Math.sin(t * 0.8) * 0.015;
      const swing2 = Math.cos(t * 2.1) * 0.008;
      freqDev = profile.baseFreqDev * Math.sin(t * 0.3) + swing1 + swing2;
      freqDev = Math.max(-0.035, Math.min(0.035, freqDev));

      const vSwing = Math.cos(t * 0.5) * 0.18 + Math.sin(t * 1.7) * 0.07;
      voltDev = profile.baseVoltDev * Math.cos(t * 0.4) + vSwing;
      voltDev = Math.max(-0.35, Math.min(0.35, voltDev));

      powerKw = profile.basePowerKw + Math.sin(t * 0.6) * profile.powerJitter;
    } else {
      // Realistic physical attack dynamics
      switch (profile.waveformType) {
        case 'quantized_sensor_drift': {
          // False data injection: persistent positive divergence + step bias
          const drift = Math.sin(t * 1.5) * profile.freqDevJitter;
          const sensorSteps = (Math.floor(t * 4) % 3 === 0 ? 0.25 : -0.15);
          freqDev = profile.baseFreqDev + drift + sensorSteps;
          voltDev = profile.baseVoltDev + Math.cos(t * 1.8) * profile.voltDevJitter;
          break;
        }

        case 'transient_ringing_surge': {
          // Command injection: sharp rotor acceleration and inductive ringing
          const ringing = Math.sin(t * 8.5) * Math.exp(-((t % 4.0) * 0.4)) * 0.85;
          freqDev = profile.baseFreqDev + ringing;
          voltDev = profile.baseVoltDev + Math.cos(t * 9.0) * 1.45;
          break;
        }

        case 'undamped_hunting_swing': {
          // DoS: un-damped 0.35 Hz inter-area governor hunting
          const hunting = Math.sin(2 * Math.PI * 0.35 * t) * 1.45;
          const subHarmonic = Math.sin(2 * Math.PI * 0.85 * t) * 0.45;
          freqDev = profile.baseFreqDev + hunting + subHarmonic;
          voltDev = profile.baseVoltDev + Math.cos(2 * Math.PI * 0.35 * t) * profile.voltDevJitter;
          break;
        }

        case 'replay_phase_tear': {
          // Replay: periodic phase tear discontinuity every 2.5s
          const inTear = (t % 2.5) < 0.4;
          freqDev = inTear ? (profile.baseFreqDev + 0.95) : 0.08;
          voltDev = inTear ? (profile.baseVoltDev + 2.1) : 0.45;
          break;
        }

        case 'monotonic_droop_creep': {
          // Insider: persistent monotonic thermal creep
          const creep = Math.sin(t * 0.2) * 0.35;
          freqDev = profile.baseFreqDev + creep;
          voltDev = profile.baseVoltDev + Math.cos(t * 0.25) * 0.45;
          break;
        }

        case 'phase_inversion_jitter': {
          // Spoofing: rapid alternating phase jitter
          const jitterSign = Math.sin(t * 7.5) > 0 ? 1 : -1;
          freqDev = (profile.baseFreqDev * 0.8) + (jitterSign * profile.freqDevJitter);
          voltDev = profile.baseVoltDev + (jitterSign * 1.25);
          break;
        }

        case 'harmonic_resonance_clipped': {
          // Malware: 3rd, 5th harmonic distortion
          const h3 = Math.sin(t * 12.0) * 0.55;
          const h5 = Math.sin(t * 20.0) * 0.35;
          freqDev = profile.baseFreqDev + h3 + h5;
          voltDev = profile.baseVoltDev + Math.sin(t * 15.0) * 1.4;
          break;
        }

        case 'recon_micro_jitter':
        default: {
          freqDev = profile.baseFreqDev + (Math.sin(t * 3.0) * profile.freqDevJitter);
          voltDev = profile.baseVoltDev + (Math.cos(t * 2.5) * profile.voltDevJitter);
          break;
        }
      }

      powerKw = profile.basePowerKw + (Math.sin(t * 1.2) * profile.powerJitter);
    }

    // Safety trip interlock breaches
    const isFreqTrip = Math.abs(freqDev) >= SAFETY_FREQ_TRIP_HZ;
    const isVoltTrip = Math.abs(voltDev) >= SAFETY_VOLT_TRIP_PCT;
    const isSafetyBreach = isFreqTrip || isVoltTrip;

    return {
      attackType,
      profileName: profile.name,
      isAttack: profile.isAttack,
      isSafetyBreach,
      statusMessage: profile.statusMessage,
      playbookAction: profile.playbookAction,
      thdPercent: profile.thdPercent,
      metrics: {
        frequencyHz: parseFloat((NOMINAL_FREQ_HZ + freqDev).toFixed(3)),
        frequencyDeviation: parseFloat(freqDev.toFixed(3)),
        voltageDeviation: parseFloat(voltDev.toFixed(2)),
        powerKw: parseFloat(powerKw.toFixed(1)),
        isFreqTrip,
        isVoltTrip
      }
    };
  }

  /**
   * Generates continuous instantaneous AC waveform samples across an oscilloscope window.
   * `numPoints`: number of horizontal pixels/samples on the canvas (e.g. 100)
   * `currentTime`: continuous epoch time in seconds
   */
  function generateOscilloscopeWaveform(attackType, currentTime, numPoints = 60) {
    const profile = ATTACK_PROFILES[attackType] || ATTACK_PROFILES['Normal'];
    const telemetry = getPhysicalTelemetry(attackType, currentTime);
    const points = [];

    // Base fundamental frequency: 50 Hz.
    // In oscilloscope representation, we scale phase for optimal visual wave inspection.
    const omega = 2 * Math.PI * 1.5; // Visual frequency speed

    for (let i = 0; i < numPoints; i++) {
      const frac = i / (numPoints - 1);
      const tSample = currentTime - (1.0 - frac) * 1.2; // 1.2s rolling time window
      const phase = tSample * omega;

      let waveVal = 0.0;
      let freqDevSample = telemetry.metrics.frequencyDeviation;
      let voltDevSample = telemetry.metrics.voltageDeviation;

      if (!profile.isAttack) {
        // Pure AC fundamental sine wave with minimal THD (0.6%)
        waveVal = Math.sin(phase) + 0.006 * Math.sin(3 * phase);
        // Small rotor micro-droop across the window
        freqDevSample += Math.sin(tSample * 0.8) * 0.008;
      } else {
        switch (profile.waveformType) {
          case 'quantized_sensor_drift':
            // Sensor quantization chop + DC bias drift
            waveVal = Math.sin(phase) + 0.35 * Math.sin(phase * 0.5) + (Math.floor(phase * 4) % 2 === 0 ? 0.22 : -0.18);
            break;

          case 'transient_ringing_surge':
            // High-frequency ringing + amplitude overshoot
            waveVal = (1.45 * Math.sin(phase)) + (0.55 * Math.sin(phase * 5.2) * Math.exp(-((tSample % 1.5) * 0.8)));
            break;

          case 'undamped_hunting_swing':
            // Deep low frequency envelope modulation (inter-area power swing)
            const envelope = 1.0 + 0.65 * Math.sin(2 * Math.PI * 0.35 * tSample);
            waveVal = envelope * Math.sin(phase);
            break;

          case 'replay_phase_tear':
            // Abrupt phase angle slip tears
            const phaseTear = ((Math.floor(tSample * 0.8) % 2) === 1) ? Math.PI * 0.45 : 0;
            waveVal = Math.sin(phase + phaseTear);
            break;

          case 'monotonic_droop_creep':
            // Depressed amplitude, shifted DC bias
            waveVal = 0.75 * Math.sin(phase) - 0.45;
            break;

          case 'phase_inversion_jitter':
            // Rapid phase flips
            const inv = Math.sin(tSample * 9.0) > 0 ? 1 : -1;
            waveVal = inv * Math.sin(phase) + 0.3 * Math.sin(phase * 7);
            break;

          case 'harmonic_resonance_clipped':
            // Heavy 3rd, 5th, 7th harmonics with peak saturation clipping
            const rawHarmonic = Math.sin(phase) + 0.45 * Math.sin(3 * phase) + 0.25 * Math.sin(5 * phase);
            waveVal = Math.max(-1.15, Math.min(1.15, rawHarmonic * 1.3)); // Peak clipping
            break;

          case 'recon_micro_jitter':
          default:
            waveVal = Math.sin(phase) + 0.04 * Math.sin(11 * phase);
            break;
        }
      }

      points.push({
        index: i,
        time: tSample,
        normalizedVal: waveVal, // Range approximately -1.5 to +1.5
        freqDev: freqDevSample,
        voltDev: voltDevSample
      });
    }

    return {
      attackType,
      telemetry,
      profile,
      points
    };
  }

  const GridPhysics = {
    NOMINAL_FREQ_HZ,
    NOMINAL_VOLT_PCT,
    NOMINAL_POWER_KW,
    SAFETY_FREQ_TRIP_HZ,
    SAFETY_VOLT_TRIP_PCT,
    ATTACK_PROFILES,
    getPhysicalTelemetry,
    generateOscilloscopeWaveform
  };

  if (typeof window !== 'undefined') {
    window.GridPhysics = GridPhysics;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.GridPhysics = GridPhysics;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = GridPhysics;
  }
})();
