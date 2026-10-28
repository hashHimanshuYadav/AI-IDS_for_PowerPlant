/**
 * Power Plant ICS AI-IDS Operations Center - Real-Time Dashboard Client
 * Grounded strictly in authentic backend detection engine output
 */

// --- Global UI State ---
let eventSource = null;
let isAudioEnabled = false;
let isStreamPaused = false;
let currentThemeSetting = 'system';
let currentActiveAttack = 'Normal';

// Auto-detect API base
const API_BASE = (window.location.protocol === 'file:' || (window.location.port !== '5050' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')))
  ? 'http://localhost:5050'
  : '';

// Real Packet History for Oscilloscope (Stores up to 50 real packets)
const MAX_PACKETS = 50;
const packetHistory = [];

// Protocol, Substation, DeviceType string mappings (fallback for numeric values)
const PROTOCOL_MAP = {
  0: 'DNP3', 1: 'MQTT', 2: 'Modbus_TCP',
  '0': 'DNP3', '1': 'MQTT', '2': 'Modbus_TCP'
};
const SUBSTATION_MAP = {
  0: 'Distribution', 1: 'Generation', 2: 'Renewable', 3: 'Transmission',
  '0': 'Distribution', '1': 'Generation', '2': 'Renewable', '3': 'Transmission'
};
const DEVICE_TYPE_MAP = {
  0: 'IED', 1: 'PLC', 2: 'RTU', 3: 'SCADA_Server',
  '0': 'IED', '1': 'PLC', '2': 'RTU', '3': 'SCADA_Server'
};

function formatProtocol(val) {
  if (val === null || val === undefined || val === '' || val === 'N/A') return 'N/A';
  if (PROTOCOL_MAP[val] !== undefined) return PROTOCOL_MAP[val];
  if (typeof val === 'string' && isNaN(Number(val))) return val;
  return 'N/A';
}

function formatSubstation(val) {
  if (val === null || val === undefined || val === '' || val === 'N/A') return 'N/A';
  if (SUBSTATION_MAP[val] !== undefined) return SUBSTATION_MAP[val];
  if (typeof val === 'string' && isNaN(Number(val))) return val;
  return 'N/A';
}

function formatDeviceType(val) {
  if (val === null || val === undefined || val === '' || val === 'N/A') return 'N/A';
  if (DEVICE_TYPE_MAP[val] !== undefined) return DEVICE_TYPE_MAP[val];
  if (typeof val === 'string' && isNaN(Number(val))) return val;
  return 'N/A';
}

function formatOriginNode(val) {
  if (val === null || val === undefined || val === '' || val === 'N/A') return 'N/A';
  return String(val);
}

// Current stream interval tracking (strictly from config, default 0.5s or from server)
let currentStreamInterval = 1.0;

function updateStreamStatusDisplay(intervalSec) {
  if (typeof intervalSec === 'number' && !isNaN(intervalSec)) {
    currentStreamInterval = intervalSec;
  }
  if (!streamStatus) return;
  if (isStreamPaused) {
    streamStatus.innerHTML = '<span class="status-dot paused"></span> Paused (SIMULATED TELEMETRY)';
  } else {
    const s = currentStreamInterval.toFixed(1);
    streamStatus.innerHTML = `<span class="status-dot"></span> Live Stream (${s}s) [SIMULATED]`;
  }
}

// DOM Elements
const clockDisplay = document.getElementById('clock-display');
const streamStatus = document.getElementById('stream-status');
const toggleStreamBtn = document.getElementById('toggle-stream-btn');
const streamBtnText = document.getElementById('stream-btn-text');
const audioToggleBtn = document.getElementById('audio-toggle-btn');
const audioStateText = document.getElementById('audio-state-text');
const rateSlider = document.getElementById('rate-slider');
const sliderValText = document.getElementById('slider-val-text');
const themeSelect = document.getElementById('theme-select');
const themeIcon = document.getElementById('theme-icon');
const telemetrySearch = document.getElementById('telemetry-search');

// Banner & Threat Elements
const threatBanner = document.getElementById('threat-banner');
const bannerHeading = document.getElementById('banner-heading');
const bannerSub = document.getElementById('banner-sub');
const bannerActionTag = document.getElementById('banner-action-tag');

// AI Cards
const cardRf = document.getElementById('card-rf');
const rfScoreVal = document.getElementById('rf-score-val');
const rfStatus = document.getElementById('rf-status');

const cardIso = document.getElementById('card-iso');
const isoScoreVal = document.getElementById('iso-score-val');
const isoStatus = document.getElementById('iso-status');

const cardLstm = document.getElementById('card-lstm');
const lstmScoreVal = document.getElementById('lstm-score-val');
const lstmStatus = document.getElementById('lstm-status');

const cardConsensus = document.getElementById('card-consensus');
const consensusVerdict = document.getElementById('consensus-verdict');
const playbookCode = document.getElementById('playbook-code');

// Waveform Overlay Elements
const statFreqVal = document.getElementById('stat-freq-val');
const statVoltVal = document.getElementById('stat-volt-val');
const statPowerVal = document.getElementById('stat-power-val');
const oscStatusIndicator = document.getElementById('osc-status-indicator');
const oscStatusText = document.getElementById('osc-status-text');

// Mini Metric Tiles
const mLatency = document.getElementById('m-latency');
const mLatencyBar = document.getElementById('m-latency-bar');
const mPacketRate = document.getElementById('m-packet-rate');
const mRateBar = document.getElementById('m-rate-bar');
const mScadaCmds = document.getElementById('m-scada-cmds');
const mScadaBar = document.getElementById('m-scada-bar');
const mEntropy = document.getElementById('m-entropy');
const mEntropyBar = document.getElementById('m-entropy-bar');

// Inspector Elements
const activePidBadge = document.getElementById('active-pid-badge');
const inspNode = document.getElementById('insp-node');
const inspSubstation = document.getElementById('insp-substation');
const inspProto = document.getElementById('insp-proto');
const inspType = document.getElementById('insp-type');

// Terminal & Stats
const terminalLog = document.getElementById('terminal-log');
const clearLogBtn = document.getElementById('clear-log-btn');
const sumTotal = document.getElementById('sum-total');
const sumThreats = document.getElementById('sum-threats');
const sumNormal = document.getElementById('sum-normal');

// Canvas Setup
const canvas = document.getElementById('telemetry-canvas');
const ctx = canvas.getContext('2d');

// --- Label as Simulated Telemetry (Requirement 2h) ---
const opNameEl = document.querySelector('.operator-name');
if (opNameEl) {
  opNameEl.textContent = 'SIMULATED TELEMETRY';
}

// --- Clock Runner ---
function updateClock() {
  const now = new Date();
  const timeStr = now.toISOString().substring(11, 19) + ' UTC';
  if (clockDisplay) clockDisplay.textContent = timeStr;
}
setInterval(updateClock, 500);

// --- Theme Management ---
const SUN_ICON = `<circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>`;
const MOON_ICON = `<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>`;
const MONITOR_ICON = `<rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line>`;

function applyTheme(theme) {
  currentThemeSetting = theme;
  try {
    localStorage.setItem('ai_ids_theme', theme);
  } catch (e) {}

  let activeMode = theme;
  if (theme === 'system') {
    const isSystemDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    activeMode = isSystemDark ? 'dark' : 'light';
    if (themeIcon) themeIcon.innerHTML = MONITOR_ICON;
  } else if (theme === 'light') {
    if (themeIcon) themeIcon.innerHTML = SUN_ICON;
  } else {
    if (themeIcon) themeIcon.innerHTML = MOON_ICON;
  }

  document.documentElement.setAttribute('data-theme', activeMode);
  if (themeSelect) themeSelect.value = theme;
  drawRealWaveforms();
}

if (window.matchMedia) {
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (currentThemeSetting === 'system') applyTheme('system');
  });
}

if (themeSelect) {
  themeSelect.addEventListener('change', (e) => applyTheme(e.target.value));
}

const savedTheme = localStorage.getItem('ai_ids_theme') || 'system';
applyTheme(savedTheme);

// --- Navigation Dock Buttons ---
document.querySelectorAll('.dock-btn[data-section]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.dock-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const target = btn.getAttribute('data-section');
    let targetCard = null;
    if (target === 'overview') targetCard = document.getElementById('threat-banner');
    else if (target === 'oscilloscope') targetCard = document.querySelector('.main-stats-card');
    else if (target === 'ai') targetCard = document.querySelector('.ai-summary-card');
    else if (target === 'injector') targetCard = document.querySelector('.injector-card');
    else if (target === 'logs') targetCard = document.querySelector('.terminal-card');

    if (targetCard) {
      targetCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  });
});

// --- Web Audio Tone Generator ---
let sharedAudioCtx = null;
function getAudioContext() {
  if (!sharedAudioCtx) {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (AudioCtx) sharedAudioCtx = new AudioCtx();
  }
  if (sharedAudioCtx && sharedAudioCtx.state === 'suspended') {
    sharedAudioCtx.resume().catch(() => {});
  }
  return sharedAudioCtx;
}

function playTone(freq, duration = 0.2, gainVol = 0.1) {
  if (!isAudioEnabled) return;
  try {
    const ctxA = getAudioContext();
    if (!ctxA) return;
    const osc = ctxA.createOscillator();
    const gain = ctxA.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(freq, ctxA.currentTime);
    gain.gain.setValueAtTime(gainVol, ctxA.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, ctxA.currentTime + duration);
    osc.connect(gain);
    gain.connect(ctxA.destination);
    osc.start();
    osc.stop(ctxA.currentTime + duration);
  } catch (err) {}
}

if (audioToggleBtn) {
  audioToggleBtn.addEventListener('click', () => {
    isAudioEnabled = !isAudioEnabled;
    if (audioStateText) audioStateText.textContent = isAudioEnabled ? 'On' : 'Off';
    audioToggleBtn.classList.toggle('active', isAudioEnabled);
    if (isAudioEnabled) {
      getAudioContext();
      playTone(660, 0.15, 0.1);
    }
  });
}

// --- Terminal Log Helper ---
function addLogLine(htmlContent, className = 'normal-line') {
  if (!terminalLog) return;
  const p = document.createElement('p');
  p.className = `log-line ${className}`;
  p.innerHTML = htmlContent;
  terminalLog.appendChild(p);

  while (terminalLog.children.length > 100) {
    terminalLog.removeChild(terminalLog.firstChild);
  }
  terminalLog.scrollTop = terminalLog.scrollHeight;
}

if (clearLogBtn) {
  clearLogBtn.addEventListener('click', () => {
    if (terminalLog) terminalLog.innerHTML = '';
    addLogLine('[SYSTEM] Security log cleared by operator.', 'system-line');
  });
}

// --- Dynamic Attack Injection Buttons (Requirement 2i) ---
function setActiveInjectionMode(attackName) {
  currentActiveAttack = attackName;
  document.querySelectorAll('.glass-action-btn').forEach(btn => {
    const match = btn.getAttribute('data-attack') === attackName;
    btn.classList.toggle('active-injection', match);
  });
}

document.querySelectorAll('.glass-action-btn[data-attack]').forEach(btn => {
  btn.addEventListener('click', async () => {
    const attackType = btn.getAttribute('data-attack');
    setActiveInjectionMode(attackType);
    try {
      const res = await fetch(API_BASE + '/api/inject', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_type: attackType })
      });
      const data = await res.json();
      addLogLine(`[INJECTOR] Operator switched mode: <strong>${attackType.replace(/_/g, ' ')}</strong>`, 'system-line');
    } catch (err) {
      addLogLine(`[INJECTOR ERROR] Failed to inject ${attackType}: ${err.message}`, 'alert-line');
    }
  });
});

// --- Stream Rate Slider & Pause/Resume (Requirement 2i) ---
if (rateSlider) {
  rateSlider.addEventListener('input', (e) => {
    const val = parseFloat(e.target.value);
    currentStreamInterval = val;
    if (sliderValText) sliderValText.textContent = `${val.toFixed(1)}s`;
    updateStreamStatusDisplay(val);
  });

  rateSlider.addEventListener('change', async (e) => {
    const val = parseFloat(e.target.value);
    currentStreamInterval = val;
    updateStreamStatusDisplay(val);
    const intervalMs = Math.round(val * 1000);
    try {
      await fetch(API_BASE + '/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ intervalMs })
      });
      addLogLine(`[STREAM] Rate adjusted: ${val.toFixed(1)}s per packet`, 'system-line');
    } catch (err) {}
  });
}

if (toggleStreamBtn) {
  toggleStreamBtn.addEventListener('click', async () => {
    isStreamPaused = !isStreamPaused;
    try {
      await fetch(API_BASE + '/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ isStreaming: !isStreamPaused })
      });
      if (streamBtnText) streamBtnText.textContent = isStreamPaused ? 'Resume' : 'Pause';
      updateStreamStatusDisplay();
      addLogLine(`[STREAM] Telemetry stream ${isStreamPaused ? 'PAUSED' : 'RESUMED'} by operator`, 'system-line');
    } catch (err) {}
  });
}

// --- Real-Data Oscilloscope (Requirement 2e) ---
// Oscilloscope is driven strictly from the last N packets' real values.
function resizeCanvas() {
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * (window.devicePixelRatio || 1);
  canvas.height = rect.height * (window.devicePixelRatio || 1);
  drawRealWaveforms();
}

window.addEventListener('resize', resizeCanvas);

function drawRealWaveforms() {
  if (!canvas || !ctx) return;
  const w = canvas.width;
  const h = canvas.height;
  const midY = h / 2;
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';

  ctx.clearRect(0, 0, w, h);

  // Background Grid & Division Lines
  ctx.strokeStyle = isLight ? 'rgba(0, 0, 0, 0.06)' : 'rgba(255, 255, 255, 0.04)';
  ctx.lineWidth = 1;
  const numHDivs = 6;
  for (let i = 0; i <= numHDivs; i++) {
    const y = (h / numHDivs) * i;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }
  const numVDivs = 8;
  for (let j = 0; j <= numVDivs; j++) {
    const x = (w / numVDivs) * j;
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, h);
    ctx.stroke();
  }

  // Center Zero Line
  ctx.strokeStyle = isLight ? 'rgba(16, 185, 129, 0.25)' : 'rgba(16, 185, 129, 0.2)';
  ctx.setLineDash([4, 4]);
  ctx.beginPath();
  ctx.moveTo(0, midY);
  ctx.lineTo(w, midY);
  ctx.stroke();
  ctx.setLineDash([]);

  // Safety Boundary Lines (±1.00 Hz)
  const maxFreqScale = 2.5; // ±2.5 Hz scale
  const tripYUpper = midY - (1.0 / maxFreqScale) * (midY * 0.85);
  const tripYLower = midY + (1.0 / maxFreqScale) * (midY * 0.85);

  ctx.strokeStyle = 'rgba(239, 68, 68, 0.35)';
  ctx.setLineDash([3, 5]);
  ctx.beginPath();
  ctx.moveTo(0, tripYUpper); ctx.lineTo(w, tripYUpper);
  ctx.moveTo(0, tripYLower); ctx.lineTo(w, tripYLower);
  ctx.stroke();
  ctx.setLineDash([]);

  ctx.save();
  ctx.font = '10px monospace';
  ctx.fillStyle = isLight ? '#dc2626' : '#ef4444';
  ctx.fillText('TRIP BOUNDARY (+1.00 Hz)', 12, tripYUpper - 6);
  ctx.fillText('TRIP BOUNDARY (-1.00 Hz)', 12, tripYLower + 14);
  ctx.restore();

  // If fewer than 2 real packets exist, show empty trace (Requirement 2e)
  if (packetHistory.length < 2) {
    if (oscStatusText) {
      oscStatusText.textContent = '● AWAITING TELEMETRY (EMPTY TRACE) • THD: N/A';
      oscStatusText.style.color = 'var(--text-muted, #94a3b8)';
    }
    return;
  }

  const lastPacket = packetHistory[packetHistory.length - 1];
  if (oscStatusText) {
    oscStatusText.textContent = `● REAL TELEMETRY SAMPLES (N=${packetHistory.length}) • FREQ: ${lastPacket.freqDev >= 0 ? '+' : ''}${lastPacket.freqDev.toFixed(3)} Hz • VOLT: ${lastPacket.voltDev >= 0 ? '+' : ''}${lastPacket.voltDev.toFixed(2)}% • THD: N/A`;
    oscStatusText.style.color = Math.abs(lastPacket.freqDev) > 1.0 ? '#ef4444' : '#10b981';
  }

  const stepX = w / (MAX_PACKETS - 1);
  const startOffset = MAX_PACKETS - packetHistory.length;

  // Trace 1: Real Frequency Deviation (Green / Red if tripped)
  ctx.save();
  ctx.strokeStyle = Math.abs(lastPacket.freqDev) > 1.0 ? '#ef4444' : '#10b981';
  ctx.lineWidth = 2.0;
  ctx.beginPath();

  for (let i = 0; i < packetHistory.length; i++) {
    const x = (startOffset + i) * stepX;
    const fDev = packetHistory[i].freqDev;
    const clampedF = Math.max(-maxFreqScale, Math.min(maxFreqScale, fDev));
    const y = midY - (clampedF / maxFreqScale) * (midY * 0.85);

    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.stroke();
  ctx.restore();

  // Trace 2: Real Voltage Deviation (Cyan / Amber)
  const maxVoltScale = 6.0; // ±6% scale
  ctx.save();
  ctx.strokeStyle = isLight ? 'rgba(37, 99, 235, 0.65)' : 'rgba(96, 165, 250, 0.65)';
  ctx.lineWidth = 1.4;
  ctx.beginPath();

  for (let i = 0; i < packetHistory.length; i++) {
    const x = (startOffset + i) * stepX;
    const vDev = packetHistory[i].voltDev;
    const clampedV = Math.max(-maxVoltScale, Math.min(maxVoltScale, vDev));
    const y = midY - (clampedV / maxVoltScale) * (midY * 0.7);

    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.stroke();
  ctx.restore();
}

// --- Process Telemetry Update (Requirement 2) ---
function handleTelemetryPacket(packet) {
  if (isStreamPaused) return;

  const p = packet;
  const analysis = p.analysis || {};
  const metrics = analysis.metrics || {};
  const isThreat = Boolean(analysis.isConsensusThreat);

  // 1. Append real physical fields to history
  const freqDev = typeof metrics.frequencyDeviation === 'number' ? metrics.frequencyDeviation : 0.0;
  const voltDev = typeof metrics.voltageDeviation === 'number' ? metrics.voltageDeviation : 0.0;
  packetHistory.push({ freqDev, voltDev });
  if (packetHistory.length > MAX_PACKETS) {
    packetHistory.shift();
  }
  drawRealWaveforms();

  // 2. Readout Stats from Real Packet Fields (Requirement 2d)
  const freqPrefix = freqDev >= 0 ? '+' : '';
  statFreqVal.textContent = `${freqPrefix}${freqDev.toFixed(3)} Hz`;
  statFreqVal.style.color = Math.abs(freqDev) > 1.0 ? 'var(--status-alert)' : 'var(--status-safe)';

  const voltPrefix = voltDev >= 0 ? '+' : '';
  statVoltVal.textContent = `${voltPrefix}${voltDev.toFixed(2)} %`;
  statVoltVal.style.color = Math.abs(voltDev) > 4.0 ? 'var(--status-alert)' : 'var(--status-safe)';

  const powerKw = typeof metrics.powerKw === 'number' ? metrics.powerKw : 0.0;
  statPowerVal.textContent = `${powerKw.toFixed(1)} kW`;

  // 3. Mini Metrics from Real Packet Fields (Requirement 2f)
  const netLatency = typeof metrics.networkLatency === 'number' ? metrics.networkLatency : 0.0;
  mLatency.textContent = `${netLatency.toFixed(1)} ms`;
  mLatencyBar.style.width = `${Math.min(100, (netLatency / 300) * 100)}%`;

  const pktRate = typeof metrics.packetRate === 'number' ? metrics.packetRate : 0;
  mPacketRate.textContent = `${pktRate} pkts/s`;
  mRateBar.style.width = `${Math.min(100, (pktRate / 1000) * 100)}%`;

  const scadaCmds = typeof metrics.scadaCommands === 'number' ? metrics.scadaCommands : 0;
  mScadaCmds.textContent = `${scadaCmds} cmds`;
  mScadaBar.style.width = `${Math.min(100, (scadaCmds / 1200) * 100)}%`;

  const entropy = typeof metrics.trafficEntropy === 'number' ? metrics.trafficEntropy : 0.0;
  mEntropy.textContent = entropy.toFixed(2);
  mEntropyBar.style.width = `${Math.min(100, (entropy / 8) * 100)}%`;

  // 4. Update AI Consensus Models
  // Model 1: Random Forest
  const rfPct = typeof analysis.rfScore === 'number' ? (analysis.rfScore * 100).toFixed(1) : 'N/A';
  rfScoreVal.textContent = typeof analysis.rfScore === 'number' ? `${rfPct}%` : 'N/A';
  rfScoreVal.title = 'attack probability';
  rfScoreVal.setAttribute('aria-label', 'attack probability');

  if (analysis.rfVote === 1) {
    cardRf.className = 'model-row threat-hit';
    rfStatus.textContent = 'Attack';
    rfStatus.className = 'status-badge threat';
    rfScoreVal.style.color = '#ef4444';
  } else {
    cardRf.className = 'model-row normal-hit';
    rfStatus.textContent = 'Normal';
    rfStatus.className = 'status-badge nominal';
    rfScoreVal.style.color = '#10b981';
  }

  // Model 2: Isolation Forest
  if (analysis.isoVote === 1) {
    cardIso.className = 'model-row threat-hit';
    isoStatus.textContent = 'Outlier';
    isoStatus.className = 'status-badge threat';
    isoScoreVal.textContent = 'Outlier';
    isoScoreVal.style.color = '#ef4444';
  } else {
    cardIso.className = 'model-row normal-hit';
    isoStatus.textContent = 'Nominal';
    isoStatus.className = 'status-badge nominal';
    isoScoreVal.textContent = 'Nominal';
    isoScoreVal.style.color = '#10b981';
  }
  isoScoreVal.title = 'anomaly outlier flag';

  // Model 3: Deep LSTM
  if (analysis.lstm_status === 'unavailable' || analysis.lstmScore === null || typeof analysis.lstmScore !== 'number') {
    cardLstm.className = 'model-row';
    lstmScoreVal.textContent = 'N/A';
    lstmScoreVal.title = 'attack probability';
    lstmStatus.textContent = 'Unavailable';
    lstmStatus.className = 'status-badge';
    lstmScoreVal.style.color = 'var(--text-muted, #94a3b8)';
  } else {
    const lstmPct = (analysis.lstmScore * 100).toFixed(1);
    lstmScoreVal.textContent = `${lstmPct}%`;
    lstmScoreVal.title = 'attack probability';
    if (analysis.lstmVote === 1) {
      cardLstm.className = 'model-row threat-hit';
      lstmStatus.textContent = 'Attack';
      lstmStatus.className = 'status-badge threat';
      lstmScoreVal.style.color = '#ef4444';
    } else {
      cardLstm.className = 'model-row normal-hit';
      lstmStatus.textContent = 'Normal';
      lstmStatus.className = 'status-badge nominal';
      lstmScoreVal.style.color = '#10b981';
    }
  }

  // Model 4: Consensus Arbiter & Playbook
  const activeVotingMode = analysis.votingMode || '2-of-2';
  const modeTag = ` [${activeVotingMode}]`;
  if (isThreat) {
    cardConsensus.className = 'consensus-row threat-hit';
    consensusVerdict.textContent = `BREAKER TRIP ALERT${modeTag}`;
    consensusVerdict.className = 'consensus-val highlight-danger mono';
    consensusVerdict.style.color = '#ef4444';
    playbookCode.textContent = `Action: ${analysis.playbookAction}`;
    playbookCode.style.color = '#ef4444';
  } else {
    cardConsensus.className = 'consensus-row normal-hit';
    consensusVerdict.textContent = `Secure (Nominal Grid)${modeTag}`;
    consensusVerdict.className = 'consensus-val secure mono';
    consensusVerdict.style.color = '#10b981';
    playbookCode.textContent = 'Action: Passive Monitoring & Forward Telemetry';
    playbookCode.style.color = '#10b981';
  }

  // Authentic Origin, Protocol, Substation strings
  const nodeText = formatOriginNode(p.node_id);
  const protoText = formatProtocol(p.protocol);
  const subText = formatSubstation(p.substation);
  const devText = formatDeviceType(p.device_type);

  // 5. Threat Alert Strip (Requirement 2g: UI never decides "attack" itself)
  if (isThreat) {
    threatBanner.className = 'alert-strip alert-state';
    bannerHeading.textContent = `CRITICAL CYBER-PHYSICAL INTRUSION: ${p.simulated_class.replace(/_/g, ' ').toUpperCase()}`;
    bannerSub.textContent = `Industrial Safety Interlock Engaged • Origin: ${nodeText} (${subText}) • Protocol: ${protoText}`;
    bannerActionTag.textContent = `PLAYBOOK: ${analysis.playbookAction}`;
    playTone(900, 0.25, 0.15);
  } else {
    // If attack was injected and missed by the engine, honestly display Normal in the banner
    threatBanner.className = 'alert-strip normal-state';
    bannerHeading.textContent = 'STATUS: NORMAL OPERATION - SCADA INTERLOCK SECURE';
    bannerSub.textContent = `Turbine frequency and voltage stabilized nominal • Origin: ${nodeText}`;
    bannerActionTag.textContent = 'PLAYBOOK: PASSIVE_MONITORING / FORWARD';
    playTone(520, 0.06, 0.03);
  }

  // 6. Active Packet Inspector Ribbon
  activePidBadge.textContent = `PKT #${String(p.packet_id).padStart(4, '0')}`;
  inspNode.textContent = nodeText;
  inspSubstation.textContent = subText;
  inspProto.textContent = protoText;
  inspType.textContent = (p.simulated_class && typeof p.simulated_class === 'string') ? p.simulated_class : 'N/A';
  inspType.style.color = isThreat ? 'var(--status-alert)' : 'var(--status-safe)';

  // 7. Security Audit Log (Requirement 2g: show injected ground truth)
  const isGroundTruthAttack = p.simulated_class && p.simulated_class.toLowerCase() !== 'normal';
  const injectedLabel = isGroundTruthAttack ? `${p.simulated_class.replace(/_/g, ' ')} (injected)` : 'Normal (baseline)';
  const logClass = isThreat ? 'alert-line' : 'normal-line';
  const badgeText = isThreat ? 'CRITICAL INTRUSION DETECTED' : 'FORWARDED - SECURE';
  const badgeHtml = `<span class="log-badge">${badgeText}</span>`;
  const isoDisplay = analysis.isoVote === 1 ? 'Outlier' : 'Nominal';
  const lstmLog = (analysis.lstm_status === 'unavailable' || analysis.lstmScore === null) ? 'LSTM: Unavailable' : `LSTM: ${(analysis.lstmScore * 100).toFixed(1)}% (${analysis.lstmVote === 1 ? 'Attack' : 'Normal'})`;
  const logMsg = `[${p.timestamp}] [PKT #${String(p.packet_id).padStart(4, '0')}] ${badgeHtml} <strong>${injectedLabel}</strong> • Node: ${nodeText} • RF: ${rfPct}% (${analysis.rfVote === 1 ? 'Attack' : 'Normal'}) • Iso: ${isoDisplay} • ${lstmLog} • Action: ${analysis.playbookAction}`;
  addLogLine(logMsg, logClass);
}

// --- Fetch Cumulative Stats from server.js ---
async function syncStats() {
  try {
    const res = await fetch(API_BASE + '/api/stats');
    const data = await res.json();
    if (sumTotal) sumTotal.textContent = data.totalPackets;
    if (sumThreats) sumThreats.textContent = data.attacksDetected;
    if (sumNormal) sumNormal.textContent = data.normalForwarded;
  } catch (err) {}
}
setInterval(syncStats, 1500);

// --- Establish Real-Time SSE Stream ---
function connectEventStream() {
  if (eventSource) {
    eventSource.close();
  }

  eventSource = new EventSource(API_BASE + '/api/stream');

  eventSource.onopen = () => {
    updateStreamStatusDisplay();
  };

  eventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'connected') {
        addLogLine('[SERVER] Connected to telemetry broadcast stream.', 'system-line');
        if (data.selectedAttack) {
          setActiveInjectionMode(data.selectedAttack);
        }
        if (data.streamIntervalMs) {
          const s = data.streamIntervalMs / 1000.0;
          currentStreamInterval = s;
          if (rateSlider) rateSlider.value = s.toFixed(1);
          if (sliderValText) sliderValText.textContent = `${s.toFixed(1)}s`;
          updateStreamStatusDisplay(s);
        }
      } else if (data.type === 'engine_status' && data.engine_offline) {
        // Requirement 2b: Detection engine offline status
        consensusVerdict.textContent = 'No data / detection engine offline';
        consensusVerdict.className = 'consensus-val mono';
        consensusVerdict.style.color = 'var(--text-muted, #94a3b8)';
        playbookCode.textContent = 'Engine Offline';
        cardRf.className = 'model-row';
        rfStatus.textContent = 'Offline';
        cardIso.className = 'model-row';
        isoStatus.textContent = 'Offline';
        cardLstm.className = 'model-row';
        lstmStatus.textContent = 'Offline';
      } else if (data.packet_id) {
        handleTelemetryPacket(data);
      }
    } catch (err) {}
  };

  eventSource.onerror = () => {
    if (streamStatus) {
      streamStatus.innerHTML = '<span class="status-dot" style="background:#ef4444"></span> Reconnecting';
    }
  };
}

// Fetch Initial Stream Config from Server (Requirement: real current interval)
async function fetchInitialConfig() {
  try {
    const res = await fetch(API_BASE + '/api/config');
    if (res.ok) {
      const cfg = await res.json();
      const sec = typeof cfg.interval === 'number' ? cfg.interval : (typeof cfg.streamIntervalMs === 'number' ? cfg.streamIntervalMs / 1000.0 : null);
      if (sec !== null) {
        currentStreamInterval = sec;
        if (rateSlider) rateSlider.value = sec.toFixed(1);
        if (sliderValText) sliderValText.textContent = `${sec.toFixed(1)}s`;
        updateStreamStatusDisplay(sec);
      }
      if (typeof cfg.isStreaming === 'boolean') {
        isStreamPaused = !cfg.isStreaming;
        if (streamBtnText) streamBtnText.textContent = isStreamPaused ? 'Resume' : 'Pause';
        updateStreamStatusDisplay();
      }
      if (cfg.selectedAttack) {
        setActiveInjectionMode(cfg.selectedAttack);
      }
    }
  } catch (err) {}
}

// Start Stream on Load
function initDashboard() {
  resizeCanvas();
  fetchInitialConfig();
  connectEventStream();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initDashboard);
} else {
  initDashboard();
}
