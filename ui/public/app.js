/**
 * Power Plant ICS AI-IDS Operations Center - Real-Time Dashboard Client
 * Supports System / Manual Light and Dark Mode with Frosted Glassmorphism
 */

// --- Global UI State ---
let eventSource = null;
let isAudioEnabled = false;
let isStreamPaused = false;
let currentThemeSetting = 'system'; // 'system', 'dark', 'light'
let currentActiveAttack = 'Normal';
let isCurrentGridAttacked = false;
let lastPacketClass = 'Normal';

// Auto-detect API base so localhost, 127.0.0.1, file://, and custom ports all resolve smoothly
const API_BASE = (window.location.protocol === 'file:' || (window.location.port !== '5050' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')))
  ? 'http://localhost:5050'
  : '';

// Telemetry History for Oscilloscope / Canvas
const MAX_HISTORY = 45;
const freqHistory = new Array(MAX_HISTORY).fill(0);
const voltHistory = new Array(MAX_HISTORY).fill(0);

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
const activeModeBadge = document.getElementById('active-mode-badge');

// Terminal & Stats
const terminalLog = document.getElementById('terminal-log');
const clearLogBtn = document.getElementById('clear-log-btn');
const sumTotal = document.getElementById('sum-total');
const sumThreats = document.getElementById('sum-threats');
const sumNormal = document.getElementById('sum-normal');

// Canvas Setup
const canvas = document.getElementById('telemetry-canvas');
const ctx = canvas.getContext('2d');

// --- Clock Runner ---
function updateClock() {
  const now = new Date();
  const timeStr = now.toISOString().substring(11, 19) + ' UTC';
  if (clockDisplay) clockDisplay.textContent = timeStr;
}
setInterval(updateClock, 500);

// --- Theme Management (System, Light, Dark) ---
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
  if (typeof drawWaveforms === 'function') {
    try { drawWaveforms(); } catch (e) {}
  }
}

// Listen to System OS Theme Changes
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
  if (currentThemeSetting === 'system') {
    applyTheme('system');
  }
});

if (themeSelect) {
  themeSelect.addEventListener('change', (e) => {
    applyTheme(e.target.value);
  });
}

// Initial Theme Restore
const savedTheme = localStorage.getItem('ai_ids_theme') || 'system';
applyTheme(savedTheme);

// --- Left Dock Navigation & Blink-Mode Highlighting ---
let activeBlinkTimer = null;

function highlightFunctionCard(targetEl) {
  if (!targetEl) return;

  // Clear any existing blink highlights from previous clicks
  document.querySelectorAll('.blink-highlight-card').forEach(el => {
    el.classList.remove('blink-highlight-card');
  });

  if (activeBlinkTimer) {
    clearTimeout(activeBlinkTimer);
    activeBlinkTimer = null;
  }

  // Force DOM reflow so rapid successive clicks immediately restart the blink animation
  void targetEl.offsetWidth;

  // Add the high-visibility glowing blink class
  targetEl.classList.add('blink-highlight-card');

  // Smoothly scroll the highlighted function card into focus without horizontal offset
  targetEl.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });

  // Play subtle feedback chime matching the single border glow if audio enabled
  try {
    if (typeof playTone === 'function' && isAudioEnabled) {
      playTone(1150, 0.12, 0.08);
    }
  } catch (err) {}

  // Cleanly remove highlight after the single border glow completes (0.95s)
  activeBlinkTimer = setTimeout(() => {
    targetEl.classList.remove('blink-highlight-card');
    activeBlinkTimer = null;
  }, 950);
}

document.querySelectorAll('.dock-btn[data-section]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.dock-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    
    const target = btn.getAttribute('data-section');
    let targetCard = null;

    if (target === 'overview') {
      targetCard = document.getElementById('threat-banner');
    } else if (target === 'oscilloscope') {
      targetCard = document.querySelector('.main-stats-card');
    } else if (target === 'ai') {
      targetCard = document.querySelector('.ai-summary-card');
    } else if (target === 'injector') {
      targetCard = document.querySelector('.injector-card');
    } else if (target === 'logs') {
      targetCard = document.querySelector('.terminal-card');
    }

    if (targetCard) {
      highlightFunctionCard(targetCard);
    } else {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  });
});

// Dock Brand (Lightning bolt icon) click handler -> highlights Threat Alert & Overview
const dockBrand = document.querySelector('.dock-brand');
if (dockBrand) {
  dockBrand.addEventListener('click', () => {
    document.querySelectorAll('.dock-btn').forEach(b => b.classList.remove('active'));
    const overviewBtn = document.querySelector('.dock-btn[data-section="overview"]');
    if (overviewBtn) overviewBtn.classList.add('active');

    const threatBanner = document.getElementById('threat-banner');
    if (threatBanner) highlightFunctionCard(threatBanner);
  });
}

// Dock Status Dot (Live heartbeat indicator) click handler
const dockStatusDot = document.getElementById('dock-status-dot');
if (dockStatusDot) {
  dockStatusDot.addEventListener('click', () => {
    const threatBanner = document.getElementById('threat-banner');
    if (threatBanner) highlightFunctionCard(threatBanner);
  });
}

// --- Web Audio Tone Generator (Clean, User-Unlocked) ---
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
document.addEventListener('click', () => { getAudioContext(); }, { once: true });

function playTone(freq = 800, duration = 0.15, volume = 0.12) {
  if (!isAudioEnabled) return;
  try {
    const audioContext = getAudioContext();
    if (!audioContext) return;
    
    const osc = audioContext.createOscillator();
    const gain = audioContext.createGain();
    
    osc.type = 'sine';
    osc.frequency.setValueAtTime(freq, audioContext.currentTime);
    
    gain.gain.setValueAtTime(volume, audioContext.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, audioContext.currentTime + duration);

    osc.connect(gain);
    gain.connect(audioContext.destination);

    osc.start();
    osc.stop(audioContext.currentTime + duration);
  } catch (err) {
    // Audio context may require user interaction
  }
}

// --- Audio Siren Toggle ---
if (audioToggleBtn) {
  audioToggleBtn.addEventListener('click', () => {
    isAudioEnabled = !isAudioEnabled;
    if (isAudioEnabled) {
      audioToggleBtn.style.borderColor = 'var(--status-safe)';
      if (audioStateText) {
        audioStateText.textContent = 'On';
        audioStateText.style.color = 'var(--status-safe)';
      }
      playTone(750, 0.15); // Audible confirmation chime
      addLogLine('[AUDIO] Alarm sound enabled. Test chime played.', 'system-line');
    } else {
      audioToggleBtn.style.borderColor = '';
      if (audioStateText) {
        audioStateText.textContent = 'Off';
        audioStateText.style.color = '';
      }
      addLogLine('[AUDIO] Alarm sound disabled.', 'system-line');
    }
  });
}

// --- Stream Pause / Resume Control ---
if (toggleStreamBtn) {
  toggleStreamBtn.addEventListener('click', async () => {
    isStreamPaused = !isStreamPaused;
    const currentRateLabel = rateSlider ? `${parseFloat(rateSlider.value).toFixed(1)}s` : '5.0s';

    if (isStreamPaused) {
      if (streamBtnText) streamBtnText.textContent = 'Resume';
      toggleStreamBtn.style.borderColor = 'var(--status-warn)';
      if (streamStatus) {
        streamStatus.innerHTML = '<span class="status-dot" style="background:var(--status-warn)"></span> Paused';
      }
      addLogLine('[OPERATOR] Telemetry stream paused by operator.', 'system-line');
    } else {
      if (streamBtnText) streamBtnText.textContent = 'Pause';
      toggleStreamBtn.style.borderColor = '';
      if (streamStatus) {
        streamStatus.innerHTML = `<span class="status-dot"></span> Live Stream (${currentRateLabel})`;
      }
      addLogLine('[OPERATOR] Telemetry stream resumed by operator.', 'system-line');
    }

    try {
      await fetch(API_BASE + '/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ isStreaming: !isStreamPaused })
      });
    } catch (err) {
      console.error('Failed to update streaming state:', err);
    }
  });
}

// --- Stream Rate Manual Slider (0.5s - 10.0s, default 5.0s) ---
let sliderDebounce = null;
if (rateSlider) {
  rateSlider.addEventListener('input', (e) => {
    const val = parseFloat(e.target.value).toFixed(1);
    if (sliderValText) sliderValText.textContent = `${val}s`;
    if (!isStreamPaused && streamStatus) {
      streamStatus.innerHTML = `<span class="status-dot"></span> Live Stream (${val}s)`;
    }
    clearTimeout(sliderDebounce);
    sliderDebounce = setTimeout(async () => {
      const seconds = parseFloat(e.target.value);
      const intervalMs = Math.round(seconds * 1000);
      try {
        await fetch(API_BASE + '/api/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ intervalMs })
        });
        addLogLine(`[CONFIG] Telemetry streaming rate updated to ${seconds.toFixed(1)}s (${intervalMs}ms)`, 'system-line');
      } catch (err) {
        console.error('Failed to change speed:', err);
      }
    }, 200);
  });

  rateSlider.addEventListener('change', async (e) => {
    clearTimeout(sliderDebounce);
    const seconds = parseFloat(e.target.value);
    const intervalMs = Math.round(seconds * 1000);
    try {
      await fetch(API_BASE + '/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ intervalMs })
      });
      addLogLine(`[CONFIG] Telemetry streaming rate locked to ${seconds.toFixed(1)}s (${intervalMs}ms)`, 'system-line');
    } catch (err) {
      console.error('Failed to change speed:', err);
    }
  });
}

if (clearLogBtn) {
  clearLogBtn.addEventListener('click', () => {
    if (terminalLog) terminalLog.innerHTML = '';
  });
}

// --- Search Filter on Logs ---
if (telemetrySearch) {
  telemetrySearch.addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase().trim();
    const lines = terminalLog.querySelectorAll('.log-line');
    lines.forEach(line => {
      if (!q || line.textContent.toLowerCase().includes(q)) {
        line.style.display = '';
      } else {
        line.style.display = 'none';
      }
    });
  });
}

// --- Attack Injection Buttons & Mode Tracking ---
function setActiveInjectionMode(attackType) {
  currentActiveAttack = attackType;
  lastPacketClass = attackType;
  isCurrentGridAttacked = (attackType !== 'Normal');

  document.querySelectorAll('.glass-action-btn').forEach(b => {
    if (b.getAttribute('data-attack') === attackType) {
      b.classList.add('active-injection');
    } else {
      b.classList.remove('active-injection');
    }
  });

  if (activeModeBadge) {
    if (attackType === 'Normal') {
      activeModeBadge.textContent = 'Normal Baseline (Continuous)';
      activeModeBadge.style.color = 'var(--status-safe)';
    } else {
      activeModeBadge.textContent = `Injected: ${attackType.replace(/_/g, ' ')}`;
      activeModeBadge.style.color = 'var(--status-alert)';
    }
  }

  if (typeof drawWaveforms === 'function') {
    try { drawWaveforms(); } catch (e) {}
  }
}

document.querySelectorAll('.glass-action-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    const clickedType = btn.getAttribute('data-attack') || 'Normal';
    
    // Toggle logic: If clicking the currently active attack, deselect it and revert to Normal baseline!
    let nextAttackType = clickedType;
    if (clickedType !== 'Normal' && currentActiveAttack === clickedType) {
      nextAttackType = 'Normal';
      addLogLine(`[INJECTOR] Deselected ${clickedType}. Reverting to continuous Normal baseline traffic...`, 'normal-line');
      playTone(550, 0.08, 0.08);
    } else if (clickedType === 'Normal') {
      nextAttackType = 'Normal';
      addLogLine(`[INJECTOR] Normal Baseline active. Generating continuous benign telemetry...`, 'normal-line');
      playTone(520, 0.08, 0.08);
    } else {
      addLogLine(`[INJECTOR] Injected ${clickedType}. Emitting at current stream rate...`, 'alert-line');
      playTone(720, 0.12, 0.12);
    }

    setActiveInjectionMode(nextAttackType);

    try {
      const res = await fetch(API_BASE + '/api/inject', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_type: nextAttackType })
      });
      const data = await res.json();
      if (data && data.success) {
        btn.style.transform = 'scale(0.96)';
        setTimeout(() => { btn.style.transform = ''; }, 120);
      }
    } catch (err) {
      console.error('Injection error:', err);
    }
  });
});

// --- Log Terminal Output ---
function addLogLine(content, cssClass = 'normal-line', isHtml = false) {
  const line = document.createElement('div');
  line.className = `log-line ${cssClass}`;
  if (isHtml) {
    line.innerHTML = content;
  } else {
    line.textContent = content;
  }
  
  // Filter check if search active
  if (telemetrySearch && telemetrySearch.value.trim()) {
    const q = telemetrySearch.value.toLowerCase().trim();
    if (!line.textContent.toLowerCase().includes(q)) {
      line.style.display = 'none';
    }
  }

  terminalLog.appendChild(line);

  while (terminalLog.children.length > 100) {
    terminalLog.removeChild(terminalLog.firstChild);
  }
  terminalLog.scrollTop = terminalLog.scrollHeight;
}

// --- Live High-Fidelity Cyber-Physical Oscilloscope Rendering (60 FPS) ---
let animFrameId = null;

function resizeCanvas() {
  if (!canvas || !ctx) return;
  const rect = canvas.getBoundingClientRect();
  const parent = canvas.parentElement;
  const dpr = window.devicePixelRatio || 1;
  const w = rect.width || (parent ? parent.clientWidth : 0) || canvas.clientWidth || 850;
  const h = rect.height || (parent ? parent.clientHeight : 0) || canvas.clientHeight || 190;
  if (w > 0 && h > 0) {
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(dpr, dpr);
  }
}
window.addEventListener('resize', resizeCanvas);
resizeCanvas();

function drawWaveforms() {
  if (!canvas || !ctx) return;
  const w = canvas.getBoundingClientRect().width || (canvas.width / (window.devicePixelRatio || 1)) || 850;
  const h = canvas.getBoundingClientRect().height || (canvas.height / (window.devicePixelRatio || 1)) || 190;
  if (!w || !h) return;
  const midY = h / 2;
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  const nowSec = Date.now() / 1000.0;

  ctx.clearRect(0, 0, w, h);

  // 1. Draw Technical Graticule / Grid Lines
  ctx.strokeStyle = isLight ? 'rgba(0, 0, 0, 0.05)' : 'rgba(255, 255, 255, 0.04)';
  ctx.lineWidth = 1;
  const numGridLines = 6;
  for (let i = 0; i <= numGridLines; i++) {
    const y = (h / numGridLines) * i;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }

  // Vertical time division graticule lines
  const numVDivs = 8;
  for (let j = 0; j <= numVDivs; j++) {
    const x = (w / numVDivs) * j;
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, h);
    ctx.stroke();
  }

  // Center Zero Baseline in soft green dash
  ctx.strokeStyle = isLight ? 'rgba(16, 185, 129, 0.25)' : 'rgba(16, 185, 129, 0.2)';
  ctx.setLineDash([4, 4]);
  ctx.beginPath();
  ctx.moveTo(0, midY);
  ctx.lineTo(w, midY);
  ctx.stroke();
  ctx.setLineDash([]);

  // Query authentic physical dynamics from GridPhysics engine with automatic fallback
  const attackMode = (currentActiveAttack && currentActiveAttack !== 'Normal')
    ? currentActiveAttack
    : (isCurrentGridAttacked ? lastPacketClass : 'Normal');
  let physData = null;
  if (window.GridPhysics && typeof window.GridPhysics.generateOscilloscopeWaveform === 'function') {
    physData = window.GridPhysics.generateOscilloscopeWaveform(attackMode, nowSec, 100);
  } else {
    // Built-in physics fallback
    const isAtt = attackMode !== 'Normal';
    const omega = 2 * Math.PI * 1.5;
    const pts = [];
    for (let i = 0; i < 100; i++) {
      const frac = i / 99;
      const tSample = nowSec - (1.0 - frac) * 1.2;
      const phase = tSample * omega;
      let waveVal = isAtt ? (Math.sin(phase) + 0.35 * Math.sin(3 * phase)) : (Math.sin(phase) + 0.006 * Math.sin(3 * phase));
      pts.push({
        index: i,
        time: tSample,
        normalizedVal: waveVal,
        freqDev: isAtt ? 1.85 : (Math.sin(tSample * 0.8) * 0.02),
        voltDev: isAtt ? 4.5 : (Math.cos(tSample * 0.5) * 0.2)
      });
    }
    physData = {
      attackType: attackMode,
      profile: {
        isAttack: isAtt,
        statusMessage: isAtt ? `SAFETY INTERLOCK BREACH: ${attackMode.replace(/_/g, ' ')}` : 'GRID SYNCHRONOUS LOCKED: 50.00 Hz [NOMINAL]',
        thdPercent: isAtt ? 6.5 : 0.65
      },
      points: pts
    };
  }
  const isAttack = physData ? physData.profile.isAttack : (attackMode !== 'Normal');

  // Draw Safety Trip Envelope Thresholds (±1.00 Hz)
  const tripYUpper = midY - (1.0 / 2.5) * (midY * 0.82);
  const tripYLower = midY + (1.0 / 2.5) * (midY * 0.82);

  ctx.save();
  ctx.setLineDash([3, 5]);
  ctx.lineWidth = 1;
  if (isAttack) {
    ctx.strokeStyle = 'rgba(239, 68, 68, 0.45)';
    ctx.fillStyle = '#ef4444';
  } else {
    ctx.strokeStyle = 'rgba(16, 185, 129, 0.22)';
    ctx.fillStyle = '#10b981';
  }
  ctx.beginPath();
  ctx.moveTo(0, tripYUpper); ctx.lineTo(w, tripYUpper);
  ctx.moveTo(0, tripYLower); ctx.lineTo(w, tripYLower);
  ctx.stroke();
  ctx.setLineDash([]);

  // Technical Graticule Markers
  ctx.save();
  ctx.font = '10px monospace';
  if (isAttack) {
    ctx.fillStyle = '#ef4444';
  } else {
    ctx.fillStyle = '#10b981';
  }
  ctx.fillText(isAttack ? 'SAFETY TRIP (+1.00 Hz)' : 'NOMINAL BOUNDARY (+1.00 Hz)', 12, tripYUpper - 6);
  ctx.fillText(isAttack ? 'SAFETY TRIP (-1.00 Hz)' : 'NOMINAL BOUNDARY (-1.00 Hz)', 12, tripYLower + 14);
  ctx.restore();

  // Update Real-Time Physical Grid Status in Dedicated HUD Header Bar
  if (oscStatusIndicator && oscStatusText) {
    if (isAttack && physData) {
      oscStatusIndicator.className = 'hud-status-dot threat';
      oscStatusText.textContent = `▲ ${physData.profile.statusMessage} • THD: ${physData.profile.thdPercent.toFixed(1)}%`;
      oscStatusText.style.color = '#ef4444';
    } else {
      oscStatusIndicator.className = 'hud-status-dot nominal';
      oscStatusText.textContent = '● GRID STATUS: SYNCHRONOUS LOCKED (50.00 Hz) • THD: 0.65% • TOLERANCE: ±0.03 Hz';
      oscStatusText.style.color = '#10b981';
    }
  }

  // Draw Continuous Real-Time Waveforms
  if (physData && physData.points && physData.points.length > 1) {
    const pts = physData.points;
    const step = w / (pts.length - 1);

    // Channel 1: Primary AC Frequency & Generator Swing Waveform
    ctx.save();
    ctx.strokeStyle = isAttack ? '#ef4444' : '#10b981';
    ctx.lineWidth = isAttack ? 2.6 : 2.0;
    ctx.shadowColor = isAttack ? 'rgba(239, 68, 68, 0.75)' : 'rgba(16, 185, 129, 0.4)';
    ctx.shadowBlur = isAttack ? 12 : 6;
    ctx.beginPath();

    for (let i = 0; i < pts.length; i++) {
      const x = i * step;
      const waveNorm = pts[i].normalizedVal; // sinusoidal & harmonic variations
      const freqDev = pts[i].freqDev; // +/- Hz deviation
      // Map rotor slip and frequency disturbance onto oscilloscope scale
      const combinedOffset = isAttack ? (freqDev * 0.52 + waveNorm * 0.42) : (freqDev * 2.2 + waveNorm * 0.38);
      const clampedOffset = Math.max(-2.3, Math.min(2.3, combinedOffset));
      const y = midY - (clampedOffset / 2.5) * (midY * 0.85);

      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.stroke();
    ctx.restore();

    // Channel 2: Voltage Deviation Envelope (Secondary trace)
    ctx.save();
    ctx.strokeStyle = isAttack ? 'rgba(239, 68, 68, 0.55)' : (isLight ? 'rgba(16, 185, 129, 0.5)' : 'rgba(52, 211, 153, 0.45)');
    ctx.lineWidth = 1.4;
    ctx.beginPath();

    for (let i = 0; i < pts.length; i++) {
      const x = i * step;
      const vDev = pts[i].voltDev;
      const waveNorm = pts[i].normalizedVal;
      const vOffset = isAttack ? (vDev * 0.12 + Math.cos(pts[i].time * 3) * 0.2) : (vDev * 0.2 + waveNorm * 0.15);
      const y = midY - (vOffset / 2.5) * (midY * 0.7);

      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.stroke();
    ctx.restore();
  }
}

function startOscilloscopeLoop() {
  if (animFrameId) cancelAnimationFrame(animFrameId);
  function loop() {
    drawWaveforms();
    animFrameId = requestAnimationFrame(loop);
  }
  animFrameId = requestAnimationFrame(loop);
}

// --- Process Telemetry Update ---
function handleTelemetryPacket(packet) {
  if (isStreamPaused) return;

  const p = packet;
  const analysis = p.analysis;
  const metrics = analysis.metrics;
  const isThreat = Boolean(analysis.isConsensusThreat);
  const isAttack = isThreat; // Strictly backend verdict, no artificial override based on simulated_class

  lastPacketClass = p.simulated_class || 'Normal';
  // Set grid attack state so oscilloscope renders authentic cyber-physical disturbance
  isCurrentGridAttacked = isAttack || Math.abs(metrics.frequencyDeviation) > 0.8;

  // 1. Shift and update waveform histories
  freqHistory.shift();
  freqHistory.push(metrics.frequencyDeviation);
  voltHistory.shift();
  voltHistory.push(metrics.voltageDeviation);
  drawWaveforms();

  // 2. Update Readout Stats (Green for Nominal, Alert Red for Breaches)
  const freqPrefix = metrics.frequencyDeviation >= 0 ? '+' : '';
  statFreqVal.textContent = `${freqPrefix}${metrics.frequencyDeviation.toFixed(3)} Hz`;
  statFreqVal.style.color = Math.abs(metrics.frequencyDeviation) > 1.0 ? 'var(--status-alert)' : 'var(--status-safe)';

  const voltPrefix = metrics.voltageDeviation >= 0 ? '+' : '';
  statVoltVal.textContent = `${voltPrefix}${metrics.voltageDeviation.toFixed(2)} %`;
  statVoltVal.style.color = Math.abs(metrics.voltageDeviation) > 4.0 ? 'var(--status-alert)' : 'var(--status-safe)';

  statPowerVal.textContent = `${metrics.powerKw.toFixed(1)} kW`;

  // 3. Update Mini Metrics
  mLatency.textContent = `${metrics.networkLatency.toFixed(1)} ms`;
  mLatencyBar.style.width = `${Math.min(100, (metrics.networkLatency / 300) * 100)}%`;

  mPacketRate.textContent = `${metrics.packetRate} pkts/s`;
  mRateBar.style.width = `${Math.min(100, (metrics.packetRate / 1000) * 100)}%`;

  mScadaCmds.textContent = `${metrics.scadaCommands} cmds`;
  mScadaBar.style.width = `${Math.min(100, (metrics.scadaCommands / 1200) * 100)}%`;

  mEntropy.textContent = metrics.trafficEntropy.toFixed(2);
  mEntropyBar.style.width = `${Math.min(100, (metrics.trafficEntropy / 8) * 100)}%`;

  // 4. Update AI Consensus Models with Explicit Green vs Red Theming

  // Model 1: Random Forest
  const rfPct = typeof analysis.rfScore === 'number' ? (analysis.rfScore * 100).toFixed(1) : 'N/A';
  rfScoreVal.textContent = `${rfPct}%`;
  const isRfAttack = analysis.rfVote !== undefined ? (analysis.rfVote === 1) : (analysis.rfScore >= 0.73);
  if (isRfAttack) {
    cardRf.className = 'model-row threat-hit';
    rfStatus.textContent = 'Attack Match';
    rfStatus.className = 'status-badge threat';
    rfScoreVal.style.color = '#ef4444';
  } else {
    cardRf.className = 'model-row normal-hit';
    rfStatus.textContent = 'Normal';
    rfStatus.className = 'status-badge nominal';
    rfScoreVal.style.color = '#10b981';
  }

  // Model 2: Isolation Forest
  isoScoreVal.textContent = analysis.isoAnomaly === 1 ? 'Outlier' : 'Normal';
  if (analysis.isoAnomaly === 1) {
    cardIso.className = 'model-row threat-hit';
    isoStatus.textContent = 'Anomaly Outlier';
    isoStatus.className = 'status-badge threat';
    isoScoreVal.style.color = '#ef4444';
  } else {
    cardIso.className = 'model-row normal-hit';
    isoStatus.textContent = 'Nominal';
    isoStatus.className = 'status-badge nominal';
    isoScoreVal.style.color = '#10b981';
  }

  // Model 3: Deep LSTM
  if (analysis.lstm_status === 'unavailable' || analysis.lstmScore === null || typeof analysis.lstmScore !== 'number') {
    cardLstm.className = 'model-row';
    lstmScoreVal.textContent = 'N/A';
    lstmStatus.textContent = 'Unavailable';
    lstmStatus.className = 'status-badge nominal';
    lstmScoreVal.style.color = 'var(--text-muted, #94a3b8)';
  } else {
    const lstmPct = (analysis.lstmScore * 100).toFixed(1);
    lstmScoreVal.textContent = `${lstmPct}%`;
    const isLstmVote = analysis.lstmVote !== undefined ? (analysis.lstmVote === 1) : (analysis.lstmScore >= 0.55);
    if (isLstmVote) {
      cardLstm.className = 'model-row threat-hit';
      lstmStatus.textContent = 'Critical Threat';
      lstmStatus.className = 'status-badge threat';
      lstmScoreVal.style.color = '#ef4444';
    } else {
      cardLstm.className = 'model-row normal-hit';
      lstmStatus.textContent = 'Low Risk';
      lstmStatus.className = 'status-badge nominal';
      lstmScoreVal.style.color = '#10b981';
    }
  }

  // Model 4: Consensus Arbiter & Playbook
  const modeTag = analysis.votingMode ? ` [${analysis.votingMode}]` : '';
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

  // 5. Update Threat Alert Strip
  if (isThreat) {
    threatBanner.className = 'alert-strip alert-state';
    bannerHeading.textContent = `CRITICAL CYBER-PHYSICAL INTRUSION: ${p.simulated_class.replace(/_/g, ' ').toUpperCase()}`;
    bannerSub.textContent = `Industrial Safety Interlock Engaged • Origin: ${p.node_id} (${p.substation}) • Protocol: ${p.protocol}`;
    bannerActionTag.textContent = `PLAYBOOK: ${analysis.playbookAction}`;
    playTone(900, 0.25, 0.15);
  } else {
    threatBanner.className = 'alert-strip normal-state';
    bannerHeading.textContent = 'STATUS: NORMAL OPERATION - SCADA INTERLOCK SECURE';
    bannerSub.textContent = `Turbine frequency and voltage stabilized nominal • Origin: ${p.node_id}`;
    bannerActionTag.textContent = 'PLAYBOOK: PASSIVE_MONITORING / FORWARD';
    playTone(520, 0.06, 0.03); // Subtle nominal telemetry heartbeat
  }

  // 6. Update Active Packet Inspector Ribbon
  activePidBadge.textContent = `PKT #${String(p.packet_id).padStart(4, '0')}`;
  inspNode.textContent = p.node_id;
  inspSubstation.textContent = p.substation;
  inspProto.textContent = p.protocol;
  inspType.textContent = p.simulated_class;
  inspType.style.color = isThreat ? 'var(--status-alert)' : 'var(--status-safe)';

  // 7. Add Log Line with Vivid Green for Normal and Vivid Red for Attack
  const logClass = isThreat ? 'alert-line' : 'normal-line';
  const badgeText = isThreat ? 'CRITICAL INTRUSION DETECTED' : 'FORWARDED - SECURE';
  const badgeHtml = `<span class="log-badge">${badgeText}</span>`;
  const classDisplay = p.simulated_class.replace(/_/g, ' ');
  const isoDisplay = analysis.isoAnomaly === 1 ? 'Outlier Anomaly' : 'Nominal';
  const lstmLog = (analysis.lstm_status === 'unavailable' || analysis.lstmScore === null) ? 'LSTM: N/A' : `LSTM: ${(analysis.lstmScore * 100).toFixed(1)}%`;
  const logMsg = `[${p.timestamp}] [PKT #${String(p.packet_id).padStart(4, '0')}] ${badgeHtml} <strong>${classDisplay}</strong> • Node: ${p.node_id} • RF: ${rfPct}% • Iso: ${isoDisplay} • ${lstmLog} • Action: ${analysis.playbookAction}`;
  addLogLine(logMsg, logClass, true);
}

// --- Fetch Cumulative Stats ---
async function syncStats() {
  try {
    const res = await fetch(API_BASE + '/api/stats');
    const data = await res.json();
    if (sumTotal) sumTotal.textContent = data.totalPackets;
    if (sumThreats) sumThreats.textContent = data.attacksDetected;
    if (sumNormal) sumNormal.textContent = data.normalForwarded;
  } catch (err) {
    // ignore
  }
}
setInterval(syncStats, 1500);

// --- Establish Real-Time SSE Stream ---
function connectEventStream() {
  if (eventSource) {
    eventSource.close();
  }

  eventSource = new EventSource(API_BASE + '/api/stream');

  eventSource.onopen = () => {
    console.log('[SSE] Connected to real-time industrial telemetry stream.');
    if (streamStatus && !isStreamPaused) {
      const currentRateLabel = rateSlider ? `${parseFloat(rateSlider.value).toFixed(1)}s` : '5.0s';
      streamStatus.innerHTML = `<span class="status-dot"></span> Live Stream (${currentRateLabel})`;
    }
  };

  eventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'connected') {
        addLogLine('[SERVER] Connected to telemetry broadcast stream.', 'system-line');
        if (data.selectedAttack) {
          setActiveInjectionMode(data.selectedAttack);
        }
        if (data.streamIntervalMs && rateSlider) {
          const s = (data.streamIntervalMs / 1000).toFixed(1);
          rateSlider.value = s;
          if (sliderValText) sliderValText.textContent = `${s}s`;
        }
      } else if (data.packet_id) {
        handleTelemetryPacket(data);
      }
    } catch (err) {
      console.error('Failed to parse telemetry event:', err);
    }
  };

  eventSource.onerror = (err) => {
    if (streamStatus) {
      streamStatus.innerHTML = '<span class="status-dot" style="background:#ef4444"></span> Reconnecting';
    }
  };
}

// Start Stream on Load (resilient to readyState)
function initDashboard() {
  resizeCanvas();
  connectEventStream();
  startOscilloscopeLoop();
  addLogLine('[SYSTEM] Cyber-Physical Glassmorphism Operations Center online.', 'system-line');
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initDashboard);
} else {
  initDashboard();
}
