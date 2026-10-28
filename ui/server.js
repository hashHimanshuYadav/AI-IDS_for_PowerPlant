const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const { spawn } = require('child_process');

const PORT = process.env.PORT || 5050;
const ROOT_DIR = path.resolve(__dirname, '..');
const LIVE_STREAM_FILE = path.join(ROOT_DIR, 'live_stream.json');
const DETECTION_FILE = path.join(ROOT_DIR, 'live_detection.json');
const CONFIG_FILE = path.join(ROOT_DIR, 'stream_config.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// --- Incident Response Playbooks (Specific ICS Mitigations) ---
const PLAYBOOKS = {
  'False_Data_Injection': {
    action: 'ISOLATE_SENSOR_BUS',
    title: 'Sensor Validation Failure (False Data Injection)',
    summary: 'Trip analog telemetry cross-check and isolate compromised RTU sensor feed.',
    steps: [
      'Trip analog telemetry cross-check interlock',
      'Compare Kalman state estimation residuals across redundant CT/PT sensors',
      'Isolate compromised RTU analog input bus to prevent turbine governor corruption',
      'Switch turbine control to autonomous dead-band governor regulation'
    ]
  },
  'Command_Injection': {
    action: 'REVOKE_SCADA_PRIVILEGES',
    title: 'Unauthorized SCADA Control Command',
    summary: 'Trip remote command execution interlock and force session re-authentication.',
    steps: [
      'Trip remote command execution interlock on Purdue Level 1 RTU/PLC',
      'Revoke active SCADA operator credentials and force session re-authentication',
      'Lock actuator setpoints to safe nominal fallback baseline',
      'Inspect Modbus/DNP3 function codes for unauthorized control writes'
    ]
  },
  'DoS_Attack': {
    action: 'RATE_LIMIT_EGRESS_PORT',
    title: 'Industrial Network Saturation (DoS)',
    summary: 'Engage hardware rate-limiting on Substation switch and prioritize GOOSE/DNP3.',
    steps: [
      'Engage hardware rate-limiting on Substation switch trunk port',
      'Prioritize GOOSE / DNP3 broadcast heartbeat queues over non-critical telemetry',
      'Isolate compromised network segment to Purdue Level 2 DMZ',
      'Verify protective relays maintain autonomous fail-safe operation'
    ]
  },
  'Replay_Attack': {
    action: 'RESET_CRYPTOGRAPHIC_NONCE',
    title: 'Stale Sensor Replay Sequence Detected',
    summary: 'Invalidate DNP3/IEC-61850 session nonce and enforce strict time-synchronization.',
    steps: [
      'Invalidate current DNP3/IEC-61850 session nonce and sequence counter',
      'Enforce strict time-synchronization (IEEE 1588 PTP) tolerance window',
      'Flush telemetry replay cache on SCADA front-end processor',
      'Trigger out-of-band integrity heartbeat poll to RTU'
    ]
  },
  'Insider_Threat': {
    action: 'ENGAGE_DUAL_AUTHORIZATION',
    title: 'Privilege Escalation / Rogue Operator Action',
    summary: 'Lock anomalous operator session and require two-person rule for breaker trips.',
    steps: [
      'Lock out anomalous operator workstation session',
      'Require two-person integrity (2-person rule) for critical breaker trips',
      'Export audit log snapshot to SIEM / security operations center',
      'Halt remote setpoint modifications until supervisor clearance'
    ]
  },
  'Spoofing_Attack': {
    action: 'DROP_UNVERIFIED_FRAMES',
    title: 'Device Identity / MAC Spoofing Detected',
    summary: 'Enable 802.1X port security and drop unverified industrial frames.',
    steps: [
      'Enable 802.1X port security and block unverified MAC/IP bindings',
      'Drop spoofed industrial frames at Substation managed switch',
      'Verify digital certificates and device trust levels for all IED nodes',
      'Alert network operations team to inspect physical tap locations'
    ]
  },
  'Malware': {
    action: 'QUARANTINE_PLC_FIRMWARE',
    title: 'Firmware / Memory Integrity Anomaly (Malware)',
    summary: 'Sever network connection to affected PLC and verify firmware cryptographic hash.',
    steps: [
      'Sever network connection to affected PLC/RTU controller immediately',
      'Verify firmware cryptographic hash against golden engineering baseline',
      'Transfer turbine protection loop to redundant standby safety PLC',
      'Initiate offline forensic memory dump and clean restore'
    ]
  },
  'Reconnaissance': {
    action: 'BLOCK_PROBING_HOST',
    title: 'Substation Port Scanning & Mapping Activity',
    summary: 'Add probing IP to perimeter drop rules and suppress protocol discovery.',
    steps: [
      'Add probing source IP/MAC to firewall perimeter drop rule',
      'Suppress ICMP and industrial protocol discovery responses',
      'Alert SOC of pre-attack reconnaissance phase',
      'Audit access logs across all Purdue Level 2 and Level 3 gateways'
    ]
  },
  'Normal': {
    action: 'PASSIVE_MONITORING',
    title: 'Nominal SCADA Operation',
    summary: 'Maintain passive telemetry monitoring and forward packets to historian.',
    steps: [
      'Telemetry within nominal statistical tolerance',
      'Forward packets to SCADA historian database',
      'Maintain active baseline drift profiling'
    ]
  }
};

// --- Background Worker Management ---
let generatorProcess = null;
let detectorProcess = null;

function getPythonPath() {
  const venvPython = path.join(ROOT_DIR, 'venv', 'bin', 'python');
  if (fs.existsSync(venvPython)) {
    return venvPython;
  }
  return 'python3';
}

function startBackgroundProcesses() {
  const pyCmd = getPythonPath();
  console.log(`[+] Auto-supervisor using Python: ${pyCmd}`);

  // Launch stream_generator.py if not currently writing
  let streamAgeMs = Infinity;
  if (fs.existsSync(LIVE_STREAM_FILE)) {
    try {
      streamAgeMs = Date.now() - fs.statSync(LIVE_STREAM_FILE).mtimeMs;
    } catch (e) {}
  }

  if (streamAgeMs > 4000) {
    console.log('[+] Starting live telemetry stream generator (stream_generator.py)...');
    generatorProcess = spawn(pyCmd, ['stream_generator.py'], {
      cwd: ROOT_DIR,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    generatorProcess.stdout.on('data', () => {});
    generatorProcess.stderr.on('data', (d) => {
      console.error(`[generator] ${d.toString().trim()}`);
    });
  } else {
    console.log('[*] Live stream generator already active.');
  }

  // Launch detect.py if not currently writing
  let detAgeMs = Infinity;
  if (fs.existsSync(DETECTION_FILE)) {
    try {
      detAgeMs = Date.now() - fs.statSync(DETECTION_FILE).mtimeMs;
    } catch (e) {}
  }

  if (detAgeMs > 4000) {
    console.log('[+] Starting AI detection engine (detect.py)...');
    detectorProcess = spawn(pyCmd, ['detect.py'], {
      cwd: ROOT_DIR,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    detectorProcess.stdout.on('data', () => {});
    detectorProcess.stderr.on('data', (d) => {
      console.error(`[detector] ${d.toString().trim()}`);
    });
  } else {
    console.log('[*] AI detection engine already active.');
  }

  // Gracefully terminate child processes
  const cleanup = () => {
    if (generatorProcess) {
      try { generatorProcess.kill(); } catch (e) {}
    }
    if (detectorProcess) {
      try { detectorProcess.kill(); } catch (e) {}
    }
  };
  process.on('SIGINT', () => { cleanup(); process.exit(); });
  process.on('SIGTERM', () => { cleanup(); process.exit(); });
}

// --- Global State ---
let clients = [];
let packetCounter = 0;
let lastProcessedPacketId = null;
let lastDetectionTime = 0;
let isStreaming = true;
let selectedAttack = 'Normal';
let streamIntervalMs = 5000;

// Cumulative Statistics (Derived strictly from real detection output)
const stats = {
  totalPackets: 0,
  attacksDetected: 0,
  normalForwarded: 0,
  attacksByType: {}
};

function broadcastEvent(payload) {
  const dataString = `data: ${JSON.stringify(payload)}\n\n`;
  clients.forEach(res => {
    try {
      res.write(dataString);
    } catch (e) {
      // client disconnected
    }
  });
}

// 1. Process Real Detection Output from detect.py
function checkDetectionOutput() {
  const now = Date.now();
  let detectionData = null;
  let isEngineAlive = false;

  if (fs.existsSync(DETECTION_FILE)) {
    try {
      const stat = fs.statSync(DETECTION_FILE);
      const ageMs = now - stat.mtimeMs;
      // If detection file modified within last 10 seconds, engine is active
      if (ageMs <= 10000) {
        const content = fs.readFileSync(DETECTION_FILE, 'utf8');
        if (content.trim()) {
          detectionData = JSON.parse(content);
          isEngineAlive = true;
          lastDetectionTime = now;
        }
      }
    } catch (err) {
      // transient read error
    }
  }

  // If engine hasn't written for > 8s, notify UI that detection engine is offline
  if (!isEngineAlive && (now - lastDetectionTime > 8000)) {
    broadcastEvent({
      type: 'engine_status',
      engine_offline: true,
      status_text: 'No data / detection engine offline'
    });
    return;
  }

  if (detectionData && detectionData.packet_id && detectionData.packet_id !== lastProcessedPacketId) {
    lastProcessedPacketId = detectionData.packet_id;
    packetCounter++;

    // Compute stats strictly from authentic detection output
    stats.totalPackets++;
    if (detectionData.alert) {
      stats.attacksDetected++;
      const attackType = detectionData.simulated_class || 'Unknown';
      stats.attacksByType[attackType] = (stats.attacksByType[attackType] || 0) + 1;
    } else {
      stats.normalForwarded++;
    }

    // Assemble relay payload for UI
    const attackType = detectionData.simulated_class || 'Normal';
    const isAlert = Boolean(detectionData.alert);
    const pb = PLAYBOOKS[attackType] || (isAlert ? PLAYBOOKS['Command_Injection'] : PLAYBOOKS['Normal']);

    const payload = {
      packet_id: detectionData.packet_id,
      timestamp: detectionData.timestamp || new Date().toISOString(),
      node_id: detectionData.node_id || 'N/A',
      substation: (detectionData.substation !== undefined && detectionData.substation !== null && detectionData.substation !== '') ? detectionData.substation : 'N/A',
      protocol: (detectionData.protocol !== undefined && detectionData.protocol !== null && detectionData.protocol !== '') ? detectionData.protocol : 'N/A',
      device_type: (detectionData.device_type !== undefined && detectionData.device_type !== null && detectionData.device_type !== '') ? detectionData.device_type : 'N/A',
      simulated_class: detectionData.simulated_class || 'Normal',
      source: detectionData.source || 'simulator',
      engine_offline: false,
      analysis: {
        rfScore: typeof detectionData.rf_score === 'number' ? parseFloat(detectionData.rf_score.toFixed(4)) : null,
        rfVote: typeof detectionData.rf_vote === 'number' ? detectionData.rf_vote : 0,
        isoScore: typeof detectionData.iso_score === 'number' ? parseFloat(detectionData.iso_score.toFixed(4)) : null,
        isoAnomaly: typeof detectionData.iso_anomaly === 'number' ? detectionData.iso_anomaly : 0,
        isoVote: typeof detectionData.iso_vote === 'number' ? detectionData.iso_vote : 0,
        lstmScore: typeof detectionData.lstm_score === 'number' ? parseFloat(detectionData.lstm_score.toFixed(4)) : null,
        lstmVote: typeof detectionData.lstm_vote === 'number' ? detectionData.lstm_vote : null,
        lstm_status: detectionData.lstm_status || (detectionData.lstm_score === null ? 'unavailable' : 'active'),
        consensusVotes: typeof detectionData.consensus_votes === 'number' ? detectionData.consensus_votes : 0,
        votingMode: detectionData.voting_mode || '2-of-2',
        consensusReason: detectionData.consensus_reason || (isAlert ? 'Multi-Model Consensus Alert' : 'Nominal Grid Telemetry'),
        isConsensusThreat: isAlert,
        playbookAction: isAlert ? pb.action : 'PASSIVE_MONITORING',
        playbookTitle: isAlert ? pb.title : 'Nominal SCADA Operation',
        playbookSummary: isAlert ? pb.summary : 'Telemetry within nominal statistical tolerance',
        playbookSteps: isAlert ? pb.steps : PLAYBOOKS['Normal'].steps,
        gridStatusMessage: isAlert ? 'TRIP BREAKER ENGAGED' : 'NOMINAL GRID',
        thdPercent: 'N/A', // Real datasets have no THD; honest report
        metrics: {
          voltageDeviation: detectionData.physical ? parseFloat(detectionData.physical.voltage_deviation_percent || 0) : 0.0,
          frequencyDeviation: detectionData.physical ? parseFloat(detectionData.physical.frequency_deviation_hz || 0) : 0.0,
          powerKw: detectionData.physical ? parseFloat(detectionData.physical.power_consumption_kw || 0) : 0.0,
          thdPercent: 'N/A',
          scadaCommands: detectionData.physical ? parseInt(detectionData.physical.scada_command_count || 0, 10) : 0,
          networkLatency: detectionData.physical ? parseFloat(detectionData.physical.network_latency_ms || 0) : 0.0,
          packetRate: detectionData.physical ? parseInt(detectionData.physical.packet_rate_per_sec || 0, 10) : 0,
          trafficEntropy: detectionData.physical ? parseFloat(detectionData.physical.traffic_entropy || 0) : 0.0,
          sessionRisk: 0.0
        }
      }
    };

    broadcastEvent(payload);
  }
}

// Poll detection output every 100ms
setInterval(checkDetectionOutput, 100);

// Helper to write stream_config.json
function updateStreamConfigFile() {
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify({
      interval: streamIntervalMs / 1000.0,
      is_streaming: isStreaming,
      selected_attack: selectedAttack
    }, null, 2));
  } catch (err) {
    // ignore
  }
}

// 2. HTTP Server & API Endpoints
const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml'
};

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // SSE Stream Endpoint
  if (pathname === '/api/stream') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    });
    res.write('retry: 1000\n\n');
    clients.push(res);

    res.write(`data: ${JSON.stringify({ type: 'connected', stats, streamIntervalMs, isStreaming, selectedAttack })}\n\n`);

    req.on('close', () => {
      clients = clients.filter(c => c !== res);
    });
    return;
  }

  // Attack Injection Endpoint (writes to stream_config.json)
  if (pathname === '/api/inject' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        selectedAttack = data.attack_type || 'Normal';
        updateStreamConfigFile();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, injected: selectedAttack, selectedAttack }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // Stream Configuration Endpoint (Rate & Pause/Resume)
  if (pathname === '/api/config') {
    if (req.method === 'GET') {
      try {
        if (fs.existsSync(CONFIG_FILE)) {
          const cfg = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
          if (typeof cfg.interval === 'number' && cfg.interval > 0) {
            streamIntervalMs = Math.round(cfg.interval * 1000);
          }
          if (typeof cfg.is_streaming === 'boolean') {
            isStreaming = cfg.is_streaming;
          }
          if (cfg.selected_attack) {
            selectedAttack = cfg.selected_attack;
          }
        }
      } catch (e) {}
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ isStreaming, streamIntervalMs, interval: streamIntervalMs / 1000.0, selectedAttack }));
      return;
    }
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const data = JSON.parse(body || '{}');
          if (typeof data.isStreaming === 'boolean') {
            isStreaming = data.isStreaming;
          }
          if (typeof data.intervalMs === 'number' && data.intervalMs >= 100) {
            streamIntervalMs = data.intervalMs;
          }
          updateStreamConfigFile();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ isStreaming, streamIntervalMs, interval: streamIntervalMs / 1000.0 }));
        } catch (err) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: err.message }));
        }
      });
      return;
    }
  }

  // Stats Endpoint
  if (pathname === '/api/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(stats));
    return;
  }

  // Static File Serving
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'text/plain';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 Not Found');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(`Server Error: ${err.code}`);
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content, 'utf-8');
    }
  });
});

// Load initial config if exists
try {
  if (fs.existsSync(CONFIG_FILE)) {
    const cfg = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    if (typeof cfg.interval === 'number' && cfg.interval > 0) {
      streamIntervalMs = Math.round(cfg.interval * 1000);
    }
    if (cfg.selected_attack) {
      selectedAttack = cfg.selected_attack;
    }
    if (typeof cfg.is_streaming === 'boolean') {
      isStreaming = cfg.is_streaming;
    }
  }
} catch (e) {
  // ignore
}

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n[!] Port ${PORT} is currently in use.`);
    process.exit(1);
  } else {
    throw err;
  }
});

server.listen(PORT, () => {
  console.log('================================================================');
  console.log('  🏭 AI-DRIVEN POWER PLANT ICS INTRUSION DETECTION SYSTEM (UI)  ');
  console.log('================================================================');
  console.log(`[+] Dashboard UI:            http://localhost:${PORT}`);
  console.log(`[+] Real-Time SSE Relay:     http://localhost:${PORT}/api/stream`);
  console.log(`[+] Mode:                    Relaying detect.py outputs only`);
  console.log('================================================================\n');

  // Automatically ensure live telemetry generator and AI engine are active
  startBackgroundProcesses();
});
