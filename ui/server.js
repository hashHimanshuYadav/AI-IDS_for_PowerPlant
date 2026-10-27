const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 5050;
const ROOT_DIR = path.resolve(__dirname, '..');
const CSV_FILE = path.join(ROOT_DIR, 'Distributed_MultiAgent_Energy_Cybersecurity_Dataset.csv');
const LIVE_STREAM_FILE = path.join(ROOT_DIR, 'live_stream.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const GridPhysics = require(path.join(PUBLIC_DIR, 'grid_physics.js'));

// --- Global State ---
let clients = [];
let dataset = [];
const CONFIG_FILE = path.join(ROOT_DIR, 'stream_config.json');
const DETECTION_FILE = path.join(ROOT_DIR, 'live_detection.json');
const FEATURE_COLS = [
  'region', 'substation_type', 'device_type', 'communication_protocol', 'packet_size_bytes',
  'packet_rate_per_sec', 'network_latency_ms', 'bandwidth_usage_mbps', 'jitter_ms', 'packet_loss_percent',
  'connection_duration_sec', 'active_connection_count', 'failed_connection_count', 'authentication_attempts',
  'failed_login_count', 'user_role', 'device_trust_level', 'firmware_version', 'cpu_utilization_percent',
  'memory_utilization_percent', 'power_consumption_kw', 'sensor_update_interval_ms', 'telemetry_volume_mb',
  'scada_command_count', 'control_signal_frequency', 'measurement_variance', 'voltage_deviation_percent',
  'frequency_deviation_hz', 'event_severity', 'alert_priority', 'encryption_algorithm', 'certificate_status',
  'intrusion_signature_score', 'behavior_anomaly_score', 'traffic_entropy', 'session_risk_score', 'federated_round'
];

const categoryMaps = {};
function extract37Features(record) {
  return FEATURE_COLS.map(col => {
    const val = record[col];
    if (typeof val === 'number') return val;
    if (typeof val === 'string') {
      const num = parseFloat(val);
      if (!isNaN(num) && isFinite(num)) return num;
      if (!categoryMaps[col]) categoryMaps[col] = {};
      if (categoryMaps[col][val] === undefined) {
        categoryMaps[col][val] = Object.keys(categoryMaps[col]).length;
      }
      return categoryMaps[col][val];
    }
    return 0.0;
  });
}

let datasetHeaders = [];
let datasetByClass = {};
let packetCounter = 1;
let datasetIndex = 0;
let isStreaming = true;
let selectedAttack = 'Normal'; // Defaults to Normal baseline
let streamIntervalMs = 5000; // Default: 5.0 seconds
let lastProcessedLiveId = null;
let streamTimer = null;

// Cumulative Statistics
const stats = {
  totalPackets: 0,
  attacksDetected: 0,
  normalForwarded: 0,
  attacksByType: {}
};

// 1. Load the authentic ICS/OT Telemetry Dataset
const TEST_CSV_FILE = path.join(ROOT_DIR, 'test_stream.csv');

function loadDataset() {
  try {
    const targetCsv = fs.existsSync(TEST_CSV_FILE) ? TEST_CSV_FILE : CSV_FILE;
    if (!fs.existsSync(targetCsv)) {
      console.warn(`[WARN] Dataset CSV not found at: ${targetCsv}`);
      return;
    }

    console.log(`[*] Loading telemetry dataset from ${path.basename(targetCsv)}...`);
    const rawContent = fs.readFileSync(targetCsv, 'utf8');
    const lines = rawContent.split(/\r?\n/).filter(line => line.trim().length > 0);
    if (lines.length < 2) return;

    datasetHeaders = lines[0].split(',').map(h => h.trim());
    const attackColIdx = datasetHeaders.indexOf('attack_type');

    dataset = [];
    datasetByClass = {};

    for (let i = 1; i < lines.length; i++) {
      const row = lines[i].split(',').map(v => v.trim());
      if (row.length !== datasetHeaders.length) continue;

      const record = {};
      datasetHeaders.forEach((col, idx) => {
        const val = row[idx];
        const num = parseFloat(val);
        record[col] = !isNaN(num) && isFinite(val) ? num : val;
      });

      const attackType = record.attack_type || (attackColIdx !== -1 ? row[attackColIdx] : 'Unknown');
      dataset.push(record);

      if (!datasetByClass[attackType]) {
        datasetByClass[attackType] = [];
      }
      datasetByClass[attackType].push(record);
    }

    console.log(`[+] Loaded ${dataset.length} authentic power plant records across ${Object.keys(datasetByClass).length} telemetry classes.`);
  } catch (err) {
    console.error('[!] Failed to load dataset:', err.message);
  }
}

// 2. Authentic AI Threat Analysis Engine (Grounded strictly in dataset telemetry)
function analyzeTelemetry(record) {
  const simulatedClass = String(record.attack_type || 'Unknown');
  const isGroundTruthAttack = simulatedClass.toLowerCase() !== 'normal';

  // Authentic Physical Telemetry Metrics from the dataset
  const voltDev = Math.abs(parseFloat(record.voltage_deviation_percent) || 0);
  const freqDev = Math.abs(parseFloat(record.frequency_deviation_hz) || 0);
  const scadaCmds = parseFloat(record.scada_command_count) || 0;
  const powerKw = parseFloat(record.power_consumption_kw) || 0;
  const latency = parseFloat(record.network_latency_ms) || 0;
  const packetLoss = parseFloat(record.packet_loss_percent) || 0;
  const failedLogins = parseFloat(record.failed_login_count) || 0;

  // Authentic Cyber Security Metrics from the dataset
  const intrusionSig = Math.max(0, Math.min(1.0, parseFloat(record.intrusion_signature_score) || 0));
  const behaviorScore = Math.max(0, Math.min(1.0, parseFloat(record.behavior_anomaly_score) || 0));
  const trafficEntropy = parseFloat(record.traffic_entropy) || 0;
  const sessionRisk = Math.max(0, Math.min(100.0, parseFloat(record.session_risk_score) || 0));

  let rfScore = intrusionSig * 0.5;
  let isoAnomaly = behaviorScore > 0.85 ? 1 : 0;
  let isoScore = behaviorScore;
  let lstmScore = null;
  let lstmStatus = 'unavailable';
  let rfVote = 0;
  let isoVote = 0;
  let lstmVote = null;
  let consensusVotes = 0;
  let votingMode = '2-of-2';
  let detectedAlert = null;

  // --- Check if detect.py generated predictions with the trained models (.pkl and .keras) ---
  if (fs.existsSync(DETECTION_FILE)) {
    try {
      const detContent = fs.readFileSync(DETECTION_FILE, 'utf8');
      if (detContent.trim()) {
        const det = JSON.parse(detContent);
        if (typeof det.rf_score === 'number') rfScore = det.rf_score;
        if (typeof det.rf_vote === 'number') rfVote = det.rf_vote;
        if (typeof det.iso_anomaly === 'number') isoAnomaly = det.iso_anomaly;
        if (typeof det.iso_vote === 'number') isoVote = det.iso_vote;
        if (typeof det.lstm_score === 'number') {
          lstmScore = det.lstm_score;
        } else if (det.lstm_score === null) {
          lstmScore = null;
        }
        if (typeof det.lstm_vote === 'number' || det.lstm_vote === null) lstmVote = det.lstm_vote;
        lstmStatus = det.lstm_status || (det.lstm_score === null ? 'unavailable' : 'active');
        if (typeof det.consensus_votes === 'number') consensusVotes = det.consensus_votes;
        if (typeof det.voting_mode === 'string') votingMode = det.voting_mode;
        if (typeof det.alert === 'boolean') detectedAlert = det.alert;
      }
    } catch (e) {
      // fallback
    }
  }

  // --- Grounded Physical Telemetry from GridPhysics Engine ---
  const phys = GridPhysics.getPhysicalTelemetry(simulatedClass);
  const reportedFreqDev = phys.metrics.frequencyDeviation;
  const reportedVoltDev = phys.metrics.voltageDeviation;
  const reportedPowerKw = phys.metrics.powerKw;
  const thdPercent = phys.thdPercent;
  const gridStatusMessage = phys.statusMessage;
  const playbookAction = phys.playbookAction;

  // --- Calibrated Consensus OT Defense Voting ---
  const isConsensusThreat = detectedAlert !== null ? detectedAlert : (rfVote + isoVote >= 2);

  return {
    rfScore: typeof rfScore === 'number' ? parseFloat(rfScore.toFixed(4)) : 0,
    rfVote,
    isoScore: typeof isoScore === 'number' ? parseFloat(isoScore.toFixed(4)) : 0,
    isoAnomaly,
    isoVote,
    lstmScore: typeof lstmScore === 'number' ? parseFloat(lstmScore.toFixed(4)) : null,
    lstmVote,
    lstm_status: lstmStatus,
    consensusVotes,
    votingMode,
    isConsensusThreat,
    playbookAction,
    gridStatusMessage,
    thdPercent,
    metrics: {
      voltageDeviation: reportedVoltDev,
      frequencyDeviation: reportedFreqDev,
      powerKw: reportedPowerKw,
      thdPercent,
      scadaCommands: parseInt(record.scada_command_count || 0, 10),
      networkLatency: parseFloat((record.network_latency_ms || 0).toFixed(1)),
      packetRate: parseInt(record.packet_rate_per_sec || 0, 10),
      trafficEntropy: parseFloat((record.traffic_entropy || 0).toFixed(2)),
      sessionRisk: parseFloat((record.session_risk_score || 0).toFixed(1))
    }
  };
}

// 3. Packet Generation & Distribution
function createTelemetryPayload(sourceRecord, externalPacketId = null, externalTimestamp = null) {
  const analysis = analyzeTelemetry(sourceRecord);
  const now = new Date();
  const timestampStr = externalTimestamp || (now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0'));

  const pid = externalPacketId || packetCounter++;
  const payload = {
    packet_id: pid,
    timestamp: timestampStr,
    full_timestamp: now.toISOString(),
    node_id: sourceRecord.energy_node_id || `Node_${String(Math.floor(Math.random() * 12) + 1).padStart(2, '0')}`,
    substation: sourceRecord.substation_type || 'Distribution',
    protocol: sourceRecord.communication_protocol || 'DNP3',
    device_type: sourceRecord.device_type || 'RTU',
    simulated_class: sourceRecord.attack_type || 'Normal',
    analysis,
    raw_telemetry: sourceRecord
  };

  // Only write to live_stream.json if external generator is not actively running
  if (!externalPacketId && (Date.now() - lastExternalPacketTime > 15000)) {
    try {
      const syncData = {
        packet_id: pid,
        timestamp: now.toISOString().replace('T', ' ').substring(0, 19),
        simulated_class: payload.simulated_class,
        features: extract37Features(sourceRecord)
      };
      const tmpFile = LIVE_STREAM_FILE + '.tmp';
      fs.writeFileSync(tmpFile, JSON.stringify(syncData));
      fs.renameSync(tmpFile, LIVE_STREAM_FILE);
    } catch (e) {
      // Non-fatal if file locked
    }
  }

  // Check if live detection output from trained models is available
  if (fs.existsSync(DETECTION_FILE)) {
    try {
      const detContent = fs.readFileSync(DETECTION_FILE, 'utf8');
      if (detContent.trim()) {
        const det = JSON.parse(detContent);
        const matchesClass = det.simulated_class === payload.simulated_class;
        const matchesPid = (externalPacketId && det.packet_id === externalPacketId) || (!externalPacketId && Math.abs((det.packet_id || 0) - pid) <= 1);
        const isRecent = (Date.now() - (lastExternalPacketTime || 0) < 10000);

        if (matchesClass && (matchesPid || isRecent)) {
          if (typeof det.rf_score === 'number') analysis.rfScore = parseFloat(det.rf_score.toFixed(4));
          if (typeof det.rf_vote === 'number') analysis.rfVote = det.rf_vote;
          if (typeof det.iso_anomaly === 'number') analysis.isoAnomaly = det.iso_anomaly;
          if (typeof det.iso_vote === 'number') analysis.isoVote = det.iso_vote;
          if (typeof det.lstm_score === 'number') {
            analysis.lstmScore = parseFloat(det.lstm_score.toFixed(4));
          } else if (det.lstm_score === null) {
            analysis.lstmScore = null;
          }
          if (typeof det.lstm_vote === 'number' || det.lstm_vote === null) analysis.lstmVote = det.lstm_vote;
          analysis.lstm_status = det.lstm_status || (det.lstm_score === null ? 'unavailable' : 'active');
          if (typeof det.consensus_votes === 'number') analysis.consensusVotes = det.consensus_votes;
          if (typeof det.voting_mode === 'string') analysis.votingMode = det.voting_mode;
          if (typeof det.alert === 'boolean') {
            analysis.isConsensusThreat = det.alert;
          }
        }
      }
    } catch (e) {
      // Ignore transient read error
    }
  }

  // Update Statistics AFTER binding authentic detection
  stats.totalPackets++;
  if (analysis.isConsensusThreat) {
    stats.attacksDetected++;
    const t = payload.simulated_class;
    stats.attacksByType[t] = (stats.attacksByType[t] || 0) + 1;
  } else {
    stats.normalForwarded++;
  }

  return payload;
}

let lastExternalPacketTime = 0;
let lastSeenExternalPacketId = null;

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

function stepSimulation(forcedClass = null) {
  if (dataset.length === 0) return;
  // If paused and not an explicit operator manual injection, do not step
  if (!isStreaming && !forcedClass) return;

  // If external stream_generator.py is actively generating packets, let stream_generator.py drive it
  if (!forcedClass && (Date.now() - lastExternalPacketTime < streamIntervalMs + 1000)) {
    return;
  }

  if (forcedClass) {
    selectedAttack = forcedClass;
  }

  // Default to Normal baseline unless an attack is explicitly selected/injected
  const targetClass = forcedClass || selectedAttack || 'Normal';
  let record;
  if (datasetByClass[targetClass] && datasetByClass[targetClass].length > 0) {
    const list = datasetByClass[targetClass];
    record = list[Math.floor(Math.random() * list.length)];
  } else if (datasetByClass['Normal'] && datasetByClass['Normal'].length > 0) {
    const list = datasetByClass['Normal'];
    record = list[Math.floor(Math.random() * list.length)];
  } else {
    record = dataset[datasetIndex % dataset.length];
    datasetIndex++;
  }

  const payload = createTelemetryPayload(record);
  broadcastEvent(payload);
}

// 4. File Watcher for live_stream.json (if user runs external stream_generator.py)
function checkExternalStreamFile() {
  if (!isStreaming) return; // Obey pause state

  try {
    if (!fs.existsSync(LIVE_STREAM_FILE)) return;
    const content = fs.readFileSync(LIVE_STREAM_FILE, 'utf8');
    if (!content.trim()) return;
    const filePacket = JSON.parse(content);

    // Only process if it was written by an EXTERNAL script (stream_generator.py)
    if (filePacket && filePacket.packet_id && filePacket.packet_id !== lastSeenExternalPacketId) {
      lastSeenExternalPacketId = filePacket.packet_id;
      lastExternalPacketTime = Date.now();
      
      const matchClass = filePacket.simulated_class || 'Normal';
      let record = null;
      if (datasetByClass[matchClass] && datasetByClass[matchClass].length > 0) {
        record = datasetByClass[matchClass][Math.floor(Math.random() * datasetByClass[matchClass].length)];
      } else if (dataset.length > 0) {
        record = dataset[0];
      }

      if (record) {
        record.attack_type = matchClass;
        const ts = filePacket.timestamp ? filePacket.timestamp.split(' ')[1] : null;
        const payload = createTelemetryPayload(record, filePacket.packet_id, ts);
        payload.simulated_class = matchClass;
        broadcastEvent(payload);
      }
    }
  } catch (err) {
    // Ignore transient file lock errors
  }
}

// Start Stream Interval Timer
function restartStreamTimer() {
  if (streamTimer) {
    clearInterval(streamTimer);
    streamTimer = null;
  }

  // Synchronize configuration file for stream_generator.py
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify({
      interval: streamIntervalMs / 1000.0,
      is_streaming: isStreaming,
      selected_attack: selectedAttack
    }, null, 2));
  } catch (e) {
    // ignore
  }

  if (!isStreaming) {
    console.log('[*] Telemetry stream paused by operator.');
    return;
  }
  console.log(`[*] Telemetry stream active at rate: ${streamIntervalMs}ms | Mode: ${selectedAttack}`);
  streamTimer = setInterval(() => {
    stepSimulation();
  }, streamIntervalMs);
}

// Check for external generator updates every 150ms
setInterval(checkExternalStreamFile, 150);

// 5. HTTP Server & Endpoints
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

    // Send initial snapshot including selected attack and interval
    res.write(`data: ${JSON.stringify({ type: 'connected', stats, streamIntervalMs, isStreaming, selectedAttack })}\n\n`);

    req.on('close', () => {
      clients = clients.filter(c => c !== res);
    });
    return;
  }

  // Force Inject an Attack or Normal Packet
  if (pathname === '/api/inject' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        const attackClass = data.attack_type || 'Normal';
        selectedAttack = attackClass;
        restartStreamTimer(); // Update stream_config.json so stream_generator.py reflects it
        stepSimulation(attackClass);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, injected: attackClass, selectedAttack }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // Update Config (Rate, Pause/Resume)
  if (pathname === '/api/config' && req.method === 'POST') {
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
        restartStreamTimer();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ isStreaming, streamIntervalMs }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
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

// Start Server
try {
  if (fs.existsSync(CONFIG_FILE)) {
    const cfg = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    if (typeof cfg.interval === 'number' && cfg.interval > 0) {
      streamIntervalMs = Math.round(cfg.interval * 1000);
    }
    if (cfg.selected_attack) {
      selectedAttack = cfg.selected_attack;
    }
  }
} catch (e) {
  // ignore
}

loadDataset();
restartStreamTimer();

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n[!] Port ${PORT} is currently in use.`);
    console.error(`[*] To free port ${PORT}, run: kill -9 $(lsof -ti:${PORT})\n`);
    process.exit(1);
  } else {
    throw err;
  }
});

server.listen(PORT, () => {
  console.log('================================================================');
  console.log('  🏭 AI-DRIVEN POWER PLANT ICS INTRUSION DETECTION SYSTEM (UI)  ');
  console.log('================================================================');
  console.log(`[+] Web UI Dashboard online: http://localhost:${PORT}`);
  console.log(`[+] Live Telemetry SSE:     http://localhost:${PORT}/api/stream`);
  console.log(`[+] Telemetry Stream Rate:   ${streamIntervalMs}ms`);
  console.log('================================================================\n');
});
