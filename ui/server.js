const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 5050;
const ROOT_DIR = path.resolve(__dirname, '..');
const LIVE_STREAM_FILE = path.join(ROOT_DIR, 'live_stream.json');
const DETECTION_FILE = path.join(ROOT_DIR, 'live_detection.json');
const CONFIG_FILE = path.join(ROOT_DIR, 'stream_config.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

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
    const payload = {
      packet_id: detectionData.packet_id,
      timestamp: detectionData.timestamp || new Date().toISOString(),
      node_id: detectionData.node_id || 'N/A',
      substation: detectionData.substation || 'Distribution',
      protocol: detectionData.protocol || 'DNP3',
      device_type: detectionData.device_type || 'RTU',
      simulated_class: detectionData.simulated_class || 'Normal',
      source: detectionData.source || 'simulator',
      engine_offline: false,
      analysis: {
        rfScore: typeof detectionData.rf_score === 'number' ? parseFloat(detectionData.rf_score.toFixed(4)) : null,
        rfVote: typeof detectionData.rf_vote === 'number' ? detectionData.rf_vote : 0,
        isoAnomaly: typeof detectionData.iso_anomaly === 'number' ? detectionData.iso_anomaly : 0,
        isoVote: typeof detectionData.iso_vote === 'number' ? detectionData.iso_vote : 0,
        lstmScore: typeof detectionData.lstm_score === 'number' ? parseFloat(detectionData.lstm_score.toFixed(4)) : null,
        lstmVote: typeof detectionData.lstm_vote === 'number' ? detectionData.lstm_vote : null,
        lstm_status: detectionData.lstm_status || (detectionData.lstm_score === null ? 'unavailable' : 'active'),
        consensusVotes: typeof detectionData.consensus_votes === 'number' ? detectionData.consensus_votes : 0,
        votingMode: detectionData.voting_mode || '2-of-2',
        isConsensusThreat: Boolean(detectionData.alert),
        playbookAction: detectionData.alert ? 'SAFETY_INTERLOCK_ENGAGED' : 'PASSIVE_MONITORING',
        gridStatusMessage: detectionData.alert ? 'TRIP BREAKER ENGAGED' : 'NOMINAL GRID',
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
        updateStreamConfigFile();
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
});
