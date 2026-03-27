const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { exec, spawn } = require('child_process');
const cors = require('cors');
const archiver = require('archiver');

// Auth — login page + user management, no route blocking
let authModule = null, session = null;
try {
  authModule = require('./auth');
  session = require('express-session');
} catch(e) {
  console.warn('Auth modules not installed, running without auth.');
}

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Sessions — loose config, works over IP and any origin
if (session) {
  app.use(session({
    secret: process.env.SESSION_SECRET || 'cordovadeck-dev-secret',
    resave: true,
    saveUninitialized: true,
    cookie: {
      secure: false,
      httpOnly: false,
      maxAge: 8 * 60 * 60 * 1000,
      sameSite: 'lax',
    },
  }));
}

// Auth routes (login, logout, user management)
if (authModule) {
  app.use('/api/auth', authModule.router);
  authModule.initDb();
}

// Serve login page at /login.html, dashboard at /
// No blocking — auth is informational only for now
app.use(express.static(path.join(__dirname, 'public')));

// Dirs
const PROJECTS_DIR = path.join(__dirname, 'projects');
const BUILDS_DIR = path.join(__dirname, 'builds');
[PROJECTS_DIR, BUILDS_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));

// File upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const projectPath = path.join(PROJECTS_DIR, req.params.project, 'www');
    fs.mkdirSync(projectPath, { recursive: true });
    cb(null, projectPath);
  },
  filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage });

// ── Projects ──────────────────────────────────────────────────────────────────

app.get('/api/projects', (req, res) => {
  if (!fs.existsSync(PROJECTS_DIR)) return res.json([]);
  const projects = fs.readdirSync(PROJECTS_DIR)
    .filter(f => fs.statSync(path.join(PROJECTS_DIR, f)).isDirectory())
    .map(name => {
      const configPath = path.join(PROJECTS_DIR, name, 'config.xml');
      let meta = { name, id: '', version: '1.0.0' };
      if (fs.existsSync(configPath)) {
        const xml = fs.readFileSync(configPath, 'utf8');
        const idMatch = xml.match(/id="([^"]+)"/);
        const vMatch = xml.match(/version="([^"]+)"/);
        if (idMatch) meta.id = idMatch[1];
        if (vMatch) meta.version = vMatch[1];
      }
      return meta;
    });
  res.json(projects);
});

app.post('/api/projects', express.json(), async (req, res) => {
  const { name, id = 'com.example.app', displayName = name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const projectPath = path.join(PROJECTS_DIR, name);
  if (fs.existsSync(projectPath)) return res.status(409).json({ error: 'Project exists' });

  exec(`cordova create "${projectPath}" "${id}" "${displayName}"`, (err, stdout, stderr) => {
    if (err) {
      // Fallback: create minimal structure manually
      fs.mkdirSync(path.join(projectPath, 'www'), { recursive: true });
      fs.mkdirSync(path.join(projectPath, 'platforms'), { recursive: true });
      fs.mkdirSync(path.join(projectPath, 'plugins'), { recursive: true });
      const config = `<?xml version='1.0' encoding='utf-8'?>
<widget id="${id}" version="1.0.0" xmlns="http://www.w3.org/ns/widgets">
    <name>${displayName}</name>
    <description>A new Cordova project</description>
    <author email="dev@example.com" href="http://example.com">Developer</author>
    <content src="index.html" />
    <plugin name="cordova-plugin-whitelist" spec="1" />
    <access origin="*" />
    <allow-intent href="http://*/*" />
    <allow-intent href="https://*/*" />
</widget>`;
      fs.writeFileSync(path.join(projectPath, 'config.xml'), config);
      const indexHtml = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="initial-scale=1, width=device-width, viewport-fit=cover">
    <title>${displayName}</title>
    <style>
        body { font-family: sans-serif; text-align: center; padding: 50px; background: #1a1a2e; color: #e0e0e0; }
        h1 { color: #00d4ff; }
    </style>
</head>
<body>
    <h1>${displayName}</h1>
    <p>Edit this file to build your app!</p>
    <script src="cordova.js"></script>
</body>
</html>`;
      fs.writeFileSync(path.join(projectPath, 'www', 'index.html'), indexHtml);
    }
    res.json({ success: true, name });
  });
});

app.delete('/api/projects/:project', (req, res) => {
  const projectPath = path.join(PROJECTS_DIR, req.params.project);
  if (!fs.existsSync(projectPath)) return res.status(404).json({ error: 'Not found' });
  fs.rmSync(projectPath, { recursive: true, force: true });
  res.json({ success: true });
});

// ── File Tree ─────────────────────────────────────────────────────────────────

function buildTree(dir, base = '') {
  const items = [];
  if (!fs.existsSync(dir)) return items;
  fs.readdirSync(dir).forEach(name => {
    const full = path.join(dir, name);
    const rel = path.join(base, name);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      items.push({ name, path: rel, type: 'dir', children: buildTree(full, rel) });
    } else {
      items.push({ name, path: rel, type: 'file', size: stat.size });
    }
  });
  return items;
}

app.get('/api/projects/:project/files', (req, res) => {
  const wwwPath = path.join(PROJECTS_DIR, req.params.project, 'www');
  res.json(buildTree(wwwPath));
});

app.get('/api/projects/:project/files/*', (req, res) => {
  const filePath = path.join(PROJECTS_DIR, req.params.project, 'www', req.params[0]);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Not found' });
  res.json({ content: fs.readFileSync(filePath, 'utf8'), path: req.params[0] });
});

app.put('/api/projects/:project/files/*', (req, res) => {
  const filePath = path.join(PROJECTS_DIR, req.params.project, 'www', req.params[0]);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, req.body.content || '');
  res.json({ success: true });
});

app.post('/api/projects/:project/files', (req, res) => {
  const { path: filePath, content = '', type = 'file' } = req.body;
  const fullPath = path.join(PROJECTS_DIR, req.params.project, 'www', filePath);
  if (type === 'dir') {
    fs.mkdirSync(fullPath, { recursive: true });
  } else {
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content);
  }
  res.json({ success: true });
});

app.delete('/api/projects/:project/files/*', (req, res) => {
  const filePath = path.join(PROJECTS_DIR, req.params.project, 'www', req.params[0]);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Not found' });
  const stat = fs.statSync(filePath);
  if (stat.isDirectory()) fs.rmSync(filePath, { recursive: true });
  else fs.unlinkSync(filePath);
  res.json({ success: true });
});

app.post('/api/projects/:project/upload', upload.array('files'), (req, res) => {
  res.json({ success: true, files: req.files.map(f => f.originalname) });
});

// ── Config ────────────────────────────────────────────────────────────────────

app.get('/api/projects/:project/config', (req, res) => {
  const configPath = path.join(PROJECTS_DIR, req.params.project, 'config.xml');
  if (!fs.existsSync(configPath)) return res.status(404).json({ error: 'config.xml not found' });
  res.json({ content: fs.readFileSync(configPath, 'utf8') });
});

app.put('/api/projects/:project/config', (req, res) => {
  const configPath = path.join(PROJECTS_DIR, req.params.project, 'config.xml');
  fs.writeFileSync(configPath, req.body.content);
  res.json({ success: true });
});

// ── Plugins ───────────────────────────────────────────────────────────────────

app.get('/api/projects/:project/plugins', (req, res) => {
  const pluginsPath = path.join(PROJECTS_DIR, req.params.project, 'plugins');
  if (!fs.existsSync(pluginsPath)) return res.json([]);
  const plugins = fs.readdirSync(pluginsPath)
    .filter(f => fs.statSync(path.join(pluginsPath, f)).isDirectory())
    .map(name => {
      const pkgPath = path.join(pluginsPath, name, 'package.json');
      let version = '';
      if (fs.existsSync(pkgPath)) {
        try { version = JSON.parse(fs.readFileSync(pkgPath, 'utf8')).version || ''; } catch (e) {}
      }
      return { name, version };
    });
  res.json(plugins);
});

app.post('/api/projects/:project/plugins', (req, res) => {
  const { plugin } = req.body;
  const projectPath = path.join(PROJECTS_DIR, req.params.project);
  const socketId = req.body.socketId;

  const proc = spawn('cordova', ['plugin', 'add', plugin], { cwd: projectPath });
  proc.stdout.on('data', d => io.to(socketId).emit('log', { type: 'stdout', data: d.toString() }));
  proc.stderr.on('data', d => io.to(socketId).emit('log', { type: 'stderr', data: d.toString() }));
  proc.on('close', code => {
    io.to(socketId).emit('log', { type: code === 0 ? 'success' : 'error', data: `Plugin ${code === 0 ? 'added' : 'failed'}` });
    res.json({ success: code === 0 });
  });
});

app.delete('/api/projects/:project/plugins/:plugin', (req, res) => {
  const projectPath = path.join(PROJECTS_DIR, req.params.project);
  exec(`cordova plugin rm ${req.params.plugin}`, { cwd: projectPath }, (err) => {
    res.json({ success: !err });
  });
});

// ── Build ─────────────────────────────────────────────────────────────────────

const buildProcesses = {};

app.post('/api/projects/:project/build', (req, res) => {
  const { platform = 'android', release = false, socketId } = req.body;
  const projectPath = path.join(PROJECTS_DIR, req.params.project);
  const buildId = `${req.params.project}_${Date.now()}`;

  res.json({ buildId });

  const cmd = release ? `cordova build ${platform} --release` : `cordova build ${platform}`;
  const proc = spawn('bash', ['-c', cmd], { cwd: projectPath });
  buildProcesses[buildId] = proc;

  io.to(socketId).emit('build:start', { buildId });

  proc.stdout.on('data', d => io.to(socketId).emit('build:log', { buildId, type: 'stdout', data: d.toString() }));
  proc.stderr.on('data', d => io.to(socketId).emit('build:log', { buildId, type: 'stderr', data: d.toString() }));

  proc.on('close', code => {
    if (code === 0) {
      // Find APK
      const apkSearch = path.join(projectPath, 'platforms', platform);
      let apkPath = null;
      function findApk(dir) {
        if (!fs.existsSync(dir)) return;
        fs.readdirSync(dir).forEach(f => {
          const full = path.join(dir, f);
          if (fs.statSync(full).isDirectory()) findApk(full);
          else if (f.endsWith('.apk')) apkPath = full;
        });
      }
      findApk(apkSearch);

      if (apkPath) {
        const destName = `${req.params.project}_${buildId}.apk`;
        const destPath = path.join(BUILDS_DIR, destName);
        fs.copyFileSync(apkPath, destPath);
        io.to(socketId).emit('build:success', { buildId, apk: destName, downloadUrl: `/api/download/${destName}` });
      } else {
        io.to(socketId).emit('build:success', { buildId, apk: null });
      }
    } else {
      io.to(socketId).emit('build:error', { buildId, code });
    }
    delete buildProcesses[buildId];
  });
});

app.post('/api/build/:buildId/cancel', (req, res) => {
  const proc = buildProcesses[req.params.buildId];
  if (proc) { proc.kill(); res.json({ success: true }); }
  else res.status(404).json({ error: 'Build not found' });
});

// ── Downloads ─────────────────────────────────────────────────────────────────

app.get('/api/download/:file', (req, res) => {
  const filePath = path.join(BUILDS_DIR, req.params.file);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });
  res.download(filePath);
});

app.get('/api/builds', (req, res) => {
  if (!fs.existsSync(BUILDS_DIR)) return res.json([]);
  const builds = fs.readdirSync(BUILDS_DIR)
    .filter(f => f.endsWith('.apk'))
    .map(f => {
      const stat = fs.statSync(path.join(BUILDS_DIR, f));
      return { name: f, size: stat.size, date: stat.mtime, downloadUrl: `/api/download/${f}` };
    })
    .sort((a, b) => new Date(b.date) - new Date(a.date));
  res.json(builds);
});

app.delete('/api/builds/:file', (req, res) => {
  const filePath = path.join(BUILDS_DIR, req.params.file);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  res.json({ success: true });
});

// ── Project ZIP export ────────────────────────────────────────────────────────

app.get('/api/projects/:project/export', (req, res) => {
  const projectPath = path.join(PROJECTS_DIR, req.params.project);
  res.setHeader('Content-Disposition', `attachment; filename="${req.params.project}.zip"`);
  res.setHeader('Content-Type', 'application/zip');
  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.pipe(res);
  archive.directory(projectPath, false);
  archive.finalize();
});

// ── System Info ───────────────────────────────────────────────────────────────

const os = require('os');
const SERVER_START = Date.now();

function fmtUptime(secs) {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = Math.floor(secs % 60);
  return d > 0 ? `${d}d ${h}h ${m}m` : h > 0 ? `${h}h ${m}m ${s}s` : `${m}m ${s}s`;
}

app.get('/api/sysinfo', async (req, res) => {
  try {
    const cpus      = os.cpus();
    const totalMem  = os.totalmem();
    const freeMem   = os.freemem();
    const usedMem   = totalMem - freeMem;
    const memPct    = Math.round((usedMem / totalMem) * 100);
    const uptimeSecs  = os.uptime();
    const sessionSecs = Math.floor((Date.now() - SERVER_START) / 1000);

    // CPU: sample over 300ms
    const cpuPct = await new Promise(resolve => {
      const snap = () => os.cpus().map(c => ({
        idle:  c.times.idle,
        total: Object.values(c.times).reduce((a, b) => a + b, 0)
      }));
      const t1 = snap();
      setTimeout(() => {
        const t2 = snap();
        const pcts = t2.map((c, i) => {
          const idleDiff  = c.idle  - t1[i].idle;
          const totalDiff = c.total - t1[i].total;
          return totalDiff === 0 ? 0 : Math.round((1 - idleDiff / totalDiff) * 100);
        });
        resolve(Math.round(pcts.reduce((a, b) => a + b, 0) / pcts.length));
      }, 300);
    });

    // Disk: try df, fall back gracefully
    let disk = { total: 0, used: 0, free: 0, pct: 0 };
    try {
      const dfOut = await new Promise((resolve, reject) =>
        exec('df -BM / 2>/dev/null | tail -1', (err, out) => err ? reject(err) : resolve(out))
      );
      // columns: Filesystem 1M-blocks Used Available Use% Mounted
      const parts = dfOut.trim().split(/\s+/);
      const total = parseInt(parts[1]) || 0;
      const used  = parseInt(parts[2]) || 0;
      const free  = parseInt(parts[3]) || 0;
      disk = { total, used, free, pct: total > 0 ? Math.round((used / total) * 100) : 0 };
    } catch (_) {}

    res.json({
      cpu: { usage: cpuPct, cores: cpus.length, model: (cpus[0] && cpus[0].model || 'Unknown').trim() },
      mem: { total: totalMem, used: usedMem, free: freeMem, pct: memPct },
      disk,
      uptime:        fmtUptime(uptimeSecs),
      sessionUptime: fmtUptime(sessionSecs),
      uptimeSecs,
      sessionSecs,
      platform:    os.platform(),
      hostname:    os.hostname(),
      nodeVersion: process.version,
      loadAvg:     os.loadavg().map(l => parseFloat(l.toFixed(2))),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Terminal via PTY Socket ──────────────────────────────────────────────────

let pty;
try { pty = require('node-pty'); } catch(e) { console.warn('node-pty not available, falling back to spawn'); }

const termSessions = {}; // socket.id -> pty instance

io.on('connection', socket => {
  console.log('Client connected:', socket.id);

  // Full PTY session — supports sudo, interactive programs, colours
  socket.on('terminal:create', ({ project, cols = 120, rows = 40 }) => {
    if (termSessions[socket.id]) {
      try { termSessions[socket.id].kill(); } catch(e) {}
    }
    const cwd = project ? path.join(PROJECTS_DIR, project) : process.env.HOME || __dirname;

    if (pty) {
      const shell = process.env.SHELL || 'bash';
      const p = pty.spawn(shell, [], {
        name: 'xterm-256color',
        cols, rows, cwd,
        env: { ...process.env, TERM: 'xterm-256color', COLORTERM: 'truecolor' }
      });
      termSessions[socket.id] = p;
      p.onData(data => socket.emit('terminal:data', data));
      p.onExit(({ exitCode }) => {
        delete termSessions[socket.id];
        socket.emit('terminal:exit', { code: exitCode });
      });
    } else {
      // Fallback: spawn bash
      const proc = spawn('bash', ['--login'], { cwd, env: { ...process.env }, stdio: ['pipe','pipe','pipe'] });
      proc._isFallback = true;
      termSessions[socket.id] = proc;
      proc.stdout.on('data', d => socket.emit('terminal:data', d.toString()));
      proc.stderr.on('data', d => socket.emit('terminal:data', d.toString()));
      proc.on('close', code => { delete termSessions[socket.id]; socket.emit('terminal:exit', { code }); });
    }
  });

  // Simple terminal: run command via spawn (no PTY, safe for basic use)
  const simpleProcs = {};
  socket.on('terminal:run', ({ command, project }) => {
    if (simpleProcs[socket.id]) { try { simpleProcs[socket.id].kill('SIGTERM'); } catch(e) {} }
    const cwd = project ? require('path').join(PROJECTS_DIR, project) : __dirname;
    const proc = spawn('bash', ['-c', command], { cwd });
    simpleProcs[socket.id] = proc;
    proc.stdout.on('data', d => socket.emit('terminal:out', { data: d.toString() }));
    proc.stderr.on('data', d => socket.emit('terminal:out', { data: d.toString(), error: true }));
    proc.on('close', code => { delete simpleProcs[socket.id]; socket.emit('terminal:done', { code }); });
  });

  // Send keystrokes / input to PTY
  socket.on('terminal:input', (data) => {
    const s = termSessions[socket.id];
    if (!s) return;
    if (s._isFallback) { s.stdin.write(data); }
    else { try { s.write(data); } catch(e) {} }
  });

  // Resize PTY
  socket.on('terminal:resize', ({ cols, rows }) => {
    const s = termSessions[socket.id];
    if (s && !s._isFallback) { try { s.resize(cols, rows); } catch(e) {} }
  });

  socket.on('terminal:kill', () => {
    const s = termSessions[socket.id];
    if (s) {
      try { s._isFallback ? s.kill('SIGTERM') : s.kill(); } catch(e) {}
      delete termSessions[socket.id];
      socket.emit('terminal:exit', { code: -1 });
    }
  });

  // ── btop PTY ─────────────────────────────────────────────────────────────────
  let btopProc = null;

  socket.on('btop:start', ({ cols = 120, rows = 30 }) => {
    if (btopProc) { try { btopProc.kill(); } catch(e) {} }

    // Check btop is installed
    const { execSync } = require('child_process');
    let cmd = 'btop';
    try { execSync('which btop', { stdio: 'ignore' }); }
    catch(e) {
      // fallback to htop, then top
      try { execSync('which htop', { stdio: 'ignore' }); cmd = 'htop'; }
      catch(e2) { cmd = 'top'; }
    }

    if (!pty) {
      socket.emit('btop:error', 'node-pty not installed. Run: npm install');
      return;
    }

    try {
      btopProc = pty.spawn(cmd, [], {
        name: 'xterm-256color',
        cols, rows,
        env: { ...process.env, TERM: 'xterm-256color', COLORTERM: 'truecolor', BTOP_THEME: 'TTY' },
      });
      btopProc.onData(data => socket.emit('btop:data', data));
      btopProc.onExit(({ exitCode }) => {
        btopProc = null;
        socket.emit('btop:exit', { code: exitCode });
      });
    } catch(e) {
      socket.emit('btop:error', 'Failed to start ' + cmd + ': ' + e.message);
    }
  });

  socket.on('btop:input', data => {
    if (btopProc) { try { btopProc.write(data); } catch(e) {} }
  });

  socket.on('btop:resize', ({ cols, rows }) => {
    if (btopProc) { try { btopProc.resize(cols, rows); } catch(e) {} }
  });

  socket.on('btop:stop', () => {
    if (btopProc) { try { btopProc.kill(); } catch(e) {} btopProc = null; }
  });

  socket.on('disconnect', () => {
    if (btopProc) { try { btopProc.kill(); } catch(e) {} btopProc = null; }
    const s = termSessions[socket.id];
    if (s) { try { s._isFallback ? s.kill('SIGTERM') : s.kill(); } catch(e) {} delete termSessions[socket.id]; }
    console.log('Client disconnected:', socket.id);
  });
});

// ── Server Env Check ─────────────────────────────────────────────────────────

app.get('/api/env', (req, res) => {
  exec('node -v && npm -v && cordova -v && java -version 2>&1', (err, stdout, stderr) => {
    res.json({ output: stdout + stderr });
  });
});

// ── SSH Relay WebSocket ──────────────────────────────────────────────────────
// Bridges the InfinityFree launcher page → WS → SSH on this Codespace
// The launcher connects to this relay's portmap-forwarded WS URL
// then this relay spawns an SSH connection using ssh2

let ssh2;
try { ssh2 = require('ssh2'); } catch(e) {
  console.warn('⚠️  ssh2 not installed. Run: npm install ssh2');
  console.warn('   SSH relay will not work without it.');
}

const { WebSocketServer } = require('ws');
const sshRelayServer = new WebSocketServer({ noServer: true });

sshRelayServer.on('connection', (ws) => {
  let sshConn = null;
  let sshStream = null;
  let authed = false;

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw);

      if (msg.type === 'auth' && !authed) {
        if (!ssh2) { ws.send(JSON.stringify({ type:'error', message:'ssh2 module not installed on server' })); return; }
        authed = true;
        sshConn = new ssh2.Client();
        sshConn.on('ready', () => {
          sshConn.shell({ term:'xterm-256color', cols: msg.cols||120, rows: msg.rows||40 }, (err, stream) => {
            if (err) { ws.send(JSON.stringify({ type:'error', message: err.message })); return; }
            sshStream = stream;
            ws.send(JSON.stringify({ type:'ready' }));
            stream.on('data', d => ws.send(JSON.stringify({ type:'data', data: d.toString() })));
            stream.stderr.on('data', d => ws.send(JSON.stringify({ type:'data', data: d.toString() })));
            stream.on('close', () => {
              ws.send(JSON.stringify({ type:'data', data: '\r\n[SSH session closed]\r\n' }));
              if (sshConn) sshConn.end();
            });
          });
        });
        sshConn.on('error', e => ws.send(JSON.stringify({ type:'error', message: e.message })));
        sshConn.connect({
          host:     msg.host     || 'localhost',
          port:     msg.port     || 22,
          username: msg.username || 'root',
          password: msg.password || '',
          readyTimeout: 10000,
        });
        return;
      }

      if (msg.type === 'input'  && sshStream) { sshStream.write(msg.data); }
      if (msg.type === 'resize' && sshStream) { sshStream.setWindow(msg.rows||24, msg.cols||80); }

    } catch(e) {
      // Raw passthrough for non-JSON messages
      if (sshStream) sshStream.write(raw);
    }
  });

  ws.on('close', () => {
    if (sshStream) { try { sshStream.end(); } catch(e) {} }
    if (sshConn)   { try { sshConn.end();   } catch(e) {} }
  });
});

// SSH ping endpoint — lets launcher check if relay is reachable
app.get('/api/ssh-ping', (req, res) => {
  res.json({ ok: true, relay: 'CordovaDeck SSH relay active' });
});

// ── HOST SWITCHER — redirect back to InfinityFree ────────────────────────────
app.get('/api/launcher-url', (req, res) => {
  res.json({ url: process.env.LAUNCHER_URL || '' });
});

// ── Security event logging ───────────────────────────────────────────────────
function secLog(event, detail) {
  const ts = new Date().toISOString();
  const msg = `[SECURITY] ${ts} | ${event} | ${detail}`;
  console.log(msg);
  // Append to log file
  const logFile = path.join(__dirname, 'security.log');
  fs.appendFileSync(logFile, msg + '\n');
}

// Intercept login attempts from auth module
if (authModule && authModule.onSecEvent) {
  authModule.onSecEvent(secLog);
}

// ── Dev settings — banned commands ───────────────────────────────────────────
let bannedCmds = { pty: [], simple: [] };
const bannedFile = path.join(__dirname, 'banned_cmds.json');
if (fs.existsSync(bannedFile)) {
  try { bannedCmds = JSON.parse(fs.readFileSync(bannedFile)); } catch(e) {}
}

app.post('/api/dev/banned', (req, res) => {
  const { pty = [], simple = [] } = req.body || {};
  bannedCmds = { pty, simple };
  fs.writeFileSync(bannedFile, JSON.stringify(bannedCmds, null, 2));
  res.json({ ok: true });
});

app.get('/api/dev/banned', (req, res) => res.json(bannedCmds));

// ── Cordova version in build ──────────────────────────────────────────────────
app.get('/api/env-versions', (req, res) => {
  exec('cordova --version 2>/dev/null && node --version && java -version 2>&1 | head -1', (err, stdout) => {
    res.json({ versions: stdout.trim() });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 BuildDeck running on http://localhost:${PORT}`);
});

// Upgrade HTTP → WebSocket for SSH relay
server.on('upgrade', (req, socket, head) => {
  if (req.url === '/ssh-relay') {
    sshRelayServer.handleUpgrade(req, socket, head, ws => {
      sshRelayServer.emit('connection', ws, req);
    });
  } else {
    socket.destroy();
  }
});
