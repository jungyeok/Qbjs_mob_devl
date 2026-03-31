// ── auth.js — CordovaDeck Authentication Module ──────────────────────────────
// Uses SQLite for user storage + bcrypt for password hashing
// Sessions stored server-side via express-session + connect-sqlite3
//
// Install deps:  npm install bcryptjs express-session sqlite3 connect-sqlite3

const express  = require('express');
const bcrypt   = require('bcryptjs');
const sqlite3  = require('sqlite3').verbose();

// OTP store for password reset
const otpStore = {};

// Security event callback
let _secEventCb = null;
module.exports.onSecEvent = (cb) => { _secEventCb = cb; };

// Email helper — uses nodemailer if configured
async function sendSecEmail(subject, body) {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const to   = process.env.SMTP_TO || user;
  if (!host || !user || !pass) return false;
  try {
    const nodemailer = require('nodemailer');
    const t = nodemailer.createTransport({ host, port: parseInt(process.env.SMTP_PORT||'587'), auth: { user, pass } });
    await t.sendMail({ from: user, to, subject: '[BuildDeck] ' + subject, text: body });
    return true;
  } catch(e) { console.warn('Email failed:', e.message); return false; }
}

const router   = express.Router();

// ── DB ──────────────────────────────────────────────────────────────────
// SQLite database file
let db;
function getDb() {
  if (!db) {
    db = new sqlite3.Database('./cordovadeck.db', (err) => {
      if (err) {
        console.error('Failed to open SQLite DB:', err.message);
      } else {
        console.log('Connected to SQLite DB');
      }
    });
  }
  return db;
}

// ── INIT DB ───────────────────────────────────────────────────────────────────
// Call this on server startup to ensure tables exist
async function initDb() {
  try {
    const db = getDb();
    await new Promise((resolve, reject) => {
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          username   TEXT NOT NULL UNIQUE,
          password   TEXT NOT NULL,
          role       TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin','user','viewer')),
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_login DATETIME,
          active     INTEGER NOT NULL DEFAULT 1
        )
      `, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    await new Promise((resolve, reject) => {
      db.run(`
        CREATE TABLE IF NOT EXISTS login_log (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          username   TEXT,
          ip         TEXT,
          success    INTEGER,
          ts         DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    // Create default admin if no users exist
    const rows = await new Promise((resolve, reject) => {
      db.get('SELECT COUNT(*) AS cnt FROM users', (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
    if (rows.cnt === 0) {
      const hash = await bcrypt.hash('changeme123', 12);
      await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
          ['admin', hash, 'admin'], (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });
      console.log('✅ Default admin created: admin / changeme123 — CHANGE THIS IMMEDIATELY');
    }
    console.log('✅ Auth DB ready');
  } catch (e) {
    console.warn('⚠️  Auth DB init failed:', e.message);
  }
}

// ── IN-MEMORY RATE LIMITER ────────────────────────────────────────────────────
// Tracks failed attempts per IP. Resets after lockout expires.
const failMap = new Map(); // ip -> { count, until }
const MAX_FAILS    = 5;
const LOCKOUT_MS   = 5 * 60 * 1000; // 5 minutes

function checkRateLimit(ip) {
  const entry = failMap.get(ip);
  if (!entry) return { ok: true };
  if (entry.until && Date.now() < entry.until) {
    const secs = Math.ceil((entry.until - Date.now()) / 1000);
    return { ok: false, retryAfter: secs };
  }
  if (entry.until && Date.now() >= entry.until) {
    failMap.delete(ip); // lockout expired, reset
  }
  return { ok: true };
}

function recordFail(ip) {
  const entry = failMap.get(ip) || { count: 0, until: null };
  entry.count++;
  if (entry.count >= MAX_FAILS) {
    entry.until = Date.now() + LOCKOUT_MS;
  }
  failMap.set(ip, entry);
}

function clearFails(ip) {
  failMap.delete(ip);
}

// ── ROUTES ────────────────────────────────────────────────────────────────────

// POST /api/auth/login
router.post('/login', async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';

  // Rate limit check
  const limit = checkRateLimit(ip);
  if (!limit.ok) {
    return res.status(429).json({
      error: `Too many attempts. Try again in ${Math.ceil(limit.retryAfter / 60)} min.`,
    });
  }

  const { username, password } = req.body || {};
  if (!username) {
    return res.status(400).json({ error: 'Username required' });
  }

  // Check for bypass mode (dev feature) — allow empty password if bypass
  const isBypass = req.session.bypass === true;
  if (!password && !isBypass) {
    return res.status(400).json({ error: 'Password required' });
  }

  // Sanitise — only allow alphanumeric + underscore + hyphen in username
  if (!/^[a-zA-Z0-9_\-]{1,64}$/.test(username)) {
    return res.status(400).json({ error: 'Invalid username format' });
  }

  try {
    const db = getDb();
    const user = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id, username, password, role, active FROM users WHERE username = ?',
        [username], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    // Check for bypass mode (dev feature)
    const isBypass = req.session.bypass === true;

    // If bypass, allow login as admin
    let userToUse = user;
    if (isBypass) {
      userToUse = { id: 1, username: 'admin', password: '', role: 'admin', active: 1 };
    }

    // Always run bcrypt compare to prevent timing attacks (unless bypass)
    let match = false;
    if (isBypass) {
      match = true; // Bypass password check
    } else {
      const hashToCompare = userToUse ? userToUse.password : '$2a$12$invalidhashfillertostoptimingattacks12345678901';
      match = await bcrypt.compare(password, hashToCompare);
    }

    if (!userToUse || !match || !userToUse.active) {
      recordFail(ip);
      // Log failed attempt
      try {
        await new Promise((resolve, reject) => {
          db.run('INSERT INTO login_log (username, ip, success) VALUES (?, ?, 0)', [username, ip], (err) => {
            if (err) reject(err);
            else resolve();
          });
        });
      } catch (_) {}
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Success — clear rate limit, update last_login, return token
    clearFails(ip);

    if (userToUse.id !== 1 || user) { // Only update if real user
      await new Promise((resolve, reject) => {
        db.run('UPDATE users SET last_login = datetime("now") WHERE id = ?', [userToUse.id], (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    }

    // Log success
    try {
      await new Promise((resolve, reject) => {
        db.run('INSERT INTO login_log (username, ip, success) VALUES (?, ?, 1)', [username, ip], (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    } catch (_) {}

    // Set server-side session
    req.session.userId   = userToUse.id;
    req.session.username = userToUse.username;
    req.session.role     = userToUse.role;
    req.session.loginAt  = Date.now();

    // Force save session before responding
    req.session.save(err => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({ error: 'Session error' });
      }
      return res.json({
        success:  true,
        username: userToUse.username,
        role:     userToUse.role,
        token:    req.session.id,
      });
    });

  } catch (e) {
    console.error('Login error:', e.message);
    return res.status(500).json({ error: 'Server error during login' });
  }
});

// POST /api/auth/bypass — dev feature: enable 10-second auth bypass
router.post('/bypass', (req, res) => {
  req.session.bypass = true;
  // Clear bypass after 10 seconds
  setTimeout(() => {
    if (req.session) req.session.bypass = false;
  }, 10000);
  req.session.save(err => {
    if (err) return res.status(500).json({ error: 'Session error' });
    res.json({ success: true, message: 'Auth bypass enabled for 10 seconds' });
  });
});

// POST /api/auth/check-user — step 1 of reset (no security, just checks username exists)
router.post('/check-user', async (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'Username required' });
  try {
    const db = getDb();
    const row = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id FROM users WHERE username = ? AND active = 1',
        [username], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
    if (!row) return res.status(404).json({ error: 'Username not found' });
    res.json({ exists: true });
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/reset-password — step 2 of reset
router.post('/reset-password', async (req, res) => {
  const { username, newPassword } = req.body || {};
  if (!username || !newPassword) return res.status(400).json({ error: 'Username and new password required' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const db = getDb();
    const hash = await bcrypt.hash(newPassword, 12);
    const result = await new Promise((resolve, reject) => {
      db.run(
        'UPDATE users SET password = ? WHERE username = ? AND active = 1',
        [hash, username], function(err) {
          if (err) reject(err);
          else resolve({ changes: this.changes });
        }
      );
    });
    if (result.changes === 0) return res.status(404).json({ error: 'User not found' });
    // Send notification email if configured
    try { await sendSecEmail('Password Changed', 'Password was changed for user: ' + username); } catch(e) {}
    // Security log
    if (_secEventCb) _secEventCb('PASSWORD_CHANGED', 'user=' + username);
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/request-reset — sends email OTP for secure reset
router.post('/request-reset', async (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'Username required' });
  try {
    const db = getDb();
    const row = await new Promise((resolve, reject) => {
      db.get('SELECT id, username FROM users WHERE username = ? AND active = 1', [username], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
    if (!row) return res.status(404).json({ error: 'User not found' });
    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 10 * 60 * 1000; // 10 min
    // Store OTP in memory (simple — for production use DB)
    otpStore[username] = { otp, expires };
    // Send email
    const sent = await sendSecEmail('BuildDeck Password Reset OTP', 'Your OTP is: ' + otp + '\nExpires in 10 minutes.\n\nIf you did not request this, ignore this email.');
    if (!sent) return res.json({ success: true, emailSent: false, note: 'Email not configured — OTP logged to server console' });
    console.log('[OTP] ' + username + ' OTP: ' + otp);
    res.json({ success: true, emailSent: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/auth/verify-otp
router.post('/verify-otp', async (req, res) => {
  const { username, otp, newPassword } = req.body || {};
  if (!username || !otp || !newPassword) return res.status(400).json({ error: 'Missing fields' });
  const stored = otpStore[username];
  if (!stored || stored.otp !== otp) return res.status(400).json({ error: 'Invalid or expired OTP' });
  if (Date.now() > stored.expires) { delete otpStore[username]; return res.status(400).json({ error: 'OTP expired' }); }
  delete otpStore[username];
  try {
    const db = getDb();
    const hash = await bcrypt.hash(newPassword, 12);
    await new Promise((resolve, reject) => {
      db.run('UPDATE users SET password = ? WHERE username = ?', [hash, username], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/auth/logout
router.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

// GET /api/auth/me — check if logged in
router.get('/me', requireAuth, (req, res) => {
  res.json({
    username: req.session.username,
    role:     req.session.role,
    loginAt:  req.session.loginAt,
  });
});

// GET /api/auth/latest-build — viewer can download latest APK without full auth
router.get('/latest-build', async (req, res) => {
  const buildsDir = require('path').join(__dirname, 'builds');
  const fs = require('fs');
  if (!fs.existsSync(buildsDir)) return res.status(404).json({ error: 'No builds yet' });
  const files = fs.readdirSync(buildsDir)
    .filter(f => f.endsWith('.apk'))
    .map(f => ({ name: f, mtime: fs.statSync(require('path').join(buildsDir, f)).mtime }))
    .sort((a, b) => b.mtime - a.mtime);
  if (!files.length) return res.status(404).json({ error: 'No APK builds available' });
  res.json({ name: files[0].name, downloadUrl: '/api/download/' + files[0].name, date: files[0].mtime });
});

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
// Use this on any route that needs protection
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  // Check client token header as fallback
  const token = req.headers['x-auth-token'];
  if (token && req.session && req.session.id === token) return next();
  return res.status(401).json({ error: 'Not authenticated' });
}

// ── USER MANAGEMENT ROUTES ───────────────────────────────────────────────────

// GET /api/auth/users — list all users (admin only in future, open for now)
router.get('/users', async (req, res) => {
  try {
    const db = getDb();
    const rows = await new Promise((resolve, reject) => {
      db.all(
        'SELECT id, username, role, active, created_at, last_login FROM users ORDER BY id ASC',
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
    res.json(rows);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/auth/users — create user
router.post('/users', async (req, res) => {
  const { username, password, role = 'user' } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (!/^[a-zA-Z0-9_\-]{1,64}$/.test(username)) return res.status(400).json({ error: 'Invalid username format' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });
  if (!['admin','user','viewer'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
  try {
    const db = getDb();
    const hash = await bcrypt.hash(password, 12);
    await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
        [username, hash, role], (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
    res.json({ success: true });
  } catch(e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'Username already exists' });
    res.status(500).json({ error: e.message });
  }
});

// PUT /api/auth/users/:id — update user
router.put('/users/:id', async (req, res) => {
  const { username, password, role, active } = req.body || {};
  const id = parseInt(req.params.id);
  if (!username) return res.status(400).json({ error: 'Username required' });
  if (!['admin','user','viewer'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
  try {
    const db = getDb();
    if (password) {
      if (password.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });
      const hash = await bcrypt.hash(password, 12);
      await new Promise((resolve, reject) => {
        db.run(
          'UPDATE users SET username=?, password=?, role=?, active=? WHERE id=?',
          [username, hash, role, active ? 1 : 0, id], (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });
    } else {
      await new Promise((resolve, reject) => {
        db.run(
          'UPDATE users SET username=?, role=?, active=? WHERE id=?',
          [username, role, active ? 1 : 0, id], (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });
    }
    res.json({ success: true });
  } catch(e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'Username already taken' });
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/auth/users/:id — delete user
router.delete('/users/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const db = getDb();
    // Prevent deleting the last admin
    const adminCount = await new Promise((resolve, reject) => {
      db.get("SELECT COUNT(*) AS cnt FROM users WHERE role='admin' AND active=1", (err, row) => {
        if (err) reject(err);
        else resolve(row.cnt);
      });
    });
    const target = await new Promise((resolve, reject) => {
      db.get("SELECT role FROM users WHERE id=?", [id], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
    if (target && target.role === 'admin' && adminCount <= 1) {
      return res.status(400).json({ error: 'Cannot delete the last admin account' });
    }
    await new Promise((resolve, reject) => {
      db.run('DELETE FROM users WHERE id=?', [id], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = { router, initDb, requireAuth };
