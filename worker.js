// Votle Worker
// Endpoints:
//   POST /register   { username, password } -> { token }
//   POST /login       { username, password } -> { token }
//   POST /result      (auth) game result payload -> { ok: true }
//   GET  /stats        (auth) -> aggregated stats
//
// Bindings expected:
//   DB    - D1 database (see schema.sql)
//   KV    - KV namespace for session tokens

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

function error(message, status = 400) {
  return json({ error: message }, status);
}

// ---------- Password hashing (PBKDF2-SHA256) ----------

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  let salt;
  if (saltHex) {
    salt = hexToBytes(saltHex);
  } else {
    salt = crypto.getRandomValues(new Uint8Array(16));
  }
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  const hashHex = bytesToHex(new Uint8Array(bits));
  const saltHexOut = bytesToHex(salt);
  return `${saltHexOut}:${hashHex}`;
}

async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const recomputed = await hashPassword(password, saltHex);
  const recomputedHash = recomputed.split(':')[1];
  return timingSafeEqual(recomputedHash, hashHex);
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function generateToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToHex(bytes);
}

// ---------- Auth helper ----------

async function getUserFromRequest(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const match = auth.match(/^Bearer (.+)$/);
  if (!match) return null;
  const token = match[1];
  const username = await env.KV.get(`session:${token}`);
  if (!username) return null;
  const user = await env.DB.prepare('SELECT id, username FROM users WHERE username = ?')
    .bind(username).first();
  return user || null;
}

// ---------- Route handlers ----------

async function handleRegister(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || typeof body.username !== 'string' || typeof body.password !== 'string') {
    return error('Username and password are required.');
  }
  const username = body.username.trim();
  const password = body.password;

  if (username.length < 3 || username.length > 32 || !/^[a-zA-Z0-9_-]+$/.test(username)) {
    return error('Username must be 3-32 characters, letters/numbers/underscore/hyphen only.');
  }
  if (password.length < 6) {
    return error('Password must be at least 6 characters.');
  }

  const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?')
    .bind(username).first();
  if (existing) {
    return error('That username is already taken.', 409);
  }

  const passwordHash = await hashPassword(password);
  await env.DB.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
    .bind(username, passwordHash).run();

  const token = generateToken();
  await env.KV.put(`session:${token}`, username, { expirationTtl: 60 * 60 * 24 * 90 });

  return json({ token, username });
}

async function handleLogin(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || typeof body.username !== 'string' || typeof body.password !== 'string') {
    return error('Username and password are required.');
  }
  const username = body.username.trim();
  const password = body.password;

  const user = await env.DB.prepare('SELECT username, password_hash FROM users WHERE username = ?')
    .bind(username).first();
  if (!user) {
    return error('Invalid username or password.', 401);
  }

  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) {
    return error('Invalid username or password.', 401);
  }

  const token = generateToken();
  await env.KV.put(`session:${token}`, user.username, { expirationTtl: 60 * 60 * 24 * 90 });

  return json({ token, username: user.username });
}

async function handleResult(request, env) {
  const user = await getUserFromRequest(request, env);
  if (!user) return error('Not authenticated.', 401);

  const body = await request.json().catch(() => null);
  if (!body) return error('Invalid payload.');

  const {
    resolutionId, won, accuracy, timeSeconds, guessesUsed, maxGuesses,
    found, total, difficulty, era, topic, hints, date,
  } = body;

  if (
    typeof resolutionId !== 'string' ||
    typeof won !== 'boolean' ||
    typeof accuracy !== 'number' ||
    typeof timeSeconds !== 'number' ||
    typeof guessesUsed !== 'number' ||
    typeof maxGuesses !== 'number' ||
    typeof found !== 'number' ||
    typeof total !== 'number' ||
    typeof difficulty !== 'string' ||
    typeof era !== 'string' ||
    typeof topic !== 'string'
  ) {
    return error('Invalid result payload.');
  }

  await env.DB.prepare(`
    INSERT INTO results
      (user_id, resolution_id, won, accuracy, time_seconds, guesses_used, max_guesses, found, total, difficulty, era, topic, hints, played_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    user.id, resolutionId, won ? 1 : 0, accuracy, timeSeconds, guessesUsed, maxGuesses,
    found, total, difficulty, era, topic, JSON.stringify(hints || []),
    typeof date === 'string' ? date : new Date().toISOString()
  ).run();

  return json({ ok: true });
}

async function handleStats(request, env) {
  const user = await getUserFromRequest(request, env);
  if (!user) return error('Not authenticated.', 401);

  const rows = await env.DB.prepare(`
    SELECT won, accuracy, time_seconds, guesses_used, found, difficulty, era, topic, created_at
    FROM results WHERE user_id = ? ORDER BY created_at ASC
  `).bind(user.id).all();

  const results = rows.results || [];

  if (results.length === 0) {
    return json({ gamesPlayed: 0 });
  }

  const gamesPlayed = results.length;
  const wins = results.filter(r => r.won).length;
  const avgAccuracy = results.reduce((sum, r) => sum + r.accuracy, 0) / gamesPlayed;
  const totalFound = results.reduce((sum, r) => sum + r.found, 0);
  const totalGuesses = results.reduce((sum, r) => sum + r.guesses_used, 0);

  const winTimes = results.filter(r => r.won).map(r => r.time_seconds);
  const fastestTime = winTimes.length ? Math.min(...winTimes) : null;

  // Streaks (chronological order)
  let bestStreak = 0, currentStreak = 0, runningStreak = 0;
  for (const r of results) {
    if (r.won) {
      runningStreak += 1;
      bestStreak = Math.max(bestStreak, runningStreak);
    } else {
      runningStreak = 0;
    }
  }
  currentStreak = runningStreak;

  const byDifficulty = groupBreakdown(results, 'difficulty');
  const byEra = groupBreakdown(results, 'era');
  const byTopic = groupBreakdown(results, 'topic');

  return json({
    gamesPlayed,
    wins,
    avgAccuracy,
    fastestTime,
    bestStreak,
    currentStreak,
    totalFound,
    totalGuesses,
    byDifficulty,
    byEra,
    byTopic,
  });
}

function groupBreakdown(results, key) {
  const groups = {};
  for (const r of results) {
    const k = r[key];
    if (!groups[k]) groups[k] = { played: 0, wins: 0, accuracySum: 0 };
    groups[k].played += 1;
    groups[k].wins += r.won ? 1 : 0;
    groups[k].accuracySum += r.accuracy;
  }
  return Object.entries(groups)
    .map(([value, g]) => ({
      [key]: value,
      played: g.played,
      wins: g.wins,
      avgAccuracy: g.accuracySum / g.played,
    }))
    .sort((a, b) => b.played - a.played);
}

// ---------- Router ----------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    try {
      if (pathname === '/register' && request.method === 'POST') {
        return await handleRegister(request, env);
      }
      if (pathname === '/login' && request.method === 'POST') {
        return await handleLogin(request, env);
      }
      if (pathname === '/result' && request.method === 'POST') {
        return await handleResult(request, env);
      }
      if (pathname === '/stats' && request.method === 'GET') {
        return await handleStats(request, env);
      }
      return error('Not found.', 404);
    } catch (err) {
      return error('Server error: ' + err.message, 500);
    }
  },
};
