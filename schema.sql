-- Votle D1 schema

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  resolution_id TEXT NOT NULL,
  won INTEGER NOT NULL,
  accuracy INTEGER NOT NULL,
  time_seconds INTEGER NOT NULL,
  guesses_used INTEGER NOT NULL,
  max_guesses INTEGER NOT NULL,
  found INTEGER NOT NULL,
  total INTEGER NOT NULL,
  difficulty TEXT NOT NULL,
  era TEXT NOT NULL,
  topic TEXT NOT NULL,
  hints TEXT NOT NULL DEFAULT '[]',
  played_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_results_user ON results(user_id);
CREATE INDEX IF NOT EXISTS idx_results_user_created ON results(user_id, created_at);
