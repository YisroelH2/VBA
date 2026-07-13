-- Singleton row holding the app-level scalars (single-user app: id is always 1)
CREATE TABLE IF NOT EXISTS meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  balance REAL NOT NULL DEFAULT 0,
  maaser_owed REAL NOT NULL DEFAULT 0,
  maaser_ever_paid INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO meta (id, balance, maaser_owed, maaser_ever_paid) VALUES (1, 0, 0, 0);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY,
  type TEXT NOT NULL,
  desc TEXT NOT NULL,
  amount REAL NOT NULL,
  delta REAL NOT NULL,
  date TEXT NOT NULL,
  balance_after REAL NOT NULL,
  maaser INTEGER NOT NULL DEFAULT 0,
  maaser_amt REAL NOT NULL DEFAULT 0,
  category TEXT,
  synced_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- investments/loans/pending have flexible, evolving shapes client-side;
-- stored as JSON blobs keyed by the client-generated id rather than
-- guessing at a rigid column set.
CREATE TABLE IF NOT EXISTS investments (
  id INTEGER PRIMARY KEY,
  data TEXT NOT NULL,
  synced_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS loans (
  id INTEGER PRIMARY KEY,
  data TEXT NOT NULL,
  synced_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pending (
  id INTEGER PRIMARY KEY,
  data TEXT NOT NULL,
  synced_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS authenticators (
  credential_id TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  user_id TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  device_name TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Short-lived WebAuthn challenges, bridging /register-options -> /register-verify
-- and /login-options -> /login-verify. Rows are deleted once consumed or expired.
CREATE TABLE IF NOT EXISTS auth_challenges (
  id TEXT PRIMARY KEY,
  challenge TEXT NOT NULL,
  user_id TEXT NOT NULL,
  type TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
