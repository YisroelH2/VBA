-- Tracks failed password-login attempts for basic brute-force lockout
-- (single-user app: id is always 1, mirrors the `meta` singleton pattern).
CREATE TABLE IF NOT EXISTS login_attempts (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  fail_count INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO login_attempts (id, fail_count, locked_until) VALUES (1, 0, 0);
