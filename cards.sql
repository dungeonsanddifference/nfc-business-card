PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS cards (
  uid_hex      TEXT PRIMARY KEY,          -- e.g., 041041994f6180
  url          TEXT NOT NULL,             -- written to the tag
  label        TEXT,                      -- optional: “Batch 1”, “Blue card”
  distributed_to TEXT,                    -- fill in later
  distributed_on DATE,                    -- fill in later
  created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS taps (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  uid_hex     TEXT NOT NULL,
  ts          DATETIME DEFAULT CURRENT_TIMESTAMP,
  ip          TEXT,
  user_agent  TEXT,
  referer     TEXT,
  FOREIGN KEY(uid_hex) REFERENCES cards(uid_hex)
);

CREATE INDEX IF NOT EXISTS idx_taps_uid_ts ON taps(uid_hex, ts DESC);