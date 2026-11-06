-- Run on your EXISTING remote D1 database; do not rerun schema.sql.
CREATE TABLE IF NOT EXISTS steam_links (
 discord_id TEXT PRIMARY KEY,
 steamid TEXT NOT NULL UNIQUE,
 linked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS join_states (
 state_hash TEXT PRIMARY KEY,
 invite_id TEXT NOT NULL,
 stage TEXT NOT NULL,
 discord_id TEXT,
 expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS join_states_expiry ON join_states(expires_at);
