-- Run once on the existing D1 database. Do not rerun schema.sql.
CREATE TABLE IF NOT EXISTS invitations (
 id TEXT PRIMARY KEY,
 discord_id TEXT NOT NULL,
 steamid TEXT NOT NULL,
 nickname TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS invitations_discord_status ON invitations(discord_id,status);
CREATE INDEX IF NOT EXISTS invitations_steamid_status ON invitations(steamid,status);
