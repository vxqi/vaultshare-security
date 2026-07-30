-- VaultShare database schema
-- SQLite. All foreign keys enforced. Sensitive fields (password hash, MFA secret,
-- file encryption keys) are never returned to clients directly.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT NOT NULL UNIQUE,
    -- Never actually NULL, even for OAuth-created accounts: those accounts
    -- get a random, never-disclosed placeholder hash (generated in
    -- oauthController.js) rather than a real password. This keeps this
    -- column's NOT NULL constraint - and every existing password-login code
    -- path - completely unchanged by adding OAuth as a second login method.
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL CHECK(role IN ('user','admin')) DEFAULT 'user',
    display_name    TEXT NOT NULL,
    bio             TEXT,
    company_name    TEXT,
    website         TEXT,
    avatar_color    TEXT DEFAULT '#C9A227',
    avatar_uuid     TEXT,                 -- profile picture, stored unencrypted (not confidential) under random filename
    avatar_mime     TEXT,
    mfa_enabled     INTEGER NOT NULL DEFAULT 0,
    mfa_secret      TEXT,                 -- encrypted at rest by app layer before storage (future), TOTP secret
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,                 -- ISO timestamp; NULL = not locked
    password_changed_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    is_active       INTEGER NOT NULL DEFAULT 1,
    plan            TEXT NOT NULL CHECK(plan IN ('free','pro')) DEFAULT 'free',
    storage_limit_mb INTEGER NOT NULL DEFAULT 500,
    last_login_at   TEXT,
    last_login_ip   TEXT,
    last_login_activity_id INTEGER,
    -- OAuth identity (currently: Google only). NULL/NULL = password-only
    -- account. The partial unique index guaranteeing a given provider
    -- identity maps to only one account is created in migrations.js, since
    -- it must run after the ALTER TABLE that adds these columns to any
    -- database that predates OAuth support.
    oauth_provider  TEXT,
    oauth_id        TEXT
);

-- Password history to prevent reuse
CREATE TABLE IF NOT EXISTS password_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash   TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS folders (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    parent_id       INTEGER REFERENCES folders(id) ON DELETE CASCADE,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    deleted_at      TEXT                      -- soft delete for recycle bin
);

CREATE TABLE IF NOT EXISTS files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid            TEXT NOT NULL UNIQUE,     -- public-facing identifier, never expose raw DB id or path
    owner_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    folder_id       INTEGER REFERENCES folders(id) ON DELETE SET NULL,
    original_name   TEXT NOT NULL,            -- sanitized display name only, never used as disk path
    storage_path    TEXT NOT NULL,            -- path on disk, uses uuid as filename
    mime_type       TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    enc_key_wrapped TEXT NOT NULL,            -- per-file DEK, wrapped (encrypted) with app master key
    enc_iv          TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    is_public       INTEGER NOT NULL DEFAULT 0,  -- explicit opt-in; owner must deliberately make a file public
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    deleted_at      TEXT                      -- soft delete for audit trail integrity / recycle bin
);

-- Per-file / per-folder access control list. Absence of a row = no access.
CREATE TABLE IF NOT EXISTS shares (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id         INTEGER REFERENCES files(id) ON DELETE CASCADE,
    folder_id       INTEGER REFERENCES folders(id) ON DELETE CASCADE,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission      TEXT NOT NULL CHECK(permission IN ('view','edit')) DEFAULT 'view',
    granted_by      INTEGER NOT NULL REFERENCES users(id),
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT,                     -- optional expiry for time-limited access
    CHECK ((file_id IS NOT NULL AND folder_id IS NULL) OR (file_id IS NULL AND folder_id IS NOT NULL))
);

-- One-time / time-limited signed download links (separate from persistent shares)
CREATE TABLE IF NOT EXISTS download_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id         INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,     -- sha256 of the token; raw token never stored
    issued_to       INTEGER NOT NULL REFERENCES users(id),
    expires_at      TEXT NOT NULL,
    used_at         TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS activity_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action          TEXT NOT NULL,            -- e.g. 'login_success','login_fail','file_upload','file_download','file_share','file_delete','mfa_enabled'
    target_type     TEXT,                     -- 'file' | 'folder' | 'user' | 'session'
    target_id       INTEGER,
    ip_address      TEXT,
    user_agent      TEXT,
    metadata        TEXT,                     -- JSON string, never includes file contents/passwords/tokens
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Admin-panel-only IP restriction. Empty table = no restriction (default
-- open), so a fresh deployment never locks its own admin out. Once any row
-- exists, /admin/* is only reachable from a listed address.
CREATE TABLE IF NOT EXISTS ip_allowlist (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address      TEXT NOT NULL UNIQUE,
    label           TEXT,
    added_by        INTEGER REFERENCES users(id),
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Storage-plan transactions (upgrade/downgrade). Simulated payment - no real
-- card data ever touches this app; a production deployment would integrate
-- a PCI-compliant processor (e.g. Stripe) rather than handling payment
-- details directly. This table models the internal side of that flow:
-- an auditable, append-only ledger of what a user was charged and when.
CREATE TABLE IF NOT EXISTS transactions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type            TEXT NOT NULL CHECK(type IN ('upgrade','downgrade','refund')),
    amount_cents    INTEGER NOT NULL,
    currency        TEXT NOT NULL DEFAULT 'USD',
    status          TEXT NOT NULL CHECK(status IN ('completed','failed','refunded')) DEFAULT 'completed',
    description     TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_shares_file_user ON shares(file_id, user_id) WHERE file_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
CREATE INDEX IF NOT EXISTS idx_shares_user ON shares(user_id);
CREATE INDEX IF NOT EXISTS idx_shares_file ON shares(file_id);
CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_log(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_log(created_at);
CREATE INDEX IF NOT EXISTS idx_download_tokens_hash ON download_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id);