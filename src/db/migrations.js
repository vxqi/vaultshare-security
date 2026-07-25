// Lightweight migration runner. schema.sql's CREATE TABLE IF NOT EXISTS only
// helps brand-new databases - it does nothing for columns added to a table
// that already exists on disk. This file adds those columns idempotently, so
// upgrading an existing VaultShare install never requires wiping the DB.
//
// Pattern: each migration checks PRAGMA table_info before altering, so it's
// always safe to re-run.

function columnExists(db, table, column) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  return cols.some((c) => c.name === column);
}

function runMigrations(db) {
  // --- Profile fields (bio, company, website, avatar color) ---
  if (!columnExists(db, 'users', 'bio')) {
    db.exec(`ALTER TABLE users ADD COLUMN bio TEXT`);
  }
  if (!columnExists(db, 'users', 'company_name')) {
    db.exec(`ALTER TABLE users ADD COLUMN company_name TEXT`);
  }
  if (!columnExists(db, 'users', 'website')) {
    db.exec(`ALTER TABLE users ADD COLUMN website TEXT`);
  }
  if (!columnExists(db, 'users', 'avatar_color')) {
    db.exec(`ALTER TABLE users ADD COLUMN avatar_color TEXT DEFAULT '#C9A227'`);
  }

  // --- Profile pictures ---
  if (!columnExists(db, 'users', 'avatar_uuid')) {
    db.exec(`ALTER TABLE users ADD COLUMN avatar_uuid TEXT`);
  }
  if (!columnExists(db, 'users', 'avatar_mime')) {
    db.exec(`ALTER TABLE users ADD COLUMN avatar_mime TEXT`);
  }

  // --- Public/private file visibility ---
  if (!columnExists(db, 'files', 'is_public')) {
    db.exec(`ALTER TABLE files ADD COLUMN is_public INTEGER NOT NULL DEFAULT 0`);
  }

  // --- Folder soft-delete (recycle bin) ---
  if (!columnExists(db, 'folders', 'deleted_at')) {
    db.exec(`ALTER TABLE folders ADD COLUMN deleted_at TEXT`);
  }

  // --- Billing / storage plan ---
  if (!columnExists(db, 'users', 'plan')) {
    db.exec(`ALTER TABLE users ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'`);
  }
  if (!columnExists(db, 'users', 'storage_limit_mb')) {
    db.exec(`ALTER TABLE users ADD COLUMN storage_limit_mb INTEGER NOT NULL DEFAULT 500`);
  }

  // --- Login tracking (feeds the security banner) ---
  if (!columnExists(db, 'users', 'last_login_at')) {
    db.exec(`ALTER TABLE users ADD COLUMN last_login_at TEXT`);
  }
  if (!columnExists(db, 'users', 'last_login_ip')) {
    db.exec(`ALTER TABLE users ADD COLUMN last_login_ip TEXT`);
  }
  if (!columnExists(db, 'users', 'last_login_activity_id')) {
    db.exec(`ALTER TABLE users ADD COLUMN last_login_activity_id INTEGER`);
  }

  // --- New tables (safe to re-run; CREATE TABLE IF NOT EXISTS) ---
  db.exec(`
    CREATE TABLE IF NOT EXISTS ip_allowlist (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      ip_address      TEXT NOT NULL UNIQUE,
      label           TEXT,
      added_by        INTEGER REFERENCES users(id),
      created_at      TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS transactions (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type            TEXT NOT NULL CHECK(type IN ('upgrade','downgrade','refund')),
      amount_cents    INTEGER NOT NULL,
      currency        TEXT NOT NULL DEFAULT 'USD',
      status          TEXT NOT NULL CHECK(status IN ('completed','failed','refunded')) DEFAULT 'completed',
      description     TEXT,
      created_at      TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  db.exec(`CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id)`);
}

module.exports = { runMigrations };