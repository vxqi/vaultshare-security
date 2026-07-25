const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');
const { runMigrations } = require('./migrations');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', '..', 'data', 'vaultshare.db');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Apply schema idempotently on startup
const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
db.exec(schema);

// Apply any column-level migrations for databases created before this version.
runMigrations(db);

module.exports = db;