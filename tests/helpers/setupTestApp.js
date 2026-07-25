// Spins up a fully isolated VaultShare instance for a test file: its own
// SQLite DB, its own upload/avatar directories, its own in-memory rate
// limiter state (since express-rate-limit's default store is scoped to the
// middleware instance, and we force a fresh require of the whole app below).
// This means test files never interfere with each other, and can be run
// with --runInBand for simple, predictable, serial execution.

const path = require('path');
const fs = require('fs');

let counter = 0;

function createTestApp(name) {
  counter += 1;
  const runId = `${name}-${Date.now()}-${counter}`;
  const tmpRoot = path.join(__dirname, '..', 'tmp', runId);
  const dbPath = path.join(tmpRoot, 'test.db');
  const uploadDir = path.join(tmpRoot, 'uploads');
  const avatarDir = path.join(uploadDir, 'avatars');

  fs.mkdirSync(uploadDir, { recursive: true });
  fs.mkdirSync(avatarDir, { recursive: true });

  process.env.DB_PATH = dbPath;
  process.env.UPLOAD_DIR = uploadDir;
  process.env.AVATAR_DIR = avatarDir;
  process.env.MASTER_KEY = 'a'.repeat(64);
  process.env.SESSION_SECRET = 'b'.repeat(64);
  process.env.CSRF_SECRET = 'c'.repeat(64);
  process.env.NODE_ENV = 'test';
  process.env.MAX_FILE_SIZE_MB = '25';

  // Force every app module to be re-required fresh, so it picks up the env
  // vars set above rather than a previous test file's DB connection.
  Object.keys(require.cache).forEach((key) => {
    if (key.includes(`${path.sep}src${path.sep}`)) delete require.cache[key];
  });

  const app = require('../../src/server');
  // Grab the same (now-cached) db connection the app is using, so cleanup
  // can close it explicitly before trying to delete the file on disk.
  const db = require('../../src/db');
  return { app, db, tmpRoot };
}

// Windows holds an OS-level lock on a SQLite file for as long as the
// connection is open, and will refuse to delete it (EBUSY) even though the
// same pattern works fine on Linux/macOS. Closing the DB connection first
// fixes this on all platforms. Cleanup is best-effort: if the temp directory
// still can't be removed for some reason, we log it instead of failing the
// whole test suite over what is ultimately just leftover scratch data.
function cleanupTestApp(tmpRoot, db) {
  try {
    if (db && typeof db.close === 'function') db.close();
  } catch {
    // already closed or never opened - fine either way
  }

  try {
    fs.rmSync(tmpRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch (err) {
    console.warn(`[test cleanup] could not remove ${tmpRoot}: ${err.message}`);
  }
}

// Pulls the CSRF token out of a rendered page's hidden input, same approach
// used for manual curl testing throughout this project.
function extractCsrf(html) {
  const match = html.match(/name="_csrf" value="([^"]+)"/);
  return match ? match[1] : null;
}

module.exports = { createTestApp, cleanupTestApp, extractCsrf };