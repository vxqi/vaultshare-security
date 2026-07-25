const db = require('../db');
const { getClientIp } = require('./clientIp');

const insertStmt = db.prepare(`
  INSERT INTO activity_log (user_id, action, target_type, target_id, ip_address, user_agent, metadata)
  VALUES (@user_id, @action, @target_type, @target_id, @ip_address, @user_agent, @metadata)
`);

// Fields that must NEVER end up in metadata, even by accident from a caller.
const FORBIDDEN_KEYS = new Set(['password', 'password_hash', 'mfa_secret', 'token', 'raw_token', 'file_contents']);

function log({ userId = null, action, targetType = null, targetId = null, req = null, metadata = {} }) {
  const safeMetadata = {};
  for (const [k, v] of Object.entries(metadata || {})) {
    if (!FORBIDDEN_KEYS.has(k)) safeMetadata[k] = v;
  }

  // Returns the insert result (has .lastInsertRowid) so callers that need a
  // monotonic reference point - e.g. "how many login failures happened
  // after THIS login" - can use an ID comparison instead of a timestamp
  // comparison. SQLite's datetime('now') is only second-precision, which is
  // too coarse when several events happen within the same second (routine
  // in automated testing, and plausible in a real rapid attack sequence).
  return insertStmt.run({
    user_id: userId,
    action,
    target_type: targetType,
    target_id: targetId,
    ip_address: req ? getClientIp(req) : null,
    user_agent: req ? req.headers['user-agent'] || null : null,
    metadata: Object.keys(safeMetadata).length ? JSON.stringify(safeMetadata) : null,
  });
}

module.exports = { log };