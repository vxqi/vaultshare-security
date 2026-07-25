const fs = require('fs');
const argon2 = require('argon2');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const db = require('../db');
const { checkPasswordStrength } = require('../utils/passwordPolicy');
const activityLog = require('../utils/activityLog');
const { getClientIp } = require('../utils/clientIp');

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

// Argon2id: current OWASP-recommended password hashing algorithm, resistant
// to both GPU cracking (memory-hard) and side-channel timing attacks.
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456, // 19 MiB, OWASP minimum recommendation
  timeCost: 2,
  parallelism: 1,
};

function getUserByEmail(email) {
  return db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
}

// Called at the moment a login succeeds. Compares this login's IP/failed-
// attempt history against what was recorded at the PREVIOUS login, builds a
// one-time alert if anything looks worth flagging, stashes it in the
// session for the next page render (dashboard reads and clears it), then
// updates the login-tracking columns for next time. This is the "real-time"
// half of monitoring/alerting: the person sees it the moment it's relevant,
// not buried in a page they'd have to think to go check.
//
// This function performs the login_success activity log entry itself
// (rather than the caller doing it separately) because it needs that row's
// own id immediately afterward: failed-attempt counting uses an ID
// comparison (activity_log.id > last_login_activity_id) rather than a
// timestamp comparison, since SQLite's datetime('now') is only
// second-precision and multiple events routinely land in the same second.
function recordLoginAndBuildAlert(req, user, action) {
  const previousActivityId = user.last_login_activity_id || 0;
  const previousLoginIp = user.last_login_ip;
  const currentIp = getClientIp(req);

  const failedSincePrevious = db.prepare(
    `SELECT COUNT(*) AS n FROM activity_log WHERE user_id = ? AND action = 'login_fail' AND id > ?`
  ).get(user.id, previousActivityId).n;

  const ipChanged = previousLoginIp && previousLoginIp !== currentIp;

  if (failedSincePrevious > 0 || ipChanged) {
    req.session.loginAlert = {
      failedSincePrevious,
      ipChanged,
      previousLoginAt: user.last_login_at,
      previousLoginIp,
    };
  }

  const info = activityLog.log({ userId: user.id, action, req });

  db.prepare('UPDATE users SET last_login_at = datetime(\'now\'), last_login_ip = ?, last_login_activity_id = ? WHERE id = ?')
    .run(currentIp, info.lastInsertRowid, user.id);
}

// --- Registration ---
async function showRegister(req, res) {
  res.render('auth/register', { title: 'Create account', errors: [], values: {} });
}

async function register(req, res) {
  const { email, password, confirmPassword, displayName } = req.body;
  const errors = [];

  const normalizedEmail = (email || '').toLowerCase().trim();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!emailRegex.test(normalizedEmail)) errors.push('Enter a valid email address.');
  if (!displayName || displayName.trim().length < 2) errors.push('Display name is required.');
  if (password !== confirmPassword) errors.push('Passwords do not match.');

  const strength = checkPasswordStrength(password, { email: normalizedEmail, displayName });
  if (!strength.valid) errors.push(...strength.feedback);

  if (getUserByEmail(normalizedEmail)) {
    // Generic message - do not reveal that this specific email is already registered.
    errors.push('Unable to create account with the provided details.');
  }

  if (errors.length) {
    return res.status(400).render('auth/register', {
      title: 'Create account',
      errors,
      values: { email: normalizedEmail, displayName },
    });
  }

  const passwordHash = await argon2.hash(password, ARGON2_OPTIONS);

  // Bootstrap pattern: the very first account created on a fresh deployment
  // becomes admin automatically, so there's always someone able to manage
  // the system without needing direct DB access. Once any admin exists, this
  // path never triggers again for subsequent registrations.
  const adminCount = db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").get().n;
  const role = adminCount === 0 ? 'admin' : 'user';

  const info = db.prepare(`
    INSERT INTO users (email, password_hash, role, display_name)
    VALUES (?, ?, ?, ?)
  `).run(normalizedEmail, passwordHash, role, displayName.trim());

  db.prepare('INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)')
    .run(info.lastInsertRowid, passwordHash);

  activityLog.log({ userId: info.lastInsertRowid, action: 'account_created', req, metadata: { role } });

  res.redirect('/login?registered=1');
}

// --- Login (step 1: password) ---
async function showLogin(req, res) {
  res.render('auth/login', { title: 'Log in', error: null, registered: req.query.registered === '1' });
}

async function login(req, res) {
  const { email, password } = req.body;
  const user = getUserByEmail(email || '');
  const genericError = 'Invalid email or password.';

  // Constant-shape response: whether the user exists or not, we still do a
  // hash comparison (against a dummy hash if needed) so response timing
  // doesn't leak account existence.
  const dummyHash = '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$ZmFrZWhhc2hmb3JkdW1teWNvbXBhcmU';

  if (user && user.locked_until && new Date(user.locked_until) > new Date()) {
    activityLog.log({ userId: user.id, action: 'login_blocked_locked', req });
    return res.status(423).render('auth/login', {
      title: 'Log in',
      error: `Account temporarily locked due to failed attempts. Try again after ${new Date(user.locked_until).toLocaleTimeString()}.`,
      registered: false,
    });
  }

  const hashToCheck = user ? user.password_hash : dummyHash;
  let valid = false;
  try {
    valid = await argon2.verify(hashToCheck, password || '');
  } catch {
    valid = false;
  }

  if (!user || !valid) {
    if (user) {
      const attempts = user.failed_attempts + 1;
      let lockedUntil = null;
      if (attempts >= MAX_FAILED_ATTEMPTS) {
        lockedUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000).toISOString();
      }
      db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?')
        .run(attempts, lockedUntil, user.id);
      activityLog.log({ userId: user.id, action: 'login_fail', req, metadata: { attempts } });
    }
    return res.status(401).render('auth/login', { title: 'Log in', error: genericError, registered: false });
  }

  if (!user.is_active) {
    return res.status(403).render('auth/login', { title: 'Log in', error: 'Account disabled. Contact support.', registered: false });
  }

  // Reset lockout counters on successful password verification.
  db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?').run(user.id);

  if (user.mfa_enabled) {
    req.session.pendingMfaUserId = user.id;
    activityLog.log({ userId: user.id, action: 'login_password_ok_awaiting_mfa', req });
    return res.redirect('/login/mfa');
  }

  req.session.regenerate((err) => {
    if (err) return res.status(500).render('errors/500', { title: 'Error' });
    req.session.userId = user.id;
    req.session.role = user.role;
    req.session.displayName = user.display_name;
    recordLoginAndBuildAlert(req, user, 'login_success');
    res.redirect('/dashboard');
  });
}

// --- MFA verification (step 2) ---
async function showMfaPrompt(req, res) {
  if (!req.session.pendingMfaUserId) return res.redirect('/login');
  res.render('auth/mfa-verify', { title: 'Two-factor verification', error: null });
}

async function verifyMfaLogin(req, res) {
  const userId = req.session.pendingMfaUserId;
  if (!userId) return res.redirect('/login');

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  const { token } = req.body;

  const verified = user && user.mfa_secret && speakeasy.totp.verify({
    secret: user.mfa_secret,
    encoding: 'base32',
    token: (token || '').trim(),
    window: 1, // allow ±30s clock drift
  });

  if (!verified) {
    activityLog.log({ userId: user.id, action: 'mfa_fail', req });
    return res.status(401).render('auth/mfa-verify', { title: 'Two-factor verification', error: 'Invalid code.' });
  }

  delete req.session.pendingMfaUserId;
  req.session.regenerate((err) => {
    if (err) return res.status(500).render('errors/500', { title: 'Error' });
    req.session.userId = user.id;
    req.session.role = user.role;
    req.session.displayName = user.display_name;
    recordLoginAndBuildAlert(req, user, 'login_success_mfa');
    res.redirect('/dashboard');
  });
}

// --- MFA enrollment (from account settings, requires already logged in) ---
async function startMfaSetup(req, res) {
  const secret = speakeasy.generateSecret({ name: `VaultShare (${res.locals.currentUser.displayName})` });
  req.session.pendingMfaSecret = secret.base32;
  const qrDataUrl = await qrcode.toDataURL(secret.otpauth_url);
  res.render('dashboard/mfa-setup', { title: 'Set up two-factor authentication', qrDataUrl, secret: secret.base32, error: null, activeNav: 'settings' });
}

async function confirmMfaSetup(req, res) {
  const { token } = req.body;
  const pendingSecret = req.session.pendingMfaSecret;
  if (!pendingSecret) return res.redirect('/settings/mfa/setup');

  const verified = speakeasy.totp.verify({
    secret: pendingSecret,
    encoding: 'base32',
    token: (token || '').trim(),
    window: 1,
  });

  if (!verified) {
    const qrDataUrl = await qrcode.toDataURL(
      speakeasy.otpauthURL({ secret: pendingSecret, encoding: 'base32', label: 'VaultShare' })
    );
    return res.status(400).render('dashboard/mfa-setup', {
      title: 'Set up two-factor authentication', qrDataUrl, secret: pendingSecret, error: 'Invalid code, try again.', activeNav: 'settings',
    });
  }

  db.prepare('UPDATE users SET mfa_enabled = 1, mfa_secret = ? WHERE id = ?')
    .run(pendingSecret, req.session.userId);
  delete req.session.pendingMfaSecret;
  activityLog.log({ userId: req.session.userId, action: 'mfa_enabled', req });
  res.redirect('/settings?mfa=enabled');
}

async function disableMfa(req, res) {
  db.prepare('UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?').run(req.session.userId);
  activityLog.log({ userId: req.session.userId, action: 'mfa_disabled', req });
  res.redirect('/settings?mfa=disabled');
}

// --- Logout ---
function logout(req, res) {
  const userId = req.session.userId;
  activityLog.log({ userId, action: 'logout', req });
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
}

const PASSWORD_HISTORY_DEPTH = 5;

async function showSettings(req, res) {
  const user = db.prepare('SELECT id, email, display_name, mfa_enabled, created_at, last_login_at, last_login_ip FROM users WHERE id = ?').get(req.session.userId);

  // Recent security-relevant events for this account, for the Settings
  // "Security" panel. This is the lightweight, no-email-infrastructure
  // version of "real-time monitoring and alerting": the information is
  // computed fresh on every page load and shown immediately, rather than
  // pushed out asynchronously.
  const securityEvents = db.prepare(`
    SELECT action, ip_address, created_at FROM activity_log
    WHERE user_id = ? AND action IN ('login_success','login_success_mfa','login_fail','login_blocked_locked','password_changed','mfa_enabled','mfa_disabled')
    ORDER BY created_at DESC LIMIT 10
  `).all(req.session.userId);

  res.render('dashboard/settings', {
    title: 'Settings', user, passwordError: null, passwordSuccess: req.query.pwd === 'changed', activeNav: 'settings',
    securityEvents,
  });
}

async function changePassword(req, res) {
  const { currentPassword, newPassword, confirmNewPassword } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

  const renderWithError = (msg) => res.status(400).render('dashboard/settings', {
    title: 'Settings',
    user: { id: user.id, email: user.email, display_name: user.display_name, mfa_enabled: user.mfa_enabled, created_at: user.created_at },
    passwordError: msg, passwordSuccess: false, activeNav: 'settings',
  });

  const currentValid = await argon2.verify(user.password_hash, currentPassword || '').catch(() => false);
  if (!currentValid) {
    activityLog.log({ userId: user.id, action: 'password_change_fail_current_wrong', req });
    return renderWithError('Current password is incorrect.');
  }

  if (newPassword !== confirmNewPassword) return renderWithError('New passwords do not match.');

  const strength = checkPasswordStrength(newPassword, { email: user.email, displayName: user.display_name });
  if (!strength.valid) return renderWithError(strength.feedback.join(' '));

  // Reuse prevention: check the new password against the last N stored hashes.
  const history = db.prepare(
    'SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?'
  ).all(user.id, PASSWORD_HISTORY_DEPTH);

  for (const row of history) {
    if (await argon2.verify(row.password_hash, newPassword).catch(() => false)) {
      return renderWithError(`You can't reuse any of your last ${PASSWORD_HISTORY_DEPTH} passwords.`);
    }
  }

  const newHash = await argon2.hash(newPassword, ARGON2_OPTIONS);
  db.prepare('UPDATE users SET password_hash = ?, password_changed_at = datetime(\'now\') WHERE id = ?').run(newHash, user.id);
  db.prepare('INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)').run(user.id, newHash);
  // Trim history so it doesn't grow unbounded
  db.prepare(`
    DELETE FROM password_history WHERE user_id = ? AND id NOT IN (
      SELECT id FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?
    )
  `).run(user.id, user.id, PASSWORD_HISTORY_DEPTH);

  activityLog.log({ userId: user.id, action: 'password_changed', req });

  // Regenerate session on credential change - invalidates session fixation risk.
  req.session.regenerate((err) => {
    if (err) return res.status(500).render('errors/500', { title: 'Error' });
    req.session.userId = user.id;
    req.session.role = user.role;
    req.session.displayName = user.display_name;
    res.redirect('/settings?pwd=changed');
  });
}

// Data export: lets a user download their own metadata and activity history
// as JSON (privacy/portability principle). Never includes file contents,
// other users' data, or security secrets (password hash, MFA secret).
async function exportData(req, res) {
  const userId = req.session.userId;
  const user = db.prepare('SELECT id, email, display_name, bio, company_name, website, created_at FROM users WHERE id = ?').get(userId);
  const folders = db.prepare('SELECT id, name, parent_id FROM folders WHERE owner_id = ? AND deleted_at IS NULL ORDER BY id').all(userId);
  const files = db.prepare('SELECT uuid, original_name, mime_type, size_bytes, folder_id, is_public, created_at FROM files WHERE owner_id = ? AND deleted_at IS NULL').all(userId);
  const shares = db.prepare(`
    SELECT f.uuid AS file_uuid, f.original_name, s.permission, s.created_at, s.expires_at
    FROM shares s JOIN files f ON f.id = s.file_id WHERE s.user_id = ?
  `).all(userId);
  const activity = db.prepare('SELECT action, target_type, target_id, created_at FROM activity_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 500').all(userId);

  // export_version lets the importer refuse a file from an incompatible
  // future/past format instead of guessing at its shape.
  const exportPayload = {
    export_version: 1,
    exported_at: new Date().toISOString(),
    account: user,
    folders,
    files_owned: files,
    files_shared_with_me: shares,
    recent_activity: activity,
  };

  activityLog.log({ userId, action: 'data_export', req });

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="vaultshare-export.json"');
  res.send(JSON.stringify(exportPayload, null, 2));
}

// Data import: the counterpart to exportData. Restores profile fields and
// recreates folder names from a previously exported JSON file.
//
// SECURITY NOTES:
// 1. Mass assignment defense: exactly like updateOwnProfile, this only ever
//    reads three specific fields out of the uploaded JSON's `account` object
//    (bio, company_name, website) and re-validates them with the same rules
//    as the normal profile form. A crafted import file containing
//    `"account": {"role":"admin","id":1}` has those fields silently ignored -
//    there is no code path that writes anything from the uploaded file
//    directly into a SQL statement's column list.
// 2. Folders are imported FLAT (no parent_id honored from the file). The
//    export includes each folder's OLD numeric id/parent_id, but those are
//    meaningless in the context of the importing account - trusting them
//    as real foreign keys would let a crafted import file try to nest a new
//    folder under an arbitrary folder ID that might belong to someone else.
//    Recreating everything at root level sidesteps that entirely.
// 3. File contents are never part of export or import - only metadata. This
//    is disclosed to the user, not left implicit.
async function importData(req, res) {
  const renderSettings = (error, success) => {
    const user = db.prepare('SELECT id, email, display_name, mfa_enabled, created_at FROM users WHERE id = ?').get(req.session.userId);
    return res.render('dashboard/settings', {
      title: 'Settings', user, passwordError: null, passwordSuccess: false,
      activeNav: 'settings', importError: error, importSuccess: success,
    });
  };

  if (!req.file) {
    return renderSettings('No file selected.', null);
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(req.file.path, 'utf8'));
  } catch {
    fs.unlink(req.file.path, () => {});
    return renderSettings('That file is not valid JSON.', null);
  }
  fs.unlink(req.file.path, () => {});

  if (!parsed || parsed.export_version !== 1 || typeof parsed !== 'object') {
    return renderSettings('Unrecognized export format. Only VaultShare export files (version 1) are supported.', null);
  }

  const account = parsed.account && typeof parsed.account === 'object' ? parsed.account : {};
  const bio = typeof account.bio === 'string' ? account.bio.trim().slice(0, 280) : null;
  const companyName = typeof account.company_name === 'string' ? account.company_name.trim().slice(0, 100) : null;
  const website = typeof account.website === 'string' ? account.website.trim() : null;

  if (website) {
    try {
      const u = new URL(website);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        return renderSettings('Imported website URL is invalid; import cancelled.', null);
      }
    } catch {
      return renderSettings('Imported website URL is invalid; import cancelled.', null);
    }
  }

  db.prepare(`
    UPDATE users SET
      bio = COALESCE(?, bio),
      company_name = COALESCE(?, company_name),
      website = COALESCE(?, website)
    WHERE id = ?
  `).run(bio, companyName, website, req.session.userId);

  let foldersCreated = 0;
  if (Array.isArray(parsed.folders)) {
    const existing = new Set(
      db.prepare('SELECT LOWER(name) AS n FROM folders WHERE owner_id = ? AND deleted_at IS NULL').all(req.session.userId).map(r => r.n)
    );
    const insertFolder = db.prepare('INSERT INTO folders (owner_id, name, parent_id) VALUES (?, ?, NULL)');
    for (const f of parsed.folders.slice(0, 200)) {
      const name = typeof f?.name === 'string' ? f.name.trim().slice(0, 100) : '';
      if (!name || existing.has(name.toLowerCase())) continue;
      insertFolder.run(req.session.userId, name);
      existing.add(name.toLowerCase());
      foldersCreated += 1;
    }
  }

  activityLog.log({ userId: req.session.userId, action: 'data_import', req, metadata: { foldersCreated } });

  return renderSettings(null, `Import complete. Profile fields updated, ${foldersCreated} folder(s) created. File contents are never included in export/import - only metadata.`);
}

module.exports = {
  showRegister, register,
  showLogin, login,
  showMfaPrompt, verifyMfaLogin,
  startMfaSetup, confirmMfaSetup, disableMfa,
  logout,
  showSettings, changePassword, exportData, importData,
};