const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('../db');
const activityLog = require('../utils/activityLog');

const AVATAR_COLORS = ['#C9A227', '#4FB286', '#5B8DEF', '#D14B4B', '#8B96A5', '#B57EDC'];
const BIO_MAX = 280;
const COMPANY_MAX = 100;

const AVATAR_DIR = path.resolve(process.env.AVATAR_DIR || './uploads/avatars');
fs.mkdirSync(AVATAR_DIR, { recursive: true });

// Avatars are meant to be shown across the app (search results, public
// profiles), so unlike documents they are stored unencrypted - there is no
// confidentiality requirement for a profile picture. They still go through
// the same discipline as document uploads though: strict MIME allow-list,
// random on-disk filename (never the original filename or any user input),
// and a size cap.
const ALLOWED_AVATAR_MIME = new Set(['image/png', 'image/jpeg', 'image/webp']);
const MIME_TO_EXT = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp' };

function isValidHttpUrl(value) {
  if (!value) return true; // optional field
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

async function showOwnProfile(req, res) {
  const user = db.prepare(
    'SELECT id, email, display_name, bio, company_name, website, avatar_color, avatar_uuid, created_at FROM users WHERE id = ?'
  ).get(req.session.userId);
  res.render('profile/edit', { title: 'Your profile', user, error: null, saved: req.query.saved === '1', activeNav: 'profile' });
}

// SECURITY NOTE (mass assignment defense): this handler explicitly destructures
// only the four fields a user is allowed to change. It never does something
// like `UPDATE users SET ? = ?` from a loop over req.body, and it never spreads
// req.body into the SQL params. That means a request body containing extra
// fields - role, email, mfa_enabled, is_active, password_hash, id, whatever -
// is silently ignored rather than accidentally applied. This is the control
// point to point at in a mass-assignment / privilege-escalation pentest finding.
// Avatar upload is handled by a completely separate endpoint (uploadAvatar)
// for the same reason: keep each handler narrow and single-purpose.
async function updateOwnProfile(req, res) {
  const { bio, companyName, website, avatarColor } = req.body;
  const errors = [];

  const trimmedBio = (bio || '').trim();
  const trimmedCompany = (companyName || '').trim();
  const trimmedWebsite = (website || '').trim();

  if (trimmedBio.length > BIO_MAX) errors.push(`Bio must be ${BIO_MAX} characters or fewer.`);
  if (trimmedCompany.length > COMPANY_MAX) errors.push(`Company name must be ${COMPANY_MAX} characters or fewer.`);
  if (!isValidHttpUrl(trimmedWebsite)) errors.push('Website must be a valid http(s) URL.');
  if (!AVATAR_COLORS.includes(avatarColor)) errors.push('Invalid avatar color.');

  if (errors.length) {
    const user = db.prepare(
      'SELECT id, email, display_name, bio, company_name, website, avatar_color, avatar_uuid, created_at FROM users WHERE id = ?'
    ).get(req.session.userId);
    return res.status(400).render('profile/edit', {
      title: 'Your profile',
      user: { ...user, bio: trimmedBio, company_name: trimmedCompany, website: trimmedWebsite, avatar_color: avatarColor },
      error: errors.join(' '), saved: false, activeNav: 'profile',
    });
  }

  db.prepare(`
    UPDATE users SET bio = ?, company_name = ?, website = ?, avatar_color = ? WHERE id = ?
  `).run(trimmedBio || null, trimmedCompany || null, trimmedWebsite || null, avatarColor, req.session.userId);

  activityLog.log({ userId: req.session.userId, action: 'profile_updated', req });

  res.redirect('/profile?saved=1');
}

// Separate, single-purpose endpoint: only ever touches avatar_uuid/avatar_mime
// for the CALLER's own row (req.session.userId, never a body/query param).
async function uploadAvatar(req, res) {
  if (!req.file) {
    return res.redirect('/profile');
  }

  if (!ALLOWED_AVATAR_MIME.has(req.file.mimetype)) {
    fs.unlink(req.file.path, () => {});
    const user = db.prepare(
      'SELECT id, email, display_name, bio, company_name, website, avatar_color, avatar_uuid, created_at FROM users WHERE id = ?'
    ).get(req.session.userId);
    return res.status(400).render('profile/edit', {
      title: 'Your profile', user, error: 'Profile picture must be a PNG, JPEG, or WebP image.', saved: false, activeNav: 'profile',
    });
  }

  const ext = MIME_TO_EXT[req.file.mimetype];
  const avatarUuid = crypto.randomUUID();
  const destPath = path.join(AVATAR_DIR, `${avatarUuid}.${ext}`);
  fs.copyFileSync(req.file.path, destPath);
  fs.unlink(req.file.path, () => {});

  const previous = db.prepare('SELECT avatar_uuid, avatar_mime FROM users WHERE id = ?').get(req.session.userId);

  db.prepare('UPDATE users SET avatar_uuid = ?, avatar_mime = ? WHERE id = ?')
    .run(avatarUuid, req.file.mimetype, req.session.userId);

  // Clean up the old avatar file so they don't accumulate on disk.
  if (previous && previous.avatar_uuid) {
    const oldExt = MIME_TO_EXT[previous.avatar_mime] || 'png';
    fs.unlink(path.join(AVATAR_DIR, `${previous.avatar_uuid}.${oldExt}`), () => {});
  }

  activityLog.log({ userId: req.session.userId, action: 'avatar_updated', req });

  res.redirect('/profile?saved=1');
}

// Streams an avatar image by its UUID. Avatars are looked up in the DB first
// (never trusting the URL param directly as a filesystem path) so this can
// only ever serve a file that's actually registered as someone's avatar.
async function serveAvatar(req, res) {
  const row = db.prepare('SELECT avatar_uuid, avatar_mime FROM users WHERE avatar_uuid = ?').get(req.params.uuid);
  if (!row) return res.status(404).end();

  const ext = MIME_TO_EXT[row.avatar_mime] || 'png';
  const filePath = path.join(AVATAR_DIR, `${row.avatar_uuid}.${ext}`);
  if (!fs.existsSync(filePath)) return res.status(404).end();

  res.setHeader('Content-Type', row.avatar_mime);
  res.setHeader('Cache-Control', 'private, max-age=300');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  fs.createReadStream(filePath).pipe(res);
}

// Search other users by display name or company only - deliberately NOT by
// email, so this can't be used as an email-harvesting/enumeration tool.
// Only active accounts are returned, and only non-sensitive fields.
async function searchUsers(req, res) {
  const q = (req.query.q || '').trim();
  let results = [];
  if (q) {
    results = db.prepare(`
      SELECT id, display_name, company_name, avatar_color, avatar_uuid
      FROM users
      WHERE is_active = 1 AND id != ?
        AND (display_name LIKE ? OR company_name LIKE ?)
      ORDER BY display_name
      LIMIT 30
    `).all(req.session.userId, `%${q}%`, `%${q}%`);
  }
  res.render('users/search', { title: 'Find people', q, results, activeNav: 'search' });
}

// Public-ish profile view: display name, avatar, bio, company, website, and
// the list of files that user has explicitly marked public. This is
// reachable by any authenticated user (via search or a direct link) - it is
// NOT gated on an existing share relationship, since discovery is the point.
// The boundary that matters here is field-level: only ever select/display
// non-sensitive columns, and only ever list files where is_public = 1. Email,
// private files, MFA status, role, etc. are never part of this query.
async function showPublicProfile(req, res) {
  const targetId = Number(req.params.id);
  const viewerId = req.session.userId;

  if (targetId === viewerId) return res.redirect('/profile');

  const target = db.prepare(
    'SELECT id, display_name, bio, company_name, website, avatar_color, avatar_uuid, created_at FROM users WHERE id = ? AND is_active = 1'
  ).get(targetId);

  if (!target) return res.status(404).render('errors/404', { title: 'Not found' });

  const publicFiles = db.prepare(
    `SELECT uuid, original_name, mime_type, size_bytes, created_at
     FROM files WHERE owner_id = ? AND is_public = 1 AND deleted_at IS NULL
     ORDER BY created_at DESC`
  ).all(targetId);

  res.render('profile/public', { title: target.display_name, profileUser: target, publicFiles });
}

module.exports = { showOwnProfile, updateOwnProfile, uploadAvatar, serveAvatar, searchUsers, showPublicProfile };