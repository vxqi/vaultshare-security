const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('../db');
const cryptoUtil = require('../utils/crypto');
const activityLog = require('../utils/activityLog');
const { matchesDeclaredType } = require('../utils/fileSignature');

const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || './uploads');

// Allow-list of accepted MIME types. This is deliberately restrictive - a
// document-exchange platform has no legitimate need to accept executables,
// scripts, or HTML (which could be used for stored XSS if ever rendered).
const ALLOWED_MIME_TYPES = new Set([
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'image/png', 'image/jpeg', 'image/webp',
  'text/plain', 'text/csv',
]);

function sanitizeDisplayName(originalName) {
  // Strip path separators and control characters; keep it purely a label.
  const base = path.basename(originalName || 'file');
  return base.replace(/[<>:"/\\|?*\x00-\x1F]/g, '_').slice(0, 255);
}

// Recursively collects a folder's own id plus every descendant folder id,
// scoped to a specific owner (so this can never walk into someone else's
// folder tree even if IDs happen to be adjacent).
function getFolderAndDescendantIds(rootId, ownerId) {
  const rows = db.prepare(`
    WITH RECURSIVE descendants(id) AS (
      SELECT id FROM folders WHERE id = ? AND owner_id = ?
      UNION ALL
      SELECT f.id FROM folders f JOIN descendants d ON f.parent_id = d.id
      WHERE f.owner_id = ?
    )
    SELECT id FROM descendants
  `).all(rootId, ownerId, ownerId);
  return rows.map(r => r.id);
}

async function listDashboard(req, res) {
  const userId = req.session.userId;
  const folderId = req.query.folder ? Number(req.query.folder) : null;

  // If a folder is specified, verify the caller actually owns it (and it
  // isn't sitting in the recycle bin) before using it as a filter.
  let currentFolder = null;
  if (folderId) {
    currentFolder = db.prepare('SELECT * FROM folders WHERE id = ? AND owner_id = ? AND deleted_at IS NULL').get(folderId, userId);
    if (!currentFolder) return res.status(404).render('errors/404', { title: 'Not found' });
  }

  const subfolders = db.prepare(
    `SELECT id, name FROM folders WHERE owner_id = ? AND parent_id IS ? AND deleted_at IS NULL ORDER BY name`
  ).all(userId, folderId);

  const owned = db.prepare(
    `SELECT id, uuid, original_name, mime_type, size_bytes, created_at, is_public
     FROM files WHERE owner_id = ? AND deleted_at IS NULL AND folder_id IS ?
     ORDER BY created_at DESC`
  ).all(userId, folderId);

  const sharedWithMe = db.prepare(
    `SELECT f.id, f.uuid, f.original_name, f.mime_type, f.size_bytes, f.created_at, s.permission, u.display_name AS owner_name, u.id AS owner_id
     FROM shares s
     JOIN files f ON f.id = s.file_id
     JOIN users u ON u.id = f.owner_id
     WHERE s.user_id = ? AND f.deleted_at IS NULL
       AND (s.expires_at IS NULL OR s.expires_at > datetime('now'))
     ORDER BY f.created_at DESC`
  ).all(userId);

  // Breadcrumb trail for nested folders
  const breadcrumbs = [];
  let cursor = currentFolder;
  while (cursor) {
    breadcrumbs.unshift({ id: cursor.id, name: cursor.name });
    cursor = cursor.parent_id ? db.prepare('SELECT * FROM folders WHERE id = ? AND deleted_at IS NULL').get(cursor.parent_id) : null;
  }

  // One-time security alert set at login (see recordLoginAndBuildAlert in
  // authController). Read once, then delete from the session so it never
  // shows again on subsequent page loads within the same session.
  const loginAlert = req.session.loginAlert || null;
  delete req.session.loginAlert;

  res.render('dashboard/index', {
    title: 'Dashboard', owned, sharedWithMe, subfolders, currentFolder, breadcrumbs,
    query: req.query, activeNav: 'dashboard', loginAlert,
  });
}

async function createFolder(req, res) {
  const { name, parentId } = req.body;
  const trimmed = (name || '').trim();
  if (!trimmed) return res.redirect('back');

  let parent = null;
  if (parentId) {
    parent = db.prepare('SELECT * FROM folders WHERE id = ? AND owner_id = ? AND deleted_at IS NULL').get(Number(parentId), req.session.userId);
  }

  db.prepare('INSERT INTO folders (owner_id, name, parent_id) VALUES (?, ?, ?)')
    .run(req.session.userId, trimmed.slice(0, 100), parent ? parent.id : null);

  activityLog.log({ userId: req.session.userId, action: 'folder_create', req, metadata: { name: trimmed } });

  res.redirect(parent ? `/dashboard?folder=${parent.id}` : '/dashboard');
}

// Moves a folder (and everything in its subtree) to the recycle bin. Files
// directly or transitively inside it are soft-deleted too, so they disappear
// from normal browsing and reappear together in the trash view.
async function softDeleteFolder(req, res) {
  const folderId = Number(req.params.id);
  const userId = req.session.userId;
  const folder = db.prepare('SELECT * FROM folders WHERE id = ? AND owner_id = ? AND deleted_at IS NULL').get(folderId, userId);
  if (!folder) return res.status(404).render('errors/404', { title: 'Not found' });

  const ids = getFolderAndDescendantIds(folderId, userId);
  const placeholders = ids.map(() => '?').join(',');

  db.prepare(`UPDATE folders SET deleted_at = datetime('now') WHERE id IN (${placeholders})`).run(...ids);
  db.prepare(`UPDATE files SET deleted_at = datetime('now') WHERE owner_id = ? AND folder_id IN (${placeholders}) AND deleted_at IS NULL`)
    .run(userId, ...ids);

  activityLog.log({ userId, action: 'folder_delete', targetType: 'folder', targetId: folderId, req, metadata: { name: folder.name } });

  res.redirect(folder.parent_id ? `/dashboard?folder=${folder.parent_id}` : '/dashboard');
}

async function restoreFolder(req, res) {
  const folderId = Number(req.params.id);
  const userId = req.session.userId;
  const folder = db.prepare('SELECT * FROM folders WHERE id = ? AND owner_id = ? AND deleted_at IS NOT NULL').get(folderId, userId);
  if (!folder) return res.status(404).render('errors/404', { title: 'Not found' });

  // If the parent folder is gone or still trashed, restore to root instead
  // of leaving the folder restored-but-invisible.
  let parentId = folder.parent_id;
  if (parentId) {
    const parent = db.prepare('SELECT id FROM folders WHERE id = ? AND owner_id = ? AND deleted_at IS NULL').get(parentId, userId);
    if (!parent) parentId = null;
  }

  db.prepare('UPDATE folders SET deleted_at = NULL, parent_id = ? WHERE id = ?').run(parentId, folderId);
  activityLog.log({ userId, action: 'folder_restore', targetType: 'folder', targetId: folderId, req });
  res.redirect('/dashboard/trash');
}

// Permanently deletes a folder row. Any files still pointing at it (there
// normally shouldn't be any active ones - they were soft-deleted alongside
// it) get folder_id set to NULL by the existing foreign key, not deleted.
async function purgeFolder(req, res) {
  const folderId = Number(req.params.id);
  const userId = req.session.userId;
  const folder = db.prepare('SELECT * FROM folders WHERE id = ? AND owner_id = ? AND deleted_at IS NOT NULL').get(folderId, userId);
  if (!folder) return res.status(404).render('errors/404', { title: 'Not found' });

  db.prepare('DELETE FROM folders WHERE id = ?').run(folderId);
  activityLog.log({ userId, action: 'folder_purge', targetType: 'folder', targetId: folderId, req, metadata: { name: folder.name } });
  res.redirect('/dashboard/trash');
}

async function moveFile(req, res) {
  if (req.filePermission !== 'owner') {
    return res.status(403).render('errors/403', { title: 'Access denied' });
  }
  const { folderId } = req.body;
  let folder = null;
  if (folderId) {
    folder = db.prepare('SELECT * FROM folders WHERE id = ? AND owner_id = ? AND deleted_at IS NULL').get(Number(folderId), req.session.userId);
    if (!folder) return res.status(404).render('errors/404', { title: 'Not found' });
  }
  db.prepare('UPDATE files SET folder_id = ? WHERE id = ?').run(folder ? folder.id : null, req.fileRecord.id);
  activityLog.log({ userId: req.session.userId, action: 'file_move', targetType: 'file', targetId: req.fileRecord.id, req });
  res.redirect(folder ? `/dashboard?folder=${folder.id}` : '/dashboard');
}

async function uploadFile(req, res) {
  if (!req.file) {
    return res.status(400).render('files/upload', { title: 'Upload file', error: 'No file selected.', activeNav: 'upload', folders: db.prepare('SELECT id, name FROM folders WHERE owner_id = ? AND deleted_at IS NULL ORDER BY name').all(req.session.userId), selectedFolder: '' });
  }

  if (!ALLOWED_MIME_TYPES.has(req.file.mimetype)) {
    fs.unlink(req.file.path, () => {});
    return res.status(400).render('files/upload', { title: 'Upload file', error: 'File type not allowed.', activeNav: 'upload', folders: db.prepare('SELECT id, name FROM folders WHERE owner_id = ? AND deleted_at IS NULL ORDER BY name').all(req.session.userId), selectedFolder: '' });
  }

  // Read the file once here (reused as plainBuf for the rest of this function).
  const plainBuf = fs.readFileSync(req.file.path);
  fs.unlink(req.file.path, () => {}); // remove multer's temp plaintext copy immediately

  // Verify the declared Content-Type against actual file content. Closes the
  // MIME-spoofing gap identified in pentesting: the allow-list above only
  // checks the client-declared header, which is trivially forgeable.
  if (!matchesDeclaredType(plainBuf, req.file.mimetype)) {
    activityLog.log({
      userId: req.session.userId, action: 'file_upload_rejected_signature_mismatch', req,
      metadata: { declaredType: req.file.mimetype, originalName: req.file.originalname },
    });
    return res.status(400).render('files/upload', {
      title: 'Upload file',
      error: 'This file\'s content does not match its declared type and was rejected.',
      activeNav: 'upload',
      folders: db.prepare('SELECT id, name FROM folders WHERE owner_id = ? AND deleted_at IS NULL ORDER BY name').all(req.session.userId),
      selectedFolder: '',
    });
  }

  // Storage plan enforcement - checked against the user's current plan limit
  // before any encryption/disk work happens, so a rejected upload never
  // leaves a partial file behind.
  const account = db.prepare('SELECT storage_limit_mb, plan FROM users WHERE id = ?').get(req.session.userId);
  const usageBytes = db.prepare(
    `SELECT COALESCE(SUM(size_bytes), 0) AS total FROM files WHERE owner_id = ? AND deleted_at IS NULL`
  ).get(req.session.userId).total;
  const limitBytes = account.storage_limit_mb * 1024 * 1024;

  if (usageBytes + plainBuf.length > limitBytes) {
    return res.status(400).render('files/upload', {
      title: 'Upload file',
      error: `This would exceed your ${account.storage_limit_mb} MB storage limit (${account.plan} plan). Delete some files or upgrade your plan.`,
      activeNav: 'upload',
      folders: db.prepare('SELECT id, name FROM folders WHERE owner_id = ? AND deleted_at IS NULL ORDER BY name').all(req.session.userId),
      selectedFolder: '',
    });
  }

  let targetFolderId = null;
  if (req.body.folderId) {
    const folder = db.prepare('SELECT id FROM folders WHERE id = ? AND owner_id = ? AND deleted_at IS NULL').get(Number(req.body.folderId), req.session.userId);
    if (folder) targetFolderId = folder.id;
  }

  const dek = cryptoUtil.generateFileKey();
  const { ciphertext, iv } = cryptoUtil.encryptBuffer(plainBuf, dek);
  const wrappedKey = cryptoUtil.wrapKey(dek);
  const checksum = cryptoUtil.sha256(plainBuf);

  const fileUuid = crypto.randomUUID();
  const storagePath = path.join(UPLOAD_DIR, fileUuid);
  fs.writeFileSync(storagePath, ciphertext, { mode: 0o600 });

  const displayName = sanitizeDisplayName(req.file.originalname);
  const isPublic = req.body.isPublic === 'on' ? 1 : 0;

  const info = db.prepare(`
    INSERT INTO files (uuid, owner_id, folder_id, original_name, storage_path, mime_type, size_bytes, enc_key_wrapped, enc_iv, checksum_sha256, is_public)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(fileUuid, req.session.userId, targetFolderId, displayName, storagePath, req.file.mimetype, plainBuf.length, wrappedKey, iv, checksum, isPublic);

  activityLog.log({
    userId: req.session.userId, action: 'file_upload', targetType: 'file', targetId: info.lastInsertRowid, req,
    metadata: { name: displayName, size: plainBuf.length, isPublic: !!isPublic },
  });

  res.redirect(targetFolderId ? `/dashboard?folder=${targetFolderId}&uploaded=1` : '/dashboard?uploaded=1');
}

// Assumes req.fileRecord / req.filePermission already set by requireFilePermission middleware.
async function downloadFile(req, res) {
  const file = req.fileRecord;
  const dek = cryptoUtil.unwrapKey(file.enc_key_wrapped);
  const encryptedWithTag = fs.readFileSync(file.storage_path);
  const plainBuf = cryptoUtil.decryptBuffer(encryptedWithTag, dek, file.enc_iv);

  // Integrity check on every read - catches silent disk corruption or tampering.
  const checksum = cryptoUtil.sha256(plainBuf);
  if (checksum !== file.checksum_sha256) {
    activityLog.log({ userId: req.session.userId, action: 'file_integrity_fail', targetType: 'file', targetId: file.id, req });
    return res.status(500).render('errors/500', { title: 'Integrity check failed' });
  }

  activityLog.log({ userId: req.session.userId, action: 'file_download', targetType: 'file', targetId: file.id, req });

  res.setHeader('Content-Type', file.mime_type);
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.original_name)}"`);
  // Prevent the browser from executing/rendering the file inline (defense against stored-content attacks).
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.send(plainBuf);
}

// Owner-only toggle. Public only ever grants read access (see fileAccess.js) -
// this endpoint itself only ever flips a boolean on a file the caller owns,
// nothing else.
async function toggleVisibility(req, res) {
  if (req.filePermission !== 'owner') {
    return res.status(403).render('errors/403', { title: 'Access denied' });
  }
  const newValue = req.fileRecord.is_public ? 0 : 1;
  db.prepare('UPDATE files SET is_public = ? WHERE id = ?').run(newValue, req.fileRecord.id);
  activityLog.log({
    userId: req.session.userId, action: newValue ? 'file_made_public' : 'file_made_private',
    targetType: 'file', targetId: req.fileRecord.id, req,
  });
  res.redirect(`/files/${req.fileRecord.uuid}/share`);
}

async function showShareForm(req, res) {
  const existing = db.prepare(
    `SELECT s.id, s.permission, s.expires_at, u.id AS user_id, u.email, u.display_name
     FROM shares s JOIN users u ON u.id = s.user_id
     WHERE s.file_id = ? ORDER BY s.created_at DESC`
  ).all(req.fileRecord.id);

  res.render('files/share', { title: 'Share file', file: req.fileRecord, existing, error: null });
}

async function createShare(req, res) {
  const { email, permission, expiresInDays } = req.body;
  const file = req.fileRecord;

  if (req.filePermission !== 'owner') {
    return res.status(403).render('errors/403', { title: 'Access denied' });
  }

  const targetUser = db.prepare('SELECT id FROM users WHERE email = ?').get((email || '').toLowerCase().trim());
  if (!targetUser) {
    const existing = db.prepare(
      `SELECT s.id, s.permission, s.expires_at, u.id AS user_id, u.email, u.display_name
       FROM shares s JOIN users u ON u.id = s.user_id WHERE s.file_id = ?`
    ).all(file.id);
    return res.status(400).render('files/share', { title: 'Share file', file, existing, error: 'No user found with that email.' });
  }

  if (targetUser.id === file.owner_id) {
    return res.redirect(`/files/${file.uuid}/share`);
  }

  const perm = permission === 'edit' ? 'edit' : 'view';
  const expiresAt = expiresInDays && Number(expiresInDays) > 0
    ? new Date(Date.now() + Number(expiresInDays) * 86400000).toISOString()
    : null;

  db.prepare(`
    INSERT INTO shares (file_id, user_id, permission, granted_by, expires_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT DO NOTHING
  `).run(file.id, targetUser.id, perm, req.session.userId, expiresAt);

  activityLog.log({
    userId: req.session.userId, action: 'file_share', targetType: 'file', targetId: file.id, req,
    metadata: { sharedWithUserId: targetUser.id, permission: perm },
  });

  res.redirect(`/files/${file.uuid}/share?shared=1`);
}

async function revokeShare(req, res) {
  if (req.filePermission !== 'owner') {
    return res.status(403).render('errors/403', { title: 'Access denied' });
  }
  db.prepare('DELETE FROM shares WHERE id = ? AND file_id = ?').run(req.params.shareId, req.fileRecord.id);
  activityLog.log({ userId: req.session.userId, action: 'file_share_revoke', targetType: 'file', targetId: req.fileRecord.id, req });
  res.redirect(`/files/${req.fileRecord.uuid}/share`);
}

async function deleteFile(req, res) {
  if (req.filePermission !== 'owner') {
    return res.status(403).render('errors/403', { title: 'Access denied' });
  }
  // Soft delete: moves the file into the recycle bin rather than destroying it.
  db.prepare('UPDATE files SET deleted_at = datetime(\'now\') WHERE id = ?').run(req.fileRecord.id);
  activityLog.log({ userId: req.session.userId, action: 'file_delete', targetType: 'file', targetId: req.fileRecord.id, req });
  res.redirect('/dashboard?deleted=1');
}

// --- Recycle bin ---
// Trash actions deliberately do NOT go through requireFilePermission, since
// that middleware only ever resolves files with deleted_at IS NULL (by
// design, for normal browsing). These handlers do their own scoped lookup:
// owner_id must match the caller, full stop. Non-owners get a 404, same as
// everywhere else, so trash contents can't be probed either.

async function showTrash(req, res) {
  const userId = req.session.userId;
  const files = db.prepare(
    `SELECT uuid, original_name, mime_type, size_bytes, deleted_at FROM files
     WHERE owner_id = ? AND deleted_at IS NOT NULL ORDER BY deleted_at DESC`
  ).all(userId);
  const folders = db.prepare(
    `SELECT id, name, deleted_at FROM folders
     WHERE owner_id = ? AND deleted_at IS NOT NULL ORDER BY deleted_at DESC`
  ).all(userId);
  res.render('dashboard/trash', { title: 'Recycle bin', files, folders, activeNav: 'trash' });
}

async function restoreFile(req, res) {
  const userId = req.session.userId;
  const file = db.prepare('SELECT * FROM files WHERE uuid = ? AND owner_id = ? AND deleted_at IS NOT NULL').get(req.params.uuid, userId);
  if (!file) return res.status(404).render('errors/404', { title: 'Not found' });

  // If the file's folder is gone or still trashed, restore to root instead
  // of leaving it restored-but-invisible.
  let folderId = file.folder_id;
  if (folderId) {
    const folder = db.prepare('SELECT id FROM folders WHERE id = ? AND owner_id = ? AND deleted_at IS NULL').get(folderId, userId);
    if (!folder) folderId = null;
  }

  db.prepare('UPDATE files SET deleted_at = NULL, folder_id = ? WHERE id = ?').run(folderId, file.id);
  activityLog.log({ userId, action: 'file_restore', targetType: 'file', targetId: file.id, req });
  res.redirect('/dashboard/trash');
}

// Permanently deletes a file: removes the encrypted blob from disk and the
// DB row. Activity log rows referencing it are left in place (they aren't
// foreign-keyed to files.id) so the audit trail survives even past deletion.
async function purgeFile(req, res) {
  const userId = req.session.userId;
  const file = db.prepare('SELECT * FROM files WHERE uuid = ? AND owner_id = ? AND deleted_at IS NOT NULL').get(req.params.uuid, userId);
  if (!file) return res.status(404).render('errors/404', { title: 'Not found' });

  fs.unlink(file.storage_path, () => {});
  db.prepare('DELETE FROM files WHERE id = ?').run(file.id);
  activityLog.log({ userId, action: 'file_purge', targetType: 'file', targetId: file.id, req, metadata: { name: file.original_name } });
  res.redirect('/dashboard/trash');
}

// Per-file audit trail - who viewed/downloaded/shared this file and when.
// Only the owner can see this (visible via requireFilePermission('owner') on the route).
async function fileActivity(req, res) {
  const events = db.prepare(`
    SELECT a.action, a.created_at, a.ip_address, u.display_name, u.email
    FROM activity_log a
    LEFT JOIN users u ON u.id = a.user_id
    WHERE a.target_type = 'file' AND a.target_id = ?
    ORDER BY a.created_at DESC
    LIMIT 200
  `).all(req.fileRecord.id);

  res.render('files/activity', { title: 'File activity', file: req.fileRecord, events });
}

module.exports = {
  listDashboard, uploadFile, downloadFile,
  showShareForm, createShare, revokeShare, deleteFile,
  createFolder, moveFile, fileActivity, toggleVisibility,
  softDeleteFolder, restoreFolder, purgeFolder,
  showTrash, restoreFile, purgeFile,
};