const db = require('../db');

// Looks up a file by its public UUID (never by raw incrementing DB id in URLs)
// and determines the caller's effective permission on it: 'owner' | 'edit' | 'view' | null.
// This is the single choke point every file route must pass through - it is
// deliberately NOT duplicated per-route, so a fix here fixes IDOR everywhere.
//
// Permission is resolved in order: owner > explicit share > public flag.
// A file being public only ever grants 'view' - it can never grant 'edit' or
// 'owner', and the owner must have explicitly opted in via is_public=1. There
// is no way to reach 'view' on someone else's file except through one of
// these two documented paths.
function getFileForUser(fileUuid, userId) {
  const file = db.prepare(
    `SELECT * FROM files WHERE uuid = ? AND deleted_at IS NULL`
  ).get(fileUuid);

  if (!file) return { file: null, permission: null };

  if (file.owner_id === userId) {
    return { file, permission: 'owner' };
  }

  const share = db.prepare(
    `SELECT permission, expires_at FROM shares
     WHERE file_id = ? AND user_id = ?
     ORDER BY permission = 'edit' DESC LIMIT 1`
  ).get(file.id, userId);

  if (share && (!share.expires_at || new Date(share.expires_at) >= new Date())) {
    return { file, permission: share.permission };
  }

  if (file.is_public) {
    return { file, permission: 'view' };
  }

  return { file, permission: null };
}

// Express middleware: requires at least `minPermission` on req.params.uuid.
// Attaches req.fileRecord and req.filePermission for downstream handlers.
function requireFilePermission(minPermission) {
  const rank = { view: 1, edit: 2, owner: 3 };
  return (req, res, next) => {
    const { file, permission } = getFileForUser(req.params.uuid, req.session.userId);

    if (!file || !permission || rank[permission] < rank[minPermission]) {
      // Deliberately return 404, not 403, for files the user has zero access to.
      // A 403 would confirm the file exists, leaking information via IDOR probing.
      return res.status(404).render('errors/404', { title: 'Not found' });
    }

    req.fileRecord = file;
    req.filePermission = permission;
    next();
  };
}

module.exports = { getFileForUser, requireFilePermission };