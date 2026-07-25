const db = require('../db');

// requireAuth: blocks unauthenticated access. This is deny-by-default -
// routes must opt IN to being public, never opt out of protection.
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    if (req.accepts('html')) {
      return res.redirect('/login');
    }
    return res.status(401).json({ error: 'Authentication required.' });
  }
  // Fully authenticated means: password verified AND (MFA not enabled OR MFA verified this session)
  if (req.session.pendingMfaUserId) {
    return res.redirect('/login/mfa');
  }
  next();
}

// requireRole: least-privilege role gate. Pass one or more allowed roles.
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.session || !req.session.userId) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    if (!allowedRoles.includes(req.session.role)) {
      return res.status(403).render('errors/403', { title: 'Access denied' });
    }
    next();
  };
}

// Attaches current user info to res.locals for views, without ever exposing
// password hash / mfa secret to templates. Avatar/email are looked up fresh
// from the DB on every request (a single indexed primary-key lookup) rather
// than trusted from the session, since both can change mid-session (avatar
// upload, color change) and the session isn't refreshed when they do -
// serving a stale avatar from the session would be a visible, confusing bug.
function attachUser(req, res, next) {
  if (!req.session || !req.session.userId) {
    res.locals.currentUser = null;
    return next();
  }

  const row = db.prepare('SELECT email, avatar_uuid, avatar_color, display_name FROM users WHERE id = ?').get(req.session.userId);

  res.locals.currentUser = {
    id: req.session.userId,
    role: req.session.role,
    displayName: row ? row.display_name : req.session.displayName,
    email: row ? row.email : null,
    avatarUuid: row ? row.avatar_uuid : null,
    avatarColor: row ? row.avatar_color : '#FF7A1A',
  };
  next();
}

module.exports = { requireAuth, requireRole, attachUser };