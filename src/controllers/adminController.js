const db = require('../db');
const activityLog = require('../utils/activityLog');
const { getClientIp } = require('../utils/clientIp');

const PAGE_SIZE = 25;

async function showUsers(req, res) {
  const search = (req.query.q || '').trim();
  let users;
  if (search) {
    users = db.prepare(
      `SELECT id, email, display_name, role, is_active, mfa_enabled, failed_attempts, locked_until, created_at
       FROM users WHERE email LIKE ? OR display_name LIKE ? ORDER BY created_at DESC`
    ).all(`%${search}%`, `%${search}%`);
  } else {
    users = db.prepare(
      `SELECT id, email, display_name, role, is_active, mfa_enabled, failed_attempts, locked_until, created_at
       FROM users ORDER BY created_at DESC`
    ).all();
  }
  res.render('admin/users', { title: 'User management', users, search, activeNav: 'admin-users' });
}

// Toggles a user's active status. Admins cannot disable their own account
// (would allow accidental total-lockout with no recovery path).
async function toggleUserActive(req, res) {
  const targetId = Number(req.params.id);
  if (targetId === req.session.userId) {
    return res.status(400).render('errors/403', { title: 'Not allowed', message: "You can't disable your own account." });
  }
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(targetId);
  if (!target) return res.status(404).render('errors/404', { title: 'Not found' });

  const newStatus = target.is_active ? 0 : 1;
  db.prepare('UPDATE users SET is_active = ? WHERE id = ?').run(newStatus, targetId);
  activityLog.log({
    userId: req.session.userId, action: newStatus ? 'admin_user_enabled' : 'admin_user_disabled',
    targetType: 'user', targetId, req,
  });
  res.redirect('/admin/users');
}

// Promote/demote role. Least-privilege by default - only exposed to admins,
// and an admin can't demote themselves (avoids locking out the last admin).
async function setUserRole(req, res) {
  const targetId = Number(req.params.id);
  const { role } = req.body;
  if (!['user', 'admin'].includes(role)) {
    return res.status(400).render('errors/403', { title: 'Invalid role' });
  }
  if (targetId === req.session.userId) {
    return res.status(400).render('errors/403', { title: 'Not allowed', message: "You can't change your own role." });
  }
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, targetId);
  activityLog.log({ userId: req.session.userId, action: 'admin_role_change', targetType: 'user', targetId, req, metadata: { newRole: role } });
  res.redirect('/admin/users');
}

async function showActivityLog(req, res) {
  const page = Math.max(1, Number(req.query.page) || 1);
  const actionFilter = req.query.action || '';
  const offset = (page - 1) * PAGE_SIZE;

  let where = '1=1';
  const params = [];
  if (actionFilter) {
    where += ' AND a.action = ?';
    params.push(actionFilter);
  }

  const events = db.prepare(`
    SELECT a.id, a.action, a.target_type, a.target_id, a.ip_address, a.created_at, u.display_name, u.email
    FROM activity_log a
    LEFT JOIN users u ON u.id = a.user_id
    WHERE ${where}
    ORDER BY a.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, PAGE_SIZE, offset);

  const totalRow = db.prepare(`SELECT COUNT(*) AS n FROM activity_log a WHERE ${where}`).get(...params);
  const distinctActions = db.prepare('SELECT DISTINCT action FROM activity_log ORDER BY action').all().map(r => r.action);

  res.render('admin/activity', {
    title: 'System activity log', events, page, actionFilter, distinctActions,
    totalPages: Math.max(1, Math.ceil(totalRow.n / PAGE_SIZE)), activeNav: 'admin-activity',
  });
}

// --- IP allowlist ---

async function showIpAllowlist(req, res) {
  const entries = db.prepare(`
    SELECT a.id, a.ip_address, a.label, a.created_at, u.display_name AS added_by_name
    FROM ip_allowlist a LEFT JOIN users u ON u.id = a.added_by
    ORDER BY a.created_at DESC
  `).all();
  res.render('admin/ip-allowlist', {
    title: 'Admin IP allowlist', entries, currentIp: getClientIp(req), error: null, activeNav: 'admin-ip',
  });
}

async function addIpAllowlistEntry(req, res) {
  const { ipAddress, label } = req.body;
  const trimmed = (ipAddress || '').trim();
  const currentIp = getClientIp(req);

  const renderWithError = (msg) => {
    const entries = db.prepare(`
      SELECT a.id, a.ip_address, a.label, a.created_at, u.display_name AS added_by_name
      FROM ip_allowlist a LEFT JOIN users u ON u.id = a.added_by
      ORDER BY a.created_at DESC
    `).all();
    return res.status(400).render('admin/ip-allowlist', {
      title: 'Admin IP allowlist', entries, currentIp, error: msg, activeNav: 'admin-ip',
    });
  };

  // Very basic sanity check - a full IPv4/IPv6/CIDR parser is out of scope,
  // but this catches empty input and obviously-malformed values.
  if (!trimmed || trimmed.length > 64 || /[^a-fA-F0-9.:/]/.test(trimmed)) {
    return renderWithError('Enter a valid IP address.');
  }

  const existingCount = db.prepare('SELECT COUNT(*) AS n FROM ip_allowlist').get().n;

  // Safety rail: if this would be the FIRST restriction ever applied, and
  // the admin's own current IP isn't included, refuse - otherwise the very
  // next request (loading this same page again) would lock them out with no
  // way back in short of direct DB access.
  if (existingCount === 0 && trimmed !== currentIp) {
    return renderWithError(
      `Your current IP is ${currentIp}. The first entry must include your own address, or you'll lock yourself out immediately.`
    );
  }

  try {
    db.prepare('INSERT INTO ip_allowlist (ip_address, label, added_by) VALUES (?, ?, ?)')
      .run(trimmed, (label || '').trim() || null, req.session.userId);
  } catch {
    return renderWithError('That IP address is already on the list.');
  }

  activityLog.log({ userId: req.session.userId, action: 'admin_ip_allowlist_add', req, metadata: { ip: trimmed } });
  res.redirect('/admin/ip-allowlist');
}

async function removeIpAllowlistEntry(req, res) {
  const entry = db.prepare('SELECT * FROM ip_allowlist WHERE id = ?').get(Number(req.params.id));
  if (!entry) return res.status(404).render('errors/404', { title: 'Not found' });

  db.prepare('DELETE FROM ip_allowlist WHERE id = ?').run(entry.id);
  activityLog.log({ userId: req.session.userId, action: 'admin_ip_allowlist_remove', req, metadata: { ip: entry.ip_address } });
  res.redirect('/admin/ip-allowlist');
}

module.exports = {
  showUsers, toggleUserActive, setUserRole, showActivityLog,
  showIpAllowlist, addIpAllowlistEntry, removeIpAllowlistEntry,
};