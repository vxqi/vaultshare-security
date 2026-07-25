const db = require('../db');
const { getClientIp } = require('../utils/clientIp');

// Restricts /admin/* to a configured set of IP addresses. An EMPTY allowlist
// means no restriction is active - this is deliberate: a fresh deployment,
// or an admin who hasn't configured this yet, must never be locked out by
// default. The restriction only takes effect once at least one address has
// been explicitly added.
function requireAllowedAdminIp(req, res, next) {
  const count = db.prepare('SELECT COUNT(*) AS n FROM ip_allowlist').get().n;
  if (count === 0) return next(); // no restriction configured

  const ip = getClientIp(req);
  const match = db.prepare('SELECT 1 FROM ip_allowlist WHERE ip_address = ?').get(ip);

  if (!match) {
    return res.status(403).render('errors/403', {
      title: 'Access restricted',
      message: 'The admin panel is restricted to specific IP addresses, and yours is not on the list.',
    });
  }

  next();
}

module.exports = { requireAllowedAdminIp };