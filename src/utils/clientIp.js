// Single source of truth for "what is this request's IP address". Used by
// activity logging and the admin IP allowlist, so both agree on the same
// value - inconsistent IP extraction between an access-control check and
// its audit log is a classic source of confusing bugs.
//
// SECURITY: this deliberately uses Express's req.ip rather than reading
// X-Forwarded-For directly. req.ip is proxy-aware: it only trusts
// X-Forwarded-For up to the number of hops configured via `app.set('trust
// proxy', N)` in server.js, and falls back to the raw socket address
// otherwise. Reading the header directly (as an earlier version of this
// function did) let any client set X-Forwarded-For to an arbitrary value
// and have it accepted at face value - trivially bypassing (or triggering)
// the admin IP allowlist by spoofing a single request header. This was
// caught during manual testing of the allowlist feature and fixed here.
function getClientIp(req) {
  return req.ip || req.socket.remoteAddress || '';
}

module.exports = { getClientIp };