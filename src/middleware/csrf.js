const { doubleCsrf } = require('csrf-csrf');

const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier: (req) => req.session.id,
  // __Host- prefix requires Secure to always be set, which breaks local HTTP
  // dev. Use the plain name in dev, and switch to the hardened __Host- prefix
  // automatically once running under HTTPS in production.
  cookieName: process.env.NODE_ENV === 'production' ? '__Host-vs.csrf' : 'vs.csrf',
  cookieOptions: {
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    path: '/',
  },
  getCsrfTokenFromRequest: (req) => req.body && req.body._csrf,
  // Multipart/form-data bodies (file uploads) aren't parsed into req.body by
  // the time this global middleware runs - multer parses them later, inside
  // the route itself. So we skip the global check there and apply CSRF
  // protection manually, after multer, in those specific routes.
  skipCsrfProtection: (req) =>
    req.method === 'POST' && ['/files/upload', '/profile/avatar', '/settings/import'].includes(req.path),
});

// Exposes csrfToken() to every EJS view via res.locals, so forms can embed
// a hidden <input name="_csrf"> without every controller wiring it manually.
function exposeCsrfToken(req, res, next) {
  res.locals.csrfToken = generateCsrfToken(req, res);
  next();
}

module.exports = { doubleCsrfProtection, exposeCsrfToken };