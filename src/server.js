require('dotenv').config();
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const expressLayouts = require('express-ejs-layouts');
const SqliteStore = require('better-sqlite3-session-store')(session);

const db = require('./db');
const { attachUser } = require('./middleware/auth');
const { globalLimiter } = require('./middleware/rateLimiters');
const { doubleCsrfProtection, exposeCsrfToken } = require('./middleware/csrf');

const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const fileRoutes = require('./routes/files');
const adminRoutes = require('./routes/admin');
const profileRoutes = require('./routes/profile');
const billingRoutes = require('./routes/billing');

const app = express();
const isProd = process.env.NODE_ENV === 'production';

// Trust proxy configuration: how many reverse-proxy hops (nginx, a load
// balancer, etc.) sit in front of this app in the current deployment. This
// must match reality exactly:
//   - 0 (default): no reverse proxy - trust nothing from X-Forwarded-For,
//     always use the raw socket address. This is the SAFE default for local
//     dev and any deployment where the app is reached directly.
//   - 1: exactly one reverse proxy in front, which itself sets/overwrites
//     X-Forwarded-For (never passes through a client-supplied value
//     unmodified). Only set this when that's actually true - setting it to
//     1 without a real proxy in front lets any direct client spoof their
//     apparent IP by simply sending their own X-Forwarded-For header, which
//     would defeat the admin IP allowlist and pollute activity log IPs.
// See src/utils/clientIp.js for where this setting is consumed.
app.set('trust proxy', Number(process.env.TRUST_PROXY_HOPS || 0));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'partials/layout');

// --- Security headers ---
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // inline styles only; no inline scripts allowed
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"], // clickjacking defense
      baseUri: ["'self'"],
      formAction: ["'self'"],
    },
  },
  referrerPolicy: { policy: 'no-referrer' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
}));

app.use(globalLimiter);
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// --- Session (server-side store; cookie only carries an opaque session ID) ---
app.use(session({
  store: new SqliteStore({ client: db, expired: { clear: true, intervalMs: 15 * 60 * 1000 } }),
  name: 'vs.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true, // sliding expiration - active users stay logged in, idle ones expire
  cookie: {
    httpOnly: true,
    secure: isProd,          // HTTPS-only cookie in production
    // 'lax', not 'strict': Strict cookies are withheld on ANY cross-site
    // request, including a top-level browser redirect - which is exactly
    // what happens when Google redirects the browser back to
    // /auth/google/callback after login. With Strict, that callback request
    // arrives with no session cookie at all, so the state value stored in
    // step 1 is unreachable and every OAuth login fails as "state_mismatch"
    // even on a completely legitimate attempt. Lax still blocks the cookie
    // on cross-site state-changing requests (POST etc.), so the CSRF
    // posture is effectively unchanged - state-changing routes remain
    // covered by the double-submit CSRF middleware regardless of this
    // setting, and the OAuth callback has its own independent CSRF/replay
    // defense via the state+PKCE check. Strict vs Lax here was never really
    // part of that defense-in-depth story; it was an unrelated setting that
    // happened to collide with any redirect-based third-party login flow.
    sameSite: 'lax',
    maxAge: 30 * 60 * 1000,  // 30 min idle timeout
  },
}));

app.use(attachUser);

// Force session persistence from the very first request, even before login.
// Without this, an unauthenticated session is never saved (saveUninitialized:
// false), so its ID changes on every request - which breaks CSRF validation,
// since the CSRF token is bound to the session ID.
app.use((req, res, next) => {
  if (!req.session.initialized) {
    req.session.initialized = true;
  }
  next();
});

// CSRF protection applies to all state-changing requests. GETs remain exempt
// by the library's default (safe methods aren't protected), which is correct
// since GET must never mutate state in this app.
app.use(exposeCsrfToken);
app.use(doubleCsrfProtection);

// --- Routes ---
app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('marketing/landing', { title: 'Secure document exchange' });
});
app.use('/', authRoutes);
app.use('/', profileRoutes);
app.use('/dashboard', dashboardRoutes);
app.use('/files', fileRoutes);
app.use('/admin', adminRoutes);
app.use('/billing', billingRoutes);

// --- Error handling ---
app.use((req, res) => {
  res.status(404).render('errors/404', { title: 'Not found' });
});

app.use((err, req, res, next) => {
  if (err.code === 'ERR_BAD_CSRF_TOKEN' || err.message === 'invalid csrf token') {
    return res.status(403).render('errors/403', { title: 'Request blocked', message: 'Invalid or missing security token. Please refresh and try again.' });
  }
  if (err.code === 'LIMIT_FILE_SIZE') {
    if (req.path === '/settings/import') {
      const user = req.session && req.session.userId
        ? db.prepare('SELECT id, email, display_name, mfa_enabled, created_at, last_login_at, last_login_ip FROM users WHERE id = ?').get(req.session.userId)
        : null;
      return res.status(413).render('dashboard/settings', {
        title: 'Settings', user, passwordError: null, passwordSuccess: false, activeNav: 'settings',
        securityEvents: [], importError: 'That file is too large.', importSuccess: null,
      });
    }
    const folders = req.session && req.session.userId
      ? db.prepare('SELECT id, name FROM folders WHERE owner_id = ? ORDER BY name').all(req.session.userId)
      : [];
    return res.status(413).render('files/upload', { title: 'Upload file', error: 'File is too large.', activeNav: 'upload', folders, selectedFolder: '' });
  }
  console.error(err); // Full error is logged server-side only, never sent to the client.
  res.status(500).render('errors/500', { title: 'Something went wrong' });
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`VaultShare running on http://localhost:${PORT}`));
}

module.exports = app;