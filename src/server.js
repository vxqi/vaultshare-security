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

const app = express();
const isProd = process.env.NODE_ENV === 'production';

// Trust first proxy only (needed for correct req.ip / secure cookies behind a reverse proxy in prod).
app.set('trust proxy', 1);

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
    sameSite: 'strict',      // strong CSRF baseline defense; double-submit CSRF is the primary layer
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

// --- Error handling ---
app.use((req, res) => {
  res.status(404).render('errors/404', { title: 'Not found' });
});

app.use((err, req, res, next) => {
  if (err.code === 'ERR_BAD_CSRF_TOKEN' || err.message === 'invalid csrf token') {
    return res.status(403).render('errors/403', { title: 'Request blocked', message: 'Invalid or missing security token. Please refresh and try again.' });
  }
  if (err.code === 'LIMIT_FILE_SIZE') {
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