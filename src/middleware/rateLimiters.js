const rateLimit = require('express-rate-limit');

// IP-based throttle on login attempts. This is a *second, independent* layer
// of brute-force defense on top of the per-account lockout in authController -
// an attacker spraying many different usernames from one IP is still stopped
// even if no single account crosses its own lockout threshold.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts from this address. Try again later.' },
  skipSuccessfulRequests: true,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many accounts created from this address. Try again later.' },
});

// Applies to any endpoint that reveals whether an email/account exists
// (password reset request, etc.) to slow down enumeration.
const enumerationSensitiveLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Try again later.' },
});

// General API-wide throttle as defense in depth.
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});

const downloadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many download requests. Slow down.' },
});

module.exports = {
  loginLimiter,
  registerLimiter,
  enumerationSensitiveLimiter,
  globalLimiter,
  downloadLimiter,
};
