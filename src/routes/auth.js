const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const oauthController = require('../controllers/oauthController');
const { requireAuth } = require('../middleware/auth');
const { loginLimiter, registerLimiter } = require('../middleware/rateLimiters');
const importUpload = require('../middleware/importUpload');
const { doubleCsrfProtection } = require('../middleware/csrf');

router.get('/register', authController.showRegister);
router.post('/register', registerLimiter, authController.register);

router.get('/login', authController.showLogin);
router.post('/login', loginLimiter, authController.login);

router.get('/login/mfa', authController.showMfaPrompt);
router.post('/login/mfa', loginLimiter, authController.verifyMfaLogin);

// Google OAuth login. Both routes are GET (a redirect to Google, and the
// redirect Google sends back), so neither is touched by the app's CSRF
// middleware, which only protects state-changing methods by design - the
// `state` + PKCE parameters implemented in oauthController are this flow's
// own equivalent protection. loginLimiter is reused here so an attacker
// hammering the callback endpoint (e.g. trying stale/guessed state values)
// is rate-limited the same way password login attempts are.
router.get('/auth/google', loginLimiter, oauthController.googleRedirect);
router.get('/auth/google/callback', loginLimiter, oauthController.googleCallback);

router.get('/settings/mfa/setup', requireAuth, authController.startMfaSetup);
router.post('/settings/mfa/setup', requireAuth, authController.confirmMfaSetup);
router.post('/settings/mfa/disable', requireAuth, authController.disableMfa);

router.get('/settings', requireAuth, authController.showSettings);
router.post('/settings/password', requireAuth, authController.changePassword);
router.get('/settings/export', requireAuth, authController.exportData);
// CSRF is checked here, after multer parses the multipart body - same
// pattern as the file/avatar upload routes.
router.post('/settings/import', requireAuth, importUpload.single('importFile'), doubleCsrfProtection, authController.importData);

router.post('/logout', requireAuth, authController.logout);

module.exports = router;