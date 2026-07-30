const crypto = require('crypto');
const argon2 = require('argon2');
const db = require('../db');
const activityLog = require('../utils/activityLog');
const {
  getUserByEmail, recordLoginAndBuildAlert, establishSession, ARGON2_OPTIONS,
} = require('./authController');
const {
  generateState, generatePkcePair, buildGoogleAuthUrl, exchangeCodeForTokens, fetchGoogleUserInfo,
} = require('../utils/oauthGoogle');

// Generous enough for a real human to complete a login, short enough to
// limit the window in which a stale/captured state value could be replayed.
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;

function sanitizeDisplayName(name, emailFallback) {
  const trimmed = (name || '').trim();
  if (trimmed.length >= 1) return trimmed.slice(0, 100);
  return (emailFallback || 'User').split('@')[0].slice(0, 100);
}

// Step 1: redirect the browser to Google's consent screen.
// Uses PKCE (S256) + a random `state` value, both bound to this session and
// checked on the way back in googleCallback. `state` is this flow's CSRF
// defense - it stops an attacker from tricking a victim's browser into
// completing a *different* person's OAuth flow (a known "login CSRF"
// pattern), the OAuth-flow equivalent of the double-submit CSRF token used
// elsewhere in the app for state-changing form POSTs.
async function googleRedirect(req, res) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const callbackUrl = process.env.GOOGLE_CALLBACK_URL;

  if (!clientId || !clientSecret || !callbackUrl) {
    console.error('Google OAuth is not configured (missing GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_CALLBACK_URL).');
    return res.redirect('/login?oauth_error=failed');
  }

  const state = generateState();
  const { codeVerifier, codeChallenge } = generatePkcePair();

  req.session.oauthState = state;
  req.session.oauthCodeVerifier = codeVerifier;
  req.session.oauthStateCreatedAt = Date.now();

  const authUrl = buildGoogleAuthUrl({ clientId, redirectUri: callbackUrl, state, codeChallenge });
  res.redirect(authUrl);
}

// Step 2: Google redirects back here with ?code=...&state=... (or
// ?error=... if the user cancelled on Google's side).
async function googleCallback(req, res) {
  const { code, state, error: googleError } = req.query;

  const expectedState = req.session.oauthState;
  const codeVerifier = req.session.oauthCodeVerifier;
  const stateCreatedAt = req.session.oauthStateCreatedAt || 0;

  // Single-use regardless of outcome - a state/verifier pair is never valid
  // for a second callback attempt.
  delete req.session.oauthState;
  delete req.session.oauthCodeVerifier;
  delete req.session.oauthStateCreatedAt;

  if (googleError) {
    activityLog.log({ userId: null, action: 'oauth_denied', req, metadata: { provider: 'google', error: googleError } });
    return res.redirect('/login?oauth_error=denied');
  }

  if (!code || !state || !expectedState || !codeVerifier) {
    activityLog.log({ userId: null, action: 'oauth_state_mismatch', req, metadata: { provider: 'google' } });
    return res.redirect('/login?oauth_error=state_mismatch');
  }

  if (Date.now() - stateCreatedAt > OAUTH_STATE_TTL_MS) {
    activityLog.log({ userId: null, action: 'oauth_state_expired', req, metadata: { provider: 'google' } });
    return res.redirect('/login?oauth_error=expired');
  }

  const stateMatches = state.length === expectedState.length
    && crypto.timingSafeEqual(Buffer.from(state), Buffer.from(expectedState));

  if (!stateMatches) {
    activityLog.log({ userId: null, action: 'oauth_state_mismatch', req, metadata: { provider: 'google' } });
    return res.redirect('/login?oauth_error=state_mismatch');
  }

  let tokens;
  let profile;
  try {
    tokens = await exchangeCodeForTokens({
      code,
      codeVerifier,
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      redirectUri: process.env.GOOGLE_CALLBACK_URL,
    });
    profile = await fetchGoogleUserInfo(tokens.access_token);
  } catch (err) {
    console.error('Google OAuth token exchange/userinfo failed:', err.message);
    activityLog.log({ userId: null, action: 'oauth_provider_error', req, metadata: { provider: 'google' } });
    return res.redirect('/login?oauth_error=failed');
  }

  // Google's own email_verified flag is the trust anchor here: this login
  // is only treated as proof of ownership of that email address if Google
  // itself has verified it. Without this check, someone could add an
  // unverified email alias to their Google account and use it to try to
  // access or link a VaultShare account that isn't theirs.
  if (!profile.email_verified) {
    activityLog.log({ userId: null, action: 'oauth_email_unverified', req, metadata: { provider: 'google', email: profile.email } });
    return res.redirect('/login?oauth_error=unverified_email');
  }

  const normalizedEmail = (profile.email || '').toLowerCase().trim();

  let user = db.prepare('SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ?').get('google', profile.sub);

  if (!user) {
    const existingByEmail = getUserByEmail(normalizedEmail);

    if (existingByEmail && existingByEmail.oauth_provider && existingByEmail.oauth_provider !== 'google') {
      // Extremely unlikely in practice (there's only one provider wired up
      // today), but fail closed rather than silently overwrite an existing
      // linked identity.
      activityLog.log({ userId: existingByEmail.id, action: 'oauth_provider_conflict', req, metadata: { attemptedProvider: 'google' } });
      return res.redirect('/login?oauth_error=conflict');
    }

    if (existingByEmail) {
      // Link this Google identity to the existing password-based account.
      // Deliberate design decision, documented here and in the report: we
      // trust Google's verified-email flag as sufficient proof to link,
      // rather than also requiring the user to re-enter their existing
      // VaultShare password first. This keeps the flow to one click, at the
      // cost of relying on Google's verification instead of an in-app
      // confirmation step - a trade-off worth discussing rather than
      // hiding, and one a stricter deployment could tighten by requiring
      // password re-entry before linking.
      db.prepare('UPDATE users SET oauth_provider = ?, oauth_id = ? WHERE id = ?')
        .run('google', profile.sub, existingByEmail.id);
      user = { ...existingByEmail, oauth_provider: 'google', oauth_id: profile.sub };
      activityLog.log({ userId: user.id, action: 'oauth_account_linked', req, metadata: { provider: 'google' } });
    } else {
      // Brand new account via Google. password_hash is set to a random,
      // never-disclosed value (never NULL - the users table's existing
      // NOT NULL constraint and the password-login path both keep working
      // completely unchanged). This account simply can never produce a
      // matching password unless the user later sets one explicitly via
      // the normal change-password flow. Avoids a risky SQLite table
      // rebuild that dropping the NOT NULL constraint would otherwise need.
      const randomPlaceholder = crypto.randomBytes(32).toString('hex');
      const placeholderHash = await argon2.hash(randomPlaceholder, ARGON2_OPTIONS);

      // Same bootstrap-admin pattern used by password registration.
      const adminCount = db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").get().n;
      const role = adminCount === 0 ? 'admin' : 'user';
      const displayName = sanitizeDisplayName(profile.name, normalizedEmail);

      const info = db.prepare(`
        INSERT INTO users (email, password_hash, role, display_name, oauth_provider, oauth_id)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(normalizedEmail, placeholderHash, role, displayName, 'google', profile.sub);

      user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
      activityLog.log({ userId: user.id, action: 'account_created_oauth', req, metadata: { provider: 'google', role } });
    }
  }

  if (!user.is_active) {
    activityLog.log({ userId: user.id, action: 'oauth_login_blocked_disabled', req });
    return res.redirect('/login?oauth_error=disabled');
  }

  // Same lockout check as password login - proving identity via Google does
  // not bypass a lockout triggered by earlier failed password attempts.
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    activityLog.log({ userId: user.id, action: 'oauth_login_blocked_locked', req });
    return res.redirect('/login?oauth_error=locked');
  }

  // Same MFA gate as password login: proving identity via Google does not
  // skip a second factor the account owner explicitly enabled. This reuses
  // the exact existing /login/mfa flow untouched - no new MFA code path is
  // introduced by adding OAuth.
  if (user.mfa_enabled) {
    req.session.pendingMfaUserId = user.id;
    activityLog.log({ userId: user.id, action: 'oauth_password_ok_awaiting_mfa', req, metadata: { provider: 'google' } });
    return res.redirect('/login/mfa');
  }

  establishSession(req, res, user, 'login_success_oauth');
}

module.exports = { googleRedirect, googleCallback };