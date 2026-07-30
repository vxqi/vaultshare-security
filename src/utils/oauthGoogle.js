const crypto = require('crypto');

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_USERINFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo';
const GOOGLE_SCOPE = 'openid email profile';

function generateState() {
  return crypto.randomBytes(32).toString('base64url');
}

// PKCE (RFC 7636): code_verifier is a high-entropy random string that never
// leaves the server+browser pair that started this login. code_challenge
// (its SHA-256 hash) is what actually gets sent to Google up front. On the
// token exchange, Google checks that the code_verifier we present hashes to
// the code_challenge we registered - so even if an authorization `code`
// were somehow intercepted in transit (e.g. via a referrer leak or a nosy
// browser extension), it's useless to an attacker without the verifier,
// which only ever existed server-side in this session.
function generatePkcePair() {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge };
}

function buildGoogleAuthUrl({ clientId, redirectUri, state, codeChallenge }) {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: GOOGLE_SCOPE,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    access_type: 'online', // login-only; we never call Google's APIs again later, so no refresh_token is needed
    prompt: 'select_account',
  });
  return `${GOOGLE_AUTH_URL}?${params.toString()}`;
}

async function exchangeCodeForTokens({ code, codeVerifier, clientId, clientSecret, redirectUri }) {
  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code,
    code_verifier: codeVerifier,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
  });

  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`Google token exchange failed (${response.status}): ${text}`);
  }

  return response.json();
}

// Deliberately does NOT parse/verify the id_token JWT ourselves - doing that
// correctly requires fetching and caching Google's rotating public keys
// (JWKS) and defending against algorithm-confusion attacks (e.g. an
// attacker sending alg: "none", or swapping RS256 for HS256 and signing
// with the public key as if it were an HMAC secret) - a well-known
// real-world vulnerability class when JWT verification is hand-rolled.
// Instead, this calls Google's userinfo endpoint directly using the
// access_token as a bearer credential. That's trustworthy because the
// access_token was only ever obtainable by presenting our own registered
// client_secret over HTTPS during the token exchange above - it isn't a
// bare token an attacker could forge or replay against a step we haven't
// already protected with state + PKCE.
async function fetchGoogleUserInfo(accessToken) {
  const response = await fetch(GOOGLE_USERINFO_URL, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`Google userinfo request failed (${response.status}): ${text}`);
  }

  const data = await response.json();
  return {
    sub: data.sub,
    email: data.email,
    email_verified: data.email_verified === true || data.email_verified === 'true',
    name: data.name,
    picture: data.picture,
  };
}

module.exports = {
  generateState, generatePkcePair, buildGoogleAuthUrl, exchangeCodeForTokens, fetchGoogleUserInfo,
};