# VaultShare

A secure document-exchange platform for freelancers and their clients. Owners upload
deliverables/contracts and share them with specific people under granular,
time-limited permissions. Built as a security-first coursework project — see
[Security Architecture](#security-architecture) below for what's implemented and why.

## Quick start (local)

```bash
npm install
node scripts/generate-key.js   # copy the output into .env as MASTER_KEY
cp .env.example .env           # then fill in MASTER_KEY, SESSION_SECRET, CSRF_SECRET
node src/server.js
```

Visit http://localhost:3000

To generate the two random secrets quickly:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Quick start (Docker)

```bash
cp .env.example .env   # fill in secrets as above
docker compose up --build
```

## Project structure

```
src/
  db/            SQLite schema + connection
  controllers/   Route handler logic (auth, files)
  middleware/    auth/RBAC, CSRF, rate limiting, file ACL, upload handling
  routes/        Express route definitions
  utils/         crypto (encryption), password policy, activity logging
  views/         EJS templates
scripts/         One-off ops scripts (key generation)
```

## Security architecture

**Authentication**
- Argon2id password hashing (OWASP-recommended parameters)
- Password policy: 12+ chars, mixed case, number, symbol, common-password and
  email/name-reuse rejection, with live strength feedback
- TOTP-based MFA (speakeasy + QR enrollment), enforced as a second login step
- Per-account lockout after 5 failed attempts (15 min), independent of the
  IP-based rate limiter on the login route (defense in depth against both
  targeted and distributed brute-force)
- Login response timing/shape is constant regardless of whether the account
  exists, to resist user enumeration

**Session management**
- Server-side session store (SQLite), cookie carries only an opaque ID
- `httpOnly`, `SameSite=Strict`, `Secure` in production
- Session ID regenerated on every privilege change (login, MFA completion)
- Sliding 30-minute idle expiry

**CSRF**
- Double-submit cookie pattern (`csrf-csrf`), token bound to session ID
- Applies to all state-changing (non-GET) requests

**Access control (RBAC + object-level ACL)**
- Every file has an owner; access for anyone else is governed by an explicit
  `shares` row (`view` or `edit`), optionally time-limited
- All file routes go through a single `requireFilePermission` middleware —
  one choke point, so an IDOR fix there fixes it everywhere
- Files with zero access return **404**, not 403, so probing UUIDs can't be
  used to enumerate which files exist

**Encryption**
- Each file gets a random 256-bit AES-GCM data key; the key itself is wrapped
  with a separate master key before being stored, so a DB leak alone doesn't
  expose file contents
- SHA-256 checksum verified on every read (detects tampering/corruption)
- Files stored under random UUIDs, never original filenames, with `600` perms

**Upload safety**
- MIME-type allow-list (documents, images, plain text/CSV only — no
  executables, scripts, or HTML)
- Size-limited, single temp copy deleted immediately after encryption

**Activity logging**
- Every login attempt, MFA event, upload, download, share, and delete is
  logged with actor, IP, user agent, and timestamp
- A deny-list prevents passwords/tokens/secrets from ever landing in log
  metadata, even by an accidental caller mistake

**Other hardening**
- `helmet` security headers (CSP, no-referrer, frame-ancestors 'none', etc.)
- IP-based rate limiting on login, registration, and downloads
- Docker: non-root user, read-only root filesystem, dropped capabilities

## What's not yet built

This is a foundation, not the finished coursework submission. Still needed:
- Admin role/panel (currently `role` supports `admin` in the schema but no
  admin UI exists yet)
- Activity log viewer / audit UI
- Automated tests (unit + integration)
- Formal internal penetration test write-up (this app is the *target*, not
  the test itself — testing happens separately per your coursework brief)
- CI currently runs `npm audit`, a security-focused ESLint pass, a secret
  scan, and a smoke boot test — extend with real unit/integration tests once
  written
