const crypto = require('crypto');

// The master key wraps (encrypts) each file's unique data-encryption-key (DEK).
// This means compromising the DB alone (wrapped keys + encrypted files) is not
// enough to read file contents - the master key must also be obtained, and in
// production that master key should live in a secrets manager / KMS, not in
// this env var. For coursework purposes it is loaded from .env.
function getMasterKey() {
  const keyHex = process.env.MASTER_KEY;
  if (!keyHex || keyHex.length !== 64) {
    throw new Error('MASTER_KEY must be set in .env as a 64-char hex string (32 bytes). Run `npm run generate-key`.');
  }
  return Buffer.from(keyHex, 'hex');
}

// --- Per-file encryption (AES-256-GCM) ---
// Each file gets its own random Data Encryption Key (DEK). The DEK itself is
// encrypted ("wrapped") with the master key before being stored in the DB, so
// the DB never contains a usable plaintext key.

function generateFileKey() {
  return crypto.randomBytes(32); // 256-bit DEK
}

function wrapKey(dek) {
  const masterKey = getMasterKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
  const wrapped = Buffer.concat([cipher.update(dek), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // store iv + authTag + ciphertext together, base64
  return Buffer.concat([iv, authTag, wrapped]).toString('base64');
}

function unwrapKey(wrappedB64) {
  const masterKey = getMasterKey();
  const buf = Buffer.from(wrappedB64, 'base64');
  const iv = buf.subarray(0, 12);
  const authTag = buf.subarray(12, 28);
  const ciphertext = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function encryptBuffer(plainBuf, dek) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
  const encrypted = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Store authTag appended to ciphertext on disk; iv stored separately in DB.
  return { ciphertext: Buffer.concat([encrypted, authTag]), iv: iv.toString('base64') };
}

function decryptBuffer(encryptedWithTag, dek, ivB64) {
  const iv = Buffer.from(ivB64, 'base64');
  const authTag = encryptedWithTag.subarray(encryptedWithTag.length - 16);
  const ciphertext = encryptedWithTag.subarray(0, encryptedWithTag.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', dek, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// --- Secure random tokens (for download links, etc.) ---
// Raw token is given to the user; only its hash is stored, so a DB leak alone
// cannot be used to forge/replay download links.
function generateSecureToken() {
  const raw = crypto.randomBytes(32).toString('base64url');
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, hash };
}

function hashToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

module.exports = {
  generateFileKey,
  wrapKey,
  unwrapKey,
  encryptBuffer,
  decryptBuffer,
  sha256,
  generateSecureToken,
  hashToken,
};
