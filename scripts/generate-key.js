// Generates a cryptographically secure 256-bit master key for MASTER_KEY in .env
// Usage: node scripts/generate-key.js
const crypto = require('crypto');
console.log(crypto.randomBytes(32).toString('hex'));
