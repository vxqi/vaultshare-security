// Password policy: min length, complexity, and common-password rejection.
// Returns { valid: bool, feedback: string[] } so the UI can show live strength feedback.

const COMMON_PASSWORDS = new Set([
  'password', 'password1', '12345678', 'qwerty123', 'letmein11',
  'welcome123', 'admin1234', 'iloveyou1', 'sunshine1', 'password123',
]);

const MIN_LENGTH = 12;

function checkPasswordStrength(password, { email, displayName } = {}) {
  const feedback = [];

  if (!password || password.length < MIN_LENGTH) {
    feedback.push(`Must be at least ${MIN_LENGTH} characters long.`);
  }
  if (!/[a-z]/.test(password)) feedback.push('Add a lowercase letter.');
  if (!/[A-Z]/.test(password)) feedback.push('Add an uppercase letter.');
  if (!/[0-9]/.test(password)) feedback.push('Add a number.');
  if (!/[^A-Za-z0-9]/.test(password)) feedback.push('Add a special character.');

  const lower = (password || '').toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) {
    feedback.push('This password is too common.');
  }
  if (email && lower.includes(email.split('@')[0].toLowerCase())) {
    feedback.push('Password must not contain your email address.');
  }
  if (displayName && displayName.length > 2 && lower.includes(displayName.toLowerCase())) {
    feedback.push('Password must not contain your name.');
  }

  // Simple entropy-ish score for UI strength meter (0-4)
  let score = 0;
  if (password && password.length >= MIN_LENGTH) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  if (password && password.length >= 16) score = Math.min(4, score + 1);

  return { valid: feedback.length === 0, feedback, score };
}

module.exports = { checkPasswordStrength, MIN_LENGTH };
