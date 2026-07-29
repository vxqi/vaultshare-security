// Verifies that uploaded file bytes actually match the claimed MIME type,
// using magic-number (file signature) checks rather than trusting the
// client-supplied Content-Type header alone. This closes a gap identified
// during penetration testing: a client can declare any Content-Type it
// wants in a multipart upload, and the declared value was previously
// trusted without verification (see the pentest report for the finding).
//
// For MIME types with a well-defined binary signature (images, PDF, Office
// documents), this checks the actual leading bytes. For plain-text types
// (text/plain, text/csv), there is no true magic number - valid text can
// legitimately be almost any printable content - so instead this applies a
// lightweight heuristic: genuine text files essentially never contain a NUL
// byte in their first few KB, while binary content (images, executables,
// etc.) commonly does. This isn't a full content classifier, but it does
// catch the realistic case of someone uploading a binary file disguised as
// text/plain to slip past the MIME allow-list.

const SIGNATURES = {
  'image/png': [[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]],
  'image/jpeg': [[0xFF, 0xD8, 0xFF]],
  'application/pdf': [[0x25, 0x50, 0x44, 0x46]], // %PDF
  // .docx / .xlsx are ZIP containers under the hood
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [[0x50, 0x4B, 0x03, 0x04]],
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': [[0x50, 0x4B, 0x03, 0x04]],
  // Legacy .doc / .xls (OLE2 compound file format)
  'application/msword': [[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]],
  'application/vnd.ms-excel': [[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]],
};

function bufferStartsWith(buffer, sig) {
  if (buffer.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) {
    if (buffer[i] !== sig[i]) return false;
  }
  return true;
}

function matchesDeclaredType(buffer, mimeType) {
  if (mimeType === 'image/webp') {
    // RIFF....WEBP: "RIFF" at bytes 0-3, "WEBP" at bytes 8-11.
    if (buffer.length < 12) return false;
    return buffer.subarray(0, 4).toString('ascii') === 'RIFF'
      && buffer.subarray(8, 12).toString('ascii') === 'WEBP';
  }

  const sigs = SIGNATURES[mimeType];
  if (sigs) {
    return sigs.some((sig) => bufferStartsWith(buffer, sig));
  }

  if (mimeType === 'text/plain' || mimeType === 'text/csv') {
    const sample = buffer.subarray(0, 8192);
    return !sample.includes(0x00);
  }

  // Unrecognized type reaching here (shouldn't happen given the callers'
  // allow-lists) - fail closed rather than assume it's fine.
  return false;
}

module.exports = { matchesDeclaredType };