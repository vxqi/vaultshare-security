const multer = require('multer');
const os = require('os');

// Export files are metadata-only JSON, so they're small - this is generous
// enough for even a very active account's export while still blocking
// anything absurd being uploaded to this endpoint.
const MAX_IMPORT_SIZE_MB = 2;

const importUpload = multer({
  dest: os.tmpdir(),
  limits: {
    fileSize: MAX_IMPORT_SIZE_MB * 1024 * 1024,
    files: 1,
  },
});

module.exports = importUpload;