const multer = require('multer');
const os = require('os');

const MAX_FILE_SIZE_MB = Number(process.env.MAX_FILE_SIZE_MB || 25);

// Files land in a temp dir first; fileController reads, encrypts, writes to
// the real upload store, then immediately deletes this plaintext temp copy.
const upload = multer({
  dest: os.tmpdir(),
  limits: {
    fileSize: MAX_FILE_SIZE_MB * 1024 * 1024,
    files: 1,
  },
});

module.exports = upload;
