const multer = require('multer');
const os = require('os');

// Profile pictures are much smaller than documents and image-only.
const MAX_AVATAR_SIZE_MB = 3;

const avatarUpload = multer({
  dest: os.tmpdir(),
  limits: {
    fileSize: MAX_AVATAR_SIZE_MB * 1024 * 1024,
    files: 1,
  },
});

module.exports = avatarUpload;