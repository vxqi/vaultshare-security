const express = require('express');
const router = express.Router();
const profileController = require('../controllers/profileController');
const { requireAuth } = require('../middleware/auth');
const avatarUpload = require('../middleware/avatarUpload');
const { doubleCsrfProtection } = require('../middleware/csrf');

router.use(requireAuth);

router.get('/profile', profileController.showOwnProfile);
router.post('/profile', profileController.updateOwnProfile);
// CSRF is checked here, after multer parses the multipart body - same
// pattern as the document upload route.
router.post('/profile/avatar', avatarUpload.single('avatar'), doubleCsrfProtection, profileController.uploadAvatar);

router.get('/avatars/:uuid', profileController.serveAvatar);

router.get('/users/search', profileController.searchUsers);
router.get('/users/:id/profile', profileController.showPublicProfile);

module.exports = router;