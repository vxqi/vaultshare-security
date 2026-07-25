const express = require('express');
const router = express.Router();
const fileController = require('../controllers/fileController');
const { requireAuth } = require('../middleware/auth');
const { requireFilePermission } = require('../middleware/fileAccess');
const { downloadLimiter } = require('../middleware/rateLimiters');
const upload = require('../middleware/upload');
const { doubleCsrfProtection } = require('../middleware/csrf');

router.use(requireAuth);

router.get('/upload', (req, res) => {
  const db = require('../db');
  const folders = db.prepare('SELECT id, name FROM folders WHERE owner_id = ? AND deleted_at IS NULL ORDER BY name').all(req.session.userId);
  res.render('files/upload', { title: 'Upload file', error: null, activeNav: 'upload', folders, selectedFolder: req.query.folder || '' });
});
// CSRF is checked here, after multer has parsed the multipart body into
// req.body, since the global CSRF middleware skips this exact route.
router.post('/upload', upload.single('file'), doubleCsrfProtection, fileController.uploadFile);

router.post('/folders', fileController.createFolder);
router.post('/folders/:id/delete', fileController.softDeleteFolder);
router.post('/folders/:id/restore', fileController.restoreFolder);
router.post('/folders/:id/purge', fileController.purgeFolder);

router.get('/:uuid/download', downloadLimiter, requireFilePermission('view'), fileController.downloadFile);
router.get('/:uuid/activity', requireFilePermission('owner'), fileController.fileActivity);
router.get('/:uuid/share', requireFilePermission('owner'), fileController.showShareForm);
router.post('/:uuid/share', requireFilePermission('owner'), fileController.createShare);
router.post('/:uuid/share/:shareId/revoke', requireFilePermission('owner'), fileController.revokeShare);
router.post('/:uuid/visibility', requireFilePermission('owner'), fileController.toggleVisibility);
router.post('/:uuid/move', requireFilePermission('owner'), fileController.moveFile);
router.post('/:uuid/delete', requireFilePermission('owner'), fileController.deleteFile);
router.post('/:uuid/restore', fileController.restoreFile);
router.post('/:uuid/purge', fileController.purgeFile);

module.exports = router;