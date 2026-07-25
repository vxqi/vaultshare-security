const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const fileController = require('../controllers/fileController');

router.get('/', requireAuth, fileController.listDashboard);
router.get('/trash', requireAuth, fileController.showTrash);

module.exports = router;