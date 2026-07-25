const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const { requireAuth, requireRole } = require('../middleware/auth');
const { requireAllowedAdminIp } = require('../middleware/ipAllowlist');

router.use(requireAuth, requireRole('admin'), requireAllowedAdminIp);

router.get('/users', adminController.showUsers);
router.post('/users/:id/toggle-active', adminController.toggleUserActive);
router.post('/users/:id/role', adminController.setUserRole);

router.get('/activity', adminController.showActivityLog);

router.get('/ip-allowlist', adminController.showIpAllowlist);
router.post('/ip-allowlist', adminController.addIpAllowlistEntry);
router.post('/ip-allowlist/:id/remove', adminController.removeIpAllowlistEntry);

module.exports = router;