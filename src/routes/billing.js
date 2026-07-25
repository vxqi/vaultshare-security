const express = require('express');
const router = express.Router();
const billingController = require('../controllers/billingController');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);

router.get('/', billingController.showBilling);
router.post('/upgrade', billingController.upgrade);
router.post('/downgrade', billingController.downgrade);

module.exports = router;