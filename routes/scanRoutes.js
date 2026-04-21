const express = require('express');
const router = express.Router();
const scanController = require('../controllers/scanController');
const authMiddleware = require('../middlewares/authMiddleware');
const { body } = require('express-validator');

const validateScan = [
  body('name').notEmpty().trim().isLength({ max: 150 }),
  body('target').notEmpty().trim(),
  body('scanType').isIn(['network', 'web', 'system', 'vulnerability'])
];

// Protect all routes
const { verifyToken } = require('../middlewares/authMiddleware');

router.use(verifyToken);

router.post('/',                  validateScan, scanController.createScan);
router.get('/',                                 scanController.getAllScans);
router.get('/summary',                          scanController.getScanSummary);
router.get('/wazuh/agents',                     scanController.getWazuhAgents);
router.post('/import/wazuh',                    scanController.importFromWazuh);
router.get('/:id',                              scanController.getScanById);
router.patch('/:id/status',                     scanController.updateScanStatus);
router.delete('/:id',                           scanController.deleteScan);

module.exports = router;