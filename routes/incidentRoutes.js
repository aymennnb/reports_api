const express = require('express');
const router = express.Router();
const incidentController = require('../controllers/incidentController');
const { verifyToken, isAdmin } = require('../middlewares/authMiddleware');
const { body } = require('express-validator');

// Validation for creating incidents
const validateIncident = [
  body('title').notEmpty().trim().isLength({ max: 100 }),
  body('description').notEmpty().isLength({ max: 1000 }),
  body('severity').isIn(['critical', 'high', 'medium', 'low']),
  body('affectedAssets').isArray(),
  body('scanReportId').notEmpty().isMongoId()
];

// Apply authentication to all routes
// router.use(verifyToken);

// ===== INCIDENT CRUD OPERATIONS =====

// Create incident (POST)
router.post('/', validateIncident, incidentController.createIncident);

// Get all incidents with filtering and pagination (GET)
router.get('/', incidentController.getAllIncidents);

// Get incidents grouped by severity (GET - must be before /:id to avoid conflicts)
router.get('/severity-report', incidentController.getIncidentsBySeverity);

// Get incident by ID (GET)
router.get('/:id', incidentController.getIncidentById);

// Update incident (PUT)
router.put(
  '/:id',
  [
    body('title').optional().trim(),
    body('severity').optional().isIn(['critical', 'high', 'medium', 'low']),
    body('status').optional().isIn(['open', 'in-progress', 'resolved', 'closed'])
  ],
  incidentController.updateIncident
);

// Resolve incident (PATCH)
router.patch('/:id/resolve', incidentController.resolveIncident);

// Delete incident (DELETE) - Admin only
router.delete('/:id', isAdmin, incidentController.deleteIncident);

module.exports = router;
