const express = require('express');
const router  = express.Router();
const {
  getAllIncidents,
  getIncidentById,
  createIncident,
  updateIncident,
  deleteIncident,
  syncFromWazuh,
  getStats,
} = require('../controllers/incidentsController');

const { verifyToken, isAdmin } = require("../middlewares/authMiddleware");

router.use(verifyToken);

router.get('/incidents/stats', getStats);

// Synchronisation manuelle depuis Wazuh
router.post('/incidents/sync', syncFromWazuh);

// CRUD
router.get('/incidents',     getAllIncidents);
router.get('/incidents/:id',  getIncidentById);
router.post('/incidents',    createIncident);
router.put('/incidents/:id',  updateIncident);
router.delete('/incidents/:id', deleteIncident);

module.exports = router;
