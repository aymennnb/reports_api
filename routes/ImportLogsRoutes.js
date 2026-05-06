const express = require("express");
const router  = express.Router();
const {
    getLogs,
    getLogById,
    getLogStats,
    triggerManualImport,
} = require("../controllers/importLogsController");

const { verifyToken, isAdmin } = require("../middlewares/authMiddleware");

// Toutes les routes sont protégées par JWT
router.use(verifyToken);

// Stats synthétiques (avant /:id pour éviter conflit de route)
router.get("/stats", getLogStats);

// Liste avec filtres + pagination
router.get("/", getLogs);

// Détail d'un log (avec tous les messages)
router.get("/:id", getLogById);

// Déclencher un import manuel
// POST /api/import-logs/trigger/nessus
// POST /api/import-logs/trigger/wazuh
router.post("/trigger/:source", triggerManualImport);

module.exports = router;