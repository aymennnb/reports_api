const ImportLog    = require("../models/ImportLog");
const { autoSyncNessus } = require("../services/nessusAutoSync");
const { autoSyncWazuh  } = require("../services/wazuhAutoSync");

/**
 * importLogsController.js
 *
 * Expose des routes pour :
 *   1. Consulter l'historique des imports (GET /api/import-logs)
 *   2. Voir le détail d'un log (GET /api/import-logs/:id)
 *   3. Déclencher manuellement un import (POST /api/import-logs/trigger/:source)
 *      → utile si tu veux garder le bouton manuel sur le frontend
 *         tout en profitant du même système de logs que le scheduler
 */

// ─── GET /api/import-logs ─────────────────────────────────────────────────────
const getLogs = async (req, res) => {
    try {
        const filter = {};
        if (req.query.source)  filter.source  = req.query.source;  // "nessus" | "wazuh"
        if (req.query.status)  filter.status  = req.query.status;  // "success" | "error" | "partial"
        if (req.query.trigger) filter.trigger = req.query.trigger; // "scheduler" | "manual"

        // Filtrage par date
        if (req.query.from || req.query.to) {
            filter.started_at = {};
            if (req.query.from) filter.started_at.$gte = new Date(req.query.from);
            if (req.query.to)   filter.started_at.$lte = new Date(req.query.to);
        }

        const page  = parseInt(req.query.page  || "1");
        const limit = parseInt(req.query.limit || "20");
        const skip  = (page - 1) * limit;

        const [logs, total] = await Promise.all([
            ImportLog.find(filter)
                .sort({ started_at: -1 })
                .skip(skip)
                .limit(limit)
                .select("-logs"), // On exclut le détail des logs pour la liste
            ImportLog.countDocuments(filter),
        ]);

        res.status(200).json({
            count: logs.length,
            total,
            page,
            pages: Math.ceil(total / limit),
            logs,
        });
    } catch (err) {
        res.status(500).json({ message: "Server error." });
    }
};

// ─── GET /api/import-logs/:id ─────────────────────────────────────────────────
// Retourne le détail complet avec tous les messages de log
const getLogById = async (req, res) => {
    try {
        const log = await ImportLog.findById(req.params.id);
        if (!log) return res.status(404).json({ message: "Log not found." });
        res.status(200).json(log);
    } catch (err) {
        res.status(400).json({ message: "Invalid log ID format." });
    }
};

// ─── GET /api/import-logs/stats ───────────────────────────────────────────────
// Vue synthétique : dernier import de chaque source + compteurs globaux
const getLogStats = async (req, res) => {
    try {
        const [lastNessus, lastWazuh, totalByStatus, totalBySource] = await Promise.all([
            ImportLog.findOne({ source: "nessus" }).sort({ started_at: -1 }).select("-logs"),
            ImportLog.findOne({ source: "wazuh"  }).sort({ started_at: -1 }).select("-logs"),
            ImportLog.aggregate([
                { $group: { _id: "$status", count: { $sum: 1 } } }
            ]),
            ImportLog.aggregate([
                { $group: {
                    _id: "$source",
                    total:    { $sum: 1 },
                    success:  { $sum: { $cond: [{ $eq: ["$status", "success"] }, 1, 0] } },
                    errors:   { $sum: { $cond: [{ $eq: ["$status", "error"]   }, 1, 0] } },
                    inserted: { $sum: "$stats.inserted" },
                    updated:  { $sum: "$stats.updated"  },
                }}
            ]),
        ]);

        res.status(200).json({
            last_imports: { nessus: lastNessus, wazuh: lastWazuh },
            by_status:    totalByStatus,
            by_source:    totalBySource,
        });
    } catch (err) {
        res.status(500).json({ message: "Server error." });
    }
};

// ─── POST /api/import-logs/trigger/:source ────────────────────────────────────
// Déclenche un import manuel (remplace les anciens boutons du frontend).
// Utilise les mêmes services que le scheduler → logs en base également.
const triggerManualImport = async (req, res) => {
    const { source } = req.params;

    if (!["nessus", "wazuh"].includes(source)) {
        return res.status(400).json({ message: 'source doit être "nessus" ou "wazuh".' });
    }

    try {
        let stats;

        if (source === "nessus") {
            stats = await autoSyncNessus("manual");
        } else {
            stats = await autoSyncWazuh("manual");
        }

        res.status(200).json({
            message: `Import ${source} déclenché manuellement avec succès.`,
            stats,
        });
    } catch (err) {
        res.status(500).json({
            message: `Import ${source} échoué: ${err.message}`,
        });
    }
};

module.exports = { getLogs, getLogById, getLogStats, triggerManualImport };