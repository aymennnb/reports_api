const mongoose = require("mongoose");

const importLogSchema = new mongoose.Schema(
    {
        source: {
            type: String,
            enum: ["nessus", "wazuh"],
            required: true,
            index: true,
        },
        trigger: {
            type: String,
            enum: ["scheduler", "manual"],
            default: "scheduler",
        },
        status: {
            type: String,
            enum: ["success", "partial", "error"],
            default: "success",
            index: true,
        },
        // Statistiques chiffrées de l'import
        stats: {
            inserted: { type: Number, default: 0 },
            updated:  { type: Number, default: 0 },
            skipped:  { type: Number, default: 0 },
            resolved: { type: Number, default: 0 }, // spécifique Nessus
            errors:   { type: Number, default: 0 },
        },
        // Tableau de messages texte (remplace console.log pendant l'import)
        logs: [
            {
                level:     { type: String, enum: ["info", "warn", "error"], default: "info" },
                message:   { type: String, required: true },
                timestamp: { type: Date, default: Date.now },
            },
        ],
        // Message d'erreur global si le job a planté
        error: {
            type: String,
            default: null,
        },
        // Durée de l'import en ms
        duration_ms: {
            type: Number,
            default: null,
        },
        // Date de début d'exécution
        started_at: {
            type: Date,
            default: Date.now,
            index: true,
        },
        // Date de fin d'exécution
        finished_at: {
            type: Date,
            default: null,
        },
    },
    {
        timestamps: false,
    }
);

module.exports = mongoose.model("ImportLog", importLogSchema);
