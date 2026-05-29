const ImportLog = require("../models/ImportLog");

/**
 * ImportLogger — Classe utilitaire créée pour CHAQUE exécution de job.
 *
 * Principe :
 *   1. On instancie un logger : const logger = new ImportLogger("nessus", "scheduler")
 *   2. On remplace console.log par logger.info() / logger.warn() / logger.error()
 *   3. À la fin : await logger.finish({ stats, status })
 *      → sauvegarde tout en base MongoDB dans la collection import_logs
 *
 * Avantage : les logs ne disparaissent plus au redémarrage du serveur.
 */
class ImportLogger {
    constructor(source, trigger = "scheduler") {
        this.source    = source;     // "nessus" | "wazuh"
        this.trigger   = trigger;    // "scheduler" | "manual"
        this.startedAt = new Date();
        this.entries   = [];         // buffer des messages de log
    }

    // ── Méthodes de log ────────────────────────────────────────────────────
    info(message) {
        const msg = `[${this.source.toUpperCase()}] ${message}`;
        console.log(msg);
        this.entries.push({ level: "info", message, timestamp: new Date() });
    }

    warn(message) {
        const msg = `[${this.source.toUpperCase()}] ${message}`;
        console.warn(msg);
        this.entries.push({ level: "warn", message, timestamp: new Date() });
    }

    error(message) {
        const msg = `[${this.source.toUpperCase()}] ${message}`;
        console.error(msg);
        this.entries.push({ level: "error", message, timestamp: new Date() });
    }

    /**
     * finish() — Appelée à la fin du job pour persister en MongoDB.
     *
     * @param {object} options
     * @param {object} options.stats   - { inserted, updated, skipped, resolved, errors }
     * @param {string} options.status  - "success" | "partial" | "error"
     * @param {string} options.error   - message d'erreur si status = "error"
     */
    async finish({ stats = {}, status = "success", error = null } = {}) {
        const finishedAt = new Date();
        const duration   = finishedAt - this.startedAt;

        try {
            await ImportLog.create({
                source:      this.source,
                trigger:     this.trigger,
                status,
                stats: {
                    inserted: stats.inserted ?? stats.created ?? 0,
                    updated:  stats.updated  ?? 0,
                    skipped:  stats.skipped  ?? 0,
                    resolved: stats.resolved ?? 0,
                    errors:   stats.errors   ?? 0,
                },
                logs:        this.entries,
                error,
                duration_ms: duration,
                started_at:  this.startedAt,
                finished_at: finishedAt,
            });

            console.log(
                `[${this.source.toUpperCase()}] Log sauvegardé en base — ` +
                `status: ${status}, durée: ${duration}ms`
            );
        } catch (dbErr) {
            // Ne pas crasher si la sauvegarde en base échoue
            console.error(`[ImportLogger] Erreur sauvegarde log MongoDB: ${dbErr.message}`);
        }
    }
}

module.exports = ImportLogger;
