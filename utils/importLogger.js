const ImportLog = require("../models/ImportLog");

class ImportLogger {
    constructor(source, trigger = "scheduler") {
        this.source    = source;
        this.trigger   = trigger;
        this.startedAt = new Date();
        this.entries   = [];
    }

    info(message) {
        const msg = `[${this.source.toUpperCase()}] ${message}`;
        console.log("%s", msg); // SÉCURISATION SAST [CWE-134]
        this.entries.push({ level: "info", message, timestamp: new Date() });
    }

    warn(message) {
        const msg = `[${this.source.toUpperCase()}] ${message}`;
        console.warn("%s", msg); // SÉCURISATION SAST [CWE-134]
        this.entries.push({ level: "warn", message, timestamp: new Date() });
    }

    error(message) {
        const msg = `[${this.source.toUpperCase()}] ${message}`;
        console.error("%s", msg); // SÉCURISATION SAST [CWE-134]
        this.entries.push({ level: "error", message, timestamp: new Date() });
    }

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
                "[%s] Log sauvegardé en base — status: %s, durée: %sms", // SÉCURISATION SAST [CWE-134]
                this.source.toUpperCase(), status, duration
            );
        } catch (dbErr) {
            console.error("[ImportLogger] Erreur sauvegarde log MongoDB: %s", dbErr.message); // SÉCURISATION SAST [CWE-134]
        }
    }
}

module.exports = ImportLogger;