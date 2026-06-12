const nessusService    = require("./nessusService");
const { buildSyncPayload } = require("../utils/Nessusmapper");
const Vulnerability    = require("../models/Vulnerability");
const ImportLogger     = require("../utils/importLogger");

/**
 * autoSyncNessus — Fonction principale appelée par le scheduler.
 *
 * Elle reproduit exactement la logique de syncFromNessusById() du controller,
 * mais :
 *   - tourne sur TOUS les scans (pas un seul ID)
 *   - utilise ImportLogger au lieu de console.log
 *   - retourne les stats pour le log MongoDB
 *   - n'a pas besoin de req/res (pas de contexte HTTP)
 *
 * @param {string} trigger - "scheduler" | "manual"
 */
const autoSyncNessus = async (trigger = "scheduler") => {
    const logger = new ImportLogger("nessus", trigger);
    const globalStats = { inserted: 0, updated: 0, resolved: 0, errors: 0 };

    logger.info("Démarrage de la synchronisation automatique Nessus...");

    let scansData;
    try {
        scansData = await nessusService.getScans();
    } catch (err) {
        logger.error(`Impossible de récupérer les scans Nessus: ${err.message}`);
        await logger.finish({ stats: globalStats, status: "error", error: err.message });
        throw err;
    }

    const allScans = scansData.scans || [];
    logger.info(`${allScans.length} scan(s) trouvé(s) sur Nessus`);

    if (allScans.length === 0) {
        logger.warn("Aucun scan disponible sur Nessus.");
        await logger.finish({ stats: globalStats, status: "success" });
        return globalStats;
    }

    const completedScans = allScans.filter(s => s.status === "completed");
    logger.info(`${completedScans.length} scan(s) avec status "completed" à traiter`);

    for (const scan of completedScans) {
        logger.info(`Traitement du scan: ${scan.name} (ID: ${scan.id})`);

        try {
            const scanDetail = await nessusService.getScanById(scan.id);

            if (!scanDetail.vulnerabilities?.length) {
                logger.info(`Scan ${scan.name}: aucune vulnérabilité détectée — ignoré`);
                continue;
            }

            logger.info(
                `Scan ${scan.name}: ${scanDetail.vulnerabilities.length} vulnérabilité(s) à analyser`
            );

            const pluginMap = await nessusService.getAllPluginDetails(
                scan.id,
                scanDetail.vulnerabilities
            );

            // ── ÉTAPE 2c : Transformer en payload structuré ───────────────
            const payload = buildSyncPayload(scan.id, scanDetail, pluginMap);

            // ── ÉTAPE 2d : Déduplication + insertion en base ───────────────
            const scanStats = await applySync(payload, logger);

            globalStats.inserted += scanStats.inserted;
            globalStats.updated  += scanStats.updated;
            globalStats.resolved += scanStats.resolved;

            logger.info(
                `Scan ${scan.name} terminé — ` +
                `insérés: ${scanStats.inserted}, mis à jour: ${scanStats.updated}, ` +
                `résolus: ${scanStats.resolved}`
            );

        } catch (scanErr) {
            // Un scan en erreur ne bloque pas les autres
            logger.error(`Erreur sur le scan ${scan.name} (ID: ${scan.id}): ${scanErr.message}`);
            globalStats.errors++;
        }
    }

    // ── ÉTAPE 3 : Sauvegarder le log en base ──────────────────────────────
    const finalStatus = globalStats.errors > 0
        ? (globalStats.inserted + globalStats.updated > 0 ? "partial" : "error")
        : "success";

    logger.info(
        `Synchronisation Nessus terminée — ` +
        `insérés: ${globalStats.inserted}, mis à jour: ${globalStats.updated}, ` +
        `résolus: ${globalStats.resolved}, erreurs: ${globalStats.errors}`
    );

    await logger.finish({ stats: globalStats, status: finalStatus });
    return globalStats;
};


/**
 * applySync — Même logique que dans vulnerabilitiesController.js (applySync).
 * Dupliquée ici pour que le scheduler soit indépendant du controller HTTP.
 * Les deux coexistent : le controller pour les syncs manuelles (via bouton),
 * cette fonction pour les syncs automatiques (via cron).
 */
const applySync = async ({ scan_id, vulnerabilities, hosts, plugin_details }, logger) => {
    const host  = hosts?.[0]?.hostname || "unknown";
    const now   = new Date();
    const stats = { inserted: 0, updated: 0, resolved: 0 };
    const seenPluginIds = [];

    for (const v of vulnerabilities) {
        const { plugin_id, plugin_name, severity } = v;
        if (!plugin_id || !plugin_name) continue;

        seenPluginIds.push(plugin_id);
        const details = plugin_details?.[plugin_id] || {};
        const port    = details.port || null;

        const existing = await Vulnerability.findOne({ plugin_id, host, port });

        if (!existing) {
            await Vulnerability.create({
                plugin_id,
                plugin_family:    v.plugin_family     || null,
                title:            plugin_name,
                synopsis:         details.synopsis    || null,
                description:      details.description || null,
                solution:         details.solution    || null,
                severity,
                cvss_base_score:  details.cvss_base_score  || null,
                cvss3_base_score: details.cvss3_base_score || null,
                cve:              details.cve         || [],
                host,
                port,
                plugin_output:    details.plugin_output || null,
                first_seen:       now,
                last_seen:        now,
                status:           "open",
                scan_id:          scan_id || null,
                added_manually:   false,
            });
            stats.inserted++;
        } else {
            await Vulnerability.findByIdAndUpdate(existing._id, {
                last_seen: now,
                status:    "open",
                severity,
                scan_id:   scan_id || existing.scan_id,
            });
            stats.updated++;
        }
    }

    const resolved = await Vulnerability.updateMany(
        { host, status: "open", plugin_id: { $nin: seenPluginIds } },
        { status: "resolved" }
    );
    stats.resolved = resolved.modifiedCount;

    return stats;
};

module.exports = { autoSyncNessus };