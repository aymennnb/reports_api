const axios  = require("axios");
const https  = require("https");
const Incident     = require("../models/Incident");
const ImportLogger = require("../utils/importLogger");

/**
 * wazuhAutoSync — Wrapper autour de la logique wazuhIncidentService existante.
 *
 * Ce fichier NE REMPLACE PAS wazuhIncidentService.js.
 * Il s'appuie sur les mêmes appels API mais :
 *   - utilise ImportLogger (logs persistés en MongoDB)
 *   - est conçu pour être appelé par le scheduler (pas de req/res)
 *   - retourne des stats complètes
 *
 * wazuhIncidentService.js reste utilisé par le controller pour les syncs manuelles.
 */

// ── Ignorer les certificats auto-signés (environnement lab) ───────────────────
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// ── Mapping level → severity ──────────────────────────────────────────────────
const getSeverityFromLevel = (level) => {
    if (level >= 15) return "critical";
    if (level >= 12) return "high";
    if (level >= 8)  return "medium";
    return "low";
};

// ── 1. Obtenir un token JWT Wazuh ─────────────────────────────────────────────
const getWazuhToken = async (logger) => {
    const url = `${process.env.WAZUH_API_URL}/security/user/authenticate?raw=true`;

    logger.info("Authentification sur l'API Wazuh...");

    const response = await axios.post(
        url,
        {},
        {
            auth: {
                username: process.env.WAZUH_USER,
                password: process.env.WAZUH_PASSWORD,
            },
            httpsAgent,
            timeout: 10000,
        }
    );

    logger.info("Token Wazuh obtenu ✓");
    return response.data; // raw=true → token directement en string
};

// ── 2. Récupérer les alertes OpenSearch avec rule.level > 7 ───────────────────
const fetchHighSeverityAlerts = async (logger) => {
    const url = `${process.env.OPENSEARCH_URL}/wazuh-alerts-4.x-*/_search`;

    logger.info("Requête OpenSearch — alertes rule.level > 7...");

    const query = {
        size: 500, // max par exécution (configurable via .env si besoin)
        sort: [{ "@timestamp": { order: "desc" } }],
        query: {
            range: { "rule.level": { gt: 7 } },
        },
        _source: ["agent", "@timestamp", "rule", "full_log"],
    };

    const response = await axios.post(url, query, {
        auth: {
            username: process.env.OPENSEARCH_USER,
            password: process.env.OPENSEARCH_PASSWORD,
        },
        httpsAgent,
        timeout: 15000,
        headers: { "Content-Type": "application/json" },
    });

    const hits = response.data?.hits?.hits || [];
    logger.info(`${hits.length} alerte(s) de niveau > 7 trouvée(s)`);
    return hits;
};

// ── 3. Traiter les alertes et créer les incidents sans doublons ───────────────
const processAlerts = async (alerts, logger) => {
    const stats = { created: 0, skipped: 0, errors: 0 };

    for (const hit of alerts) {
        const alertId = hit._id;
        const source  = hit._source;
        const rule    = source?.rule    || {};
        const agent   = source?.agent   || {};

        try {
            // ── Vérification doublon via alert_id (index unique sparse) ───
            const exists = await Incident.findOne({ alert_id: alertId });
            if (exists) {
                stats.skipped++;
                continue;
            }

            const severity = getSeverityFromLevel(rule.level);

            await new Incident({
                title: `[${severity.toUpperCase()}] ${rule.description || "Alerte Wazuh"}`,
                description: source?.full_log
                    ? `Rule: ${rule.description}\n\nLog:\n${source.full_log}`
                    : `Rule: ${rule.description || "N/A"} (level ${rule.level})`,
                severity,
                agent_name: agent.name || "unknown",
                rule_id:    String(rule.id || ""),
                rule_level: rule.level,
                source:     "wazuh",
                status:     "open",
                alert_id:   alertId,
                timestamp:  new Date(source["@timestamp"]),
            }).save();

            stats.created++;
            logger.info(`Incident créé: [${severity}] ${rule.description} — agent: ${agent.name}`);

        } catch (err) {
            // Erreur de duplicate key (race condition) → on ignore simplement
            if (err.code === 11000) {
                stats.skipped++;
            } else {
                logger.error(`Erreur création incident (alert_id: ${alertId}): ${err.message}`);
                stats.errors++;
            }
        }
    }

    return stats;
};

// ── Fonction principale exportée ──────────────────────────────────────────────
/**
 * autoSyncWazuh — Appelée par le scheduler toutes les N minutes.
 *
 * @param {string} trigger - "scheduler" | "manual"
 */
const autoSyncWazuh = async (trigger = "scheduler") => {
    const logger = new ImportLogger("wazuh", trigger);

    logger.info("Démarrage de la synchronisation automatique Wazuh...");

    // ── Authentification ──────────────────────────────────────────────────
    try {
        await getWazuhToken(logger);
    } catch (err) {
        logger.warn(`Connexion Wazuh API échouée (on continue avec OpenSearch): ${err.message}`);
        // On ne bloque pas : OpenSearch est indépendant du JWT Wazuh API
    }

    // ── Récupération des alertes ──────────────────────────────────────────
    let alerts;
    try {
        alerts = await fetchHighSeverityAlerts(logger);
    } catch (err) {
        logger.error(`Erreur OpenSearch: ${err.message}`);
        await logger.finish({ stats: {}, status: "error", error: err.message });
        throw err;
    }

    // ── Traitement des alertes ────────────────────────────────────────────
    const stats = await processAlerts(alerts, logger);

    logger.info(
        `Synchronisation Wazuh terminée — ` +
        `créés: ${stats.created}, ignorés: ${stats.skipped}, erreurs: ${stats.errors}`
    );

    const finalStatus = stats.errors > 0
        ? (stats.created > 0 ? "partial" : "error")
        : "success";

    await logger.finish({ stats: { inserted: stats.created, skipped: stats.skipped, errors: stats.errors }, status: finalStatus });
    return stats;
};

module.exports = { autoSyncWazuh };