const axios  = require("axios");
const https  = require("https");
const Incident     = require("../models/Incident");
const ImportLogger = require("../utils/importLogger");

// SÉCURISATION SAST [CWE-295] : Vérification TLS activée pour éviter les attaques MITM.
const httpsAgent = new https.Agent({ rejectUnauthorized: true }); // SÉCURISATION SAST [CWE-295]

const getSeverityFromLevel = (level) => {
    if (level >= 15) return 4;
    if (level >= 12) return 3;
    if (level >= 8)  return 2;
    return 1;
};

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

    logger.info("Token Wazuh obtenu");
    return response.data;
};

const fetchHighSeverityAlerts = async (logger) => {
    const url = `${process.env.OPENSEARCH_URL}/wazuh-alerts-4.x-*/_search`;

    logger.info("Requête OpenSearch — alertes rule.level > 7...");

    const query = {
        size: 500,
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
    logger.info("%s alerte(s) de niveau > 7 trouvée(s)", hits.length); // SÉCURISATION SAST [CWE-134]
    return hits;
};

const severityLabel = { 4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW" };

const processAlerts = async (alerts, logger) => {
    const stats = { created: 0, skipped: 0, errors: 0 };

    for (const hit of alerts) {
        const alertId = hit._id;
        const source  = hit._source;
        const rule    = source?.rule    || {};
        const agent   = source?.agent   || {};

        try {
            const exists = await Incident.findOne({ alert_id: String(alertId) }); // SÉCURISATION SAST [CWE-943]
            if (exists) {
                stats.skipped++;
                continue;
            }

            const severity = getSeverityFromLevel(rule.level);

            await new Incident({
                title: `[${severityLabel[severity] || "UNKNOWN"}] ${rule.description || "Alerte Wazuh"}`,
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
            logger.info("Incident créé: [%s] %s — agent: %s", severity, rule.description, agent.name); // SÉCURISATION SAST [CWE-134]

        } catch (err) {
            if (err.code === 11000) {
                stats.skipped++;
            } else {
                logger.error("Erreur création incident (alert_id: %s): %s", alertId, err.message); // SÉCURISATION SAST [CWE-134]
                stats.errors++;
            }
        }
    }

    return stats;
};

const autoSyncWazuh = async (trigger = "scheduler") => {
    const logger = new ImportLogger("wazuh", trigger);

    logger.info("Démarrage de la synchronisation automatique Wazuh...");

    try {
        await getWazuhToken(logger);
    } catch (err) {
        logger.warn("Connexion Wazuh API échouée (on continue avec OpenSearch): %s", err.message); // SÉCURISATION SAST [CWE-134]
    }

    let alerts;
    try {
        alerts = await fetchHighSeverityAlerts(logger);
    } catch (err) {
        logger.error("Erreur OpenSearch: %s", err.message); // SÉCURISATION SAST [CWE-134]
        await logger.finish({ stats: {}, status: "error", error: err.message });
        throw err;
    }

    const stats = await processAlerts(alerts, logger);

    logger.info(
        "Synchronisation Wazuh terminée — créés: %s, ignorés: %s, erreurs: %s", // SÉCURISATION SAST [CWE-134]
        stats.created, stats.skipped, stats.errors
    );

    const finalStatus = stats.errors > 0
        ? (stats.created > 0 ? "partial" : "error")
        : "success";

    await logger.finish({ stats: { inserted: stats.created, skipped: stats.skipped, errors: stats.errors }, status: finalStatus });
    return stats;
};

module.exports = { autoSyncWazuh };