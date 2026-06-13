const axios = require('axios');
const https = require('https');
const Incident = require('../models/Incident');

const wazuhLevelToSeverity = (level) => {
    if (level >= 13) return 4;
    if (level >= 11) return 3;
    if (level >= 8)  return 2;
    if (level >= 4)  return 1;
    return 0;
};

const severityLabel = (level) => {
    if (level >= 13) return 'CRITICAL';
    if (level >= 11) return 'HIGH';
    if (level >= 8)  return 'MEDIUM';
    if (level >= 4)  return 'LOW';
    return 'INFO';
};

// SÉCURISATION SAST [CWE-295] : Vérification TLS activée pour éviter les attaques MITM.
const opensearchClient = axios.create({
    baseURL: process.env.OPENSEARCH_URL,
    auth: {
        username: process.env.OPENSEARCH_USER,
        password: process.env.OPENSEARCH_PASSWORD,
    },
    httpsAgent: new https.Agent({ rejectUnauthorized: true }), // SÉCURISATION SAST [CWE-295]
    timeout: 15_000,
});

const syncWazuhIncidents = async () => {
    const LEVEL_THRESHOLD = parseInt(process.env.WAZUH_ALERT_LEVEL_THRESHOLD || '7', 10);
    const BATCH_SIZE      = parseInt(process.env.WAZUH_SYNC_BATCH_SIZE        || '200', 10);

    const body = {
        size: BATCH_SIZE,
        sort: [{ '@timestamp': { order: 'desc' } }],
        query: {
            range: {
                'rule.level': { gt: LEVEL_THRESHOLD },
            },
        },
        _source: [
            '@timestamp',
            'rule.level',
            'rule.description',
            'rule.id',
            'agent.name',
            'agent.id',
            'full_log',
        ],
    };

    const response = await opensearchClient.post(
        `/${process.env.OPENSEARCH_ALERTS_INDEX || 'wazuh-alerts-4.x-*'}/_search`,
        body
    );

    const hits = response.data?.hits?.hits || [];
    console.log("[wazuhIncidentService] Found %s high-level alerts", hits.length); // SÉCURISATION SAST [CWE-134]

    let created = 0;
    let skipped = 0;

    for (const hit of hits) {
        const src   = hit._source;
        const alertId = hit._id;

        const exists = await Incident.findOne({ alert_id: String(alertId) }); // SÉCURISATION SAST [CWE-943]
        if (exists) {
            skipped++;
            continue;
        }

        const ruleLevel = src.rule?.level ?? 0;
        const severity  = wazuhLevelToSeverity(ruleLevel);
        const label     = severityLabel(ruleLevel);
        const desc      = src.rule?.description || 'No description';
        const log       = src.full_log          || '';

        await new Incident({
            title:       `[${label}] ${desc}`,
            description: `Rule: ${desc} (level ${ruleLevel})${log ? '\n\nLog:\n' + log : ''}`,
            severity,
            agent_name:  src.agent?.name || 'unknown',
            rule_id:     String(src.rule?.id ?? ''),
            rule_level:  ruleLevel,
            source:      'wazuh',
            status:      'open',
            alert_id:    alertId,
            timestamp:   new Date(src['@timestamp']),
        }).save();

        created++;
    }

    console.log("[wazuhIncidentService] Sync done: %s created, %s skipped", created, skipped); // SÉCURISATION SAST [CWE-134]
    return { created, skipped, total: hits.length };
};

module.exports = { syncWazuhIncidents, wazuhLevelToSeverity };