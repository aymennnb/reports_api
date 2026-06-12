/**
 * wazuhIncidentService.js
 *
 * Fetches Wazuh alerts from OpenSearch, filters rule.level > 7,
 * and creates Incident documents automatically (dedup by alert_id).
 *
 * Severity mapping (Wazuh rule.level → internal 0-4):
 *   level  1–3  → 0 (info)
 *   level  4–6  → 1 (low)
 *   level  7    → 2 (medium)
 *   level  8–10 → 2 (medium)   ← threshold we create incidents for
 *   level 11–12 → 3 (high)
 *   level 13-15 → 4 (critical)
 */

const axios = require('axios');
const https = require('https');
const Incident = require('../models/Incident');

// ─── Severity helper ──────────────────────────────────────────────────────────
const wazuhLevelToSeverity = (level) => {
    if (level >= 13) return 4; // critical
    if (level >= 11) return 3; // high
    if (level >= 8)  return 2; // medium
    if (level >= 4)  return 1; // low
    return 0;                  // info
};

const severityLabel = (level) => {
    if (level >= 13) return 'CRITICAL';
    if (level >= 11) return 'HIGH';
    if (level >= 8)  return 'MEDIUM';
    if (level >= 4)  return 'LOW';
    return 'INFO';
};

// ─── Axios instance for OpenSearch (self-signed cert OK) ─────────────────────
const opensearchClient = axios.create({
    baseURL: process.env.OPENSEARCH_URL,
    auth: {
        username: process.env.OPENSEARCH_USER,
        password: process.env.OPENSEARCH_PASSWORD,
    },
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 15_000,
});

// ─── Main sync function ───────────────────────────────────────────────────────
const syncWazuhIncidents = async () => {
    const LEVEL_THRESHOLD = parseInt(process.env.WAZUH_ALERT_LEVEL_THRESHOLD || '7', 10);
    const BATCH_SIZE      = parseInt(process.env.WAZUH_SYNC_BATCH_SIZE        || '200', 10);

    // 1. Query OpenSearch for alerts above the threshold
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
    console.log(`[wazuhIncidentService] Found ${hits.length} high-level alerts`);

    let created = 0;
    let skipped = 0;

    for (const hit of hits) {
        const src   = hit._source;
        const alertId = hit._id;

        const exists = await Incident.findOne({ alert_id: alertId });
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

    console.log(`[wazuhIncidentService] Sync done: ${created} created, ${skipped} skipped`);
    return { created, skipped, total: hits.length };
};

module.exports = { syncWazuhIncidents, wazuhLevelToSeverity };