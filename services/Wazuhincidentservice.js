const axios = require('axios');
const https = require('https');
const Incident = require('../models/Incident');

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

function getSeverityFromLevel(level) {
  if (level >= 15) return 'critical';
  if (level >= 12) return 'high';
  if (level >= 8)  return 'medium';
  return 'low';
}

// ─── 1. Obtenir token JWT Wazuh ───────────────────────────────────────────
async function getWazuhToken() {
  const url = `${process.env.WAZUH_API_URL}/security/user/authenticate?raw=true`;

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

  return response.data;
}

// ─── 2. Récupérer les alertes depuis OpenSearch ───────────────────────────────
async function fetchHighSeverityAlerts() {
  const url = `${process.env.OPENSEARCH_URL}/wazuh-alerts-4.x-*/_search`;

  const query = {
    size: 100,
    sort: [{ '@timestamp': { order: 'desc' } }],
    query: {
      range: {
        'rule.level': {
          gt: 7,
        },
      },
    },
    _source: ['agent', '@timestamp', 'rule', 'full_log'],
  };

  const response = await axios.post(url, query, {
    auth: {
      username: process.env.OPENSEARCH_USER,
      password: process.env.OPENSEARCH_PASSWORD,
    },
    httpsAgent,
    timeout: 15000,
    headers: { 'Content-Type': 'application/json' },
  });

  const hits = response.data?.hits?.hits || [];
  return hits;
}

// ─── 3. Traiter et créer les incidents ───────────────────────────────────────
async function processAlerts(alerts) {
  let created = 0;
  let skipped = 0;

  for (const hit of alerts) {
    const alertId = hit._id;
    const source   = hit._source;
    const rule     = source?.rule || {};
    const agent    = source?.agent || {};

    const exists = await Incident.findOne({ alert_id: alertId });
    if (exists) {
      skipped++;
      continue;
    }

    const severity = getSeverityFromLevel(rule.level);

    const incident = new Incident({
      title:       `${rule.description || 'Alerte Wazuh'}`,
      description: source?.full_log
        ? `Rule: ${rule.description}\n\nLog:\n${source.full_log}`
        : `Rule: ${rule.description || 'N/A'} (level ${rule.level})`,
      severity,
      agent_name:  agent.name || 'unknown',
      rule_id:     String(rule.id || ''),
      rule_level:  rule.level,
      source:      'wazuh',
      status:      'open',
      alert_id:    alertId,
      timestamp:   new Date(source['@timestamp']),
    });

    await incident.save();
    created++;
    console.log(`[IncidentService] Incident créé : ${incident.title} (alert_id: ${alertId})`);
  }

  return { created, skipped };
}

// ─── 4. Fonction principale exportée ─────────────────────────────────────────
async function syncWazuhIncidents() {
  console.log('[IncidentService] Démarrage de la synchronisation...');

  try {
    await getWazuhToken();
    console.log('[IncidentService] Token Wazuh obtenu');
  } catch (err) {
    console.warn('[IncidentService] Avertissement: connexion Wazuh API échouée :', err.message);
  }

  let alerts;
  try {
    alerts = await fetchHighSeverityAlerts();
    console.log(`[IncidentService] ${alerts.length} alerte(s) de niveau > 7 trouvée(s)`);
  } catch (err) {
    console.error('[IncidentService] Erreur lors de la récupération des alertes :', err.message);
    throw err;
  }

  const result = await processAlerts(alerts);
  console.log(`[IncidentService] Terminé — créés: ${result.created}, ignorés (doublons): ${result.skipped}`);
  return result;
}

module.exports = { syncWazuhIncidents };