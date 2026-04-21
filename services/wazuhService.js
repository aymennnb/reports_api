/**
 * Service d'intégration Wazuh - Import de scans de vulnérabilité + Alertes → Incidents
 * Récupère les scans et alertes depuis l'API Wazuh et les transforme en incidents/scans
 */

const axios = require('axios');
const https = require('https');
const ScanReport = require('../models/ScanReport');
const Incident = require('../models/Incident');
const User = require('../models/User');

// ─── Configuration Wazuh ────────────────────────────────────────────────────────
const wazuhConfig = {
  url: process.env.WAZUH_API_URL || 'https://localhost:55000',
  username: (process.env.WAZUH_API_USER || 'wazuh').trim(),
  password: (process.env.WAZUH_API_PASSWORD || 'wazuh').trim(),
};

// Instance axios pour Wazuh 

const indexerClient = axios.create({
  baseURL: process.env.WAZUH_INDEXER_URL,
  httpsAgent: new https.Agent({
    rejectUnauthorized:false
  })
});

const wazuhClient = axios.create({
  baseURL: wazuhConfig.url,
  timeout: 10000,
  httpsAgent: new https.Agent({
    rejectUnauthorized: false,
  }),
});

let wazuhToken = null;
let tokenExpiry = null;

// ─── Authentification Wazuh ─────────────────────────────────────────────────────

/**
 * Obtient un token d'authentification pour l'API Wazuh
 */
async function getWazuhToken() {
  try {

    if (wazuhToken && tokenExpiry && new Date() < tokenExpiry) {
      return wazuhToken;
    }

    const response = await wazuhClient.get(
      '/security/user/authenticate',
      {
        auth: {
          username: wazuhConfig.username,
          password: wazuhConfig.password
        }
      }
    );

    wazuhToken = response.data.data.token;

    tokenExpiry = new Date(Date.now()+14*60*1000);

    return wazuhToken;

  } catch(err){
    const status = err.response?.status;
    const detail = err.response?.data?.detail || err.message;
    console.error(`[WazuhService] ❌ Erreur auth: HTTP ${status || 'UNKNOWN'} — ${detail}`);
    throw err;
  }
}

// ─── Récupération des agents ────────────────────────────────────────────────────

/**
 * Récupère les agents Wazuh actifs
 */
async function getWazuhAgents() {
  try {
    const token = await getWazuhToken();

    const response = await wazuhClient.get('/agents', {
      headers: { Authorization: `Bearer ${token}` },
      params: {
        limit: 500,
        q: 'status=active',
      },
    });

    console.log(
      `[WazuhService] 🖥️  ${response.data.data.affected_items?.length || 0} agent(s) actif(s)`
    );
    return response.data.data.affected_items || [];
  } catch (err) {
    console.error('[WazuhService] ❌ Erreur lors de la récupération des agents:', err.message);
    throw new Error('Impossible de récupérer les agents Wazuh');
  }
}

// ─── Récupération des scans de vulnérabilité ────────────────────────────────────

/**
 * Récupère les scans de vulnérabilité depuis Wazuh
 * @param {Object} options - Filtres optionnels (agentId, limit, offset)
 */
async function getWazuhScans(options = {}) {
  try {
    const token = await getWazuhToken();

    const params = new URLSearchParams({
      limit: options.limit || 50,
      offset: options.offset || 0,
      sort: '-timestamp',
    });

    if (options.agentId) {
      params.append('q', `agent.id=${options.agentId}`);
    }

    const response = await wazuhClient.get('/vulnerability', {
      headers: { Authorization: `Bearer ${token}` },
      params,
    });

    console.log(
      `[WazuhService] 📊 ${response.data.data.affected_items?.length || 0} vulnérabilité(s) récupérée(s)`
    );
    return response.data.data.affected_items || [];
  } catch (err) {
    console.error('[WazuhService] ❌ Erreur lors de la récupération des scans:', err.message);
    throw new Error('Impossible de récupérer les scans Wazuh');
  }
}

// ─── Récupération des alertes ───────────────────────────────────────────────────

/**
 * Récupère les alertes de sécurité depuis Wazuh
 * @param {Object} options - Filtres: minLevel, agentId, limit, fromDate
 */
async function getWazuhAlerts(options = {}) {
  try {
    const limit = options.limit || 100;

    const response = await indexerClient.post(
      '/wazuh-alerts*/_search',
      {
        size: limit,
        sort: [
          { "@timestamp": "desc" }
        ]
      },
      {
        auth: {
          username: wazuhConfig.username,
          password: wazuhConfig.password
        }
      }
    );

    const alerts = response.data.hits.hits || [];

    console.log(
      `[WazuhService] 🚨 ${alerts.length} alerte(s) récupérée(s)`
    );

    return alerts;

  } catch (err) {
    const status = err.response?.status;
    const detail = err.response?.data?.detail || err.response?.data || err.message;
    console.error(
      `[WazuhService] ❌ Erreur récupération alertes: HTTP ${status || 'UNKNOWN'} — ${JSON.stringify(detail)}`
    );
    console.error(`[WazuhService] 💡 Vérifiez que WAZUH_INDEXER_URL (${process.env.WAZUH_INDEXER_URL}) est correct et accessible`);

    throw new Error('Impossible de récupérer les alertes Wazuh');
  }
}

// ─── Mapping : Alerte Wazuh → Incident ─────────────────────────────────────────

/**
 * Niveau Wazuh (0–15) → priorité incident
 */
function mapLevelToPriority(level = 0) {
  if (level >= 15) return 'critical';
  if (level >= 12) return 'high';
  if (level >= 7)  return 'medium';
  return 'low';
}

/**
 * Groupes Wazuh → catégorie lisible
 */
function mapGroupsToCategory(groups = []) {
  const g = groups.join(' ').toLowerCase();
  if (/web|http|nginx|apache/.test(g))            return 'Web';
  if (/authentication|login|pam|ssh/.test(g))     return 'Authentification';
  if (/malware|virus|trojan|rootkit/.test(g))      return 'Malware';
  if (/network|firewall|iptables/.test(g))         return 'Réseau';
  if (/file|integrity|syscheck/.test(g))           return 'Intégrité Fichiers';
  if (/vulnerability|cve/.test(g))                 return 'Vulnérabilité';
  if (/policy|compliance/.test(g))                 return 'Conformité';
  return 'Sécurité';
}

/**
 * Transforme une alerte Wazuh en Incident
 * @param {Object} alert  - Alerte brute Wazuh
 * @param {string} userId - ID utilisateur système
 */
function transformAlertToIncident(alert, userId) {
 const src = alert._source || alert;

const rule    = src.rule || {};
const agent   = src.agent || {};
const data    = src.data || {};
const manager = src.manager || {};

  const priority = mapLevelToPriority(rule.level);
  const category = mapGroupsToCategory(rule.groups || []);

  const title = `[Wazuh] ${rule.description || 'Alerte de sécurité'} — ${agent.name || 'Agent inconnu'}`;

  const description = `
**Alerte Wazuh importée automatiquement**

| Champ         | Valeur |
|---------------|--------|
| **Agent**     | ${agent.name || 'N/A'} (ID: ${agent.id || 'N/A'}) |
| **IP Agent**  | ${agent.ip || 'N/A'} |
| **Manager**   | ${manager.name || 'N/A'} |
| **Règle**     | #${rule.id || 'N/A'} — Niveau ${rule.level || 0}/15 |
| **Groupes**   | ${(rule.groups || []).join(', ') || 'N/A'} |
| **MITRE**     | ${(rule.mitre?.id || []).join(', ') || 'N/A'} |
| **Timestamp** | ${src.timestamp || new Date().toISOString()} |

**Description de la règle :**
${rule.description || 'Aucune description disponible.'}

**Données brutes :**
\`\`\`json
${JSON.stringify(data, null, 2).substring(0, 1500)}
\`\`\`
  `.trim();

  return {
    title,
    description,
    priority,
    category,
    status: 'open',
    source: 'wazuh',
    assignedTo: userId,
    metadata: {
      wazuhAlertId:   alert.id,
      wazuhAgentId:   agent.id,
      wazuhAgentName: agent.name,
      wazuhAgentIp:   agent.ip,
      wazuhRuleId:    rule.id,
      wazuhRuleLevel: rule.level,
      wazuhGroups:    rule.groups,
      wazuhMitre:     rule.mitre?.id,
      rawAlert:       alert,
    },
  };
}

// ─── Transformation : Scan Wazuh → ScanReport ──────────────────────────────────

/**
 * Transforme les données Wazuh en ScanReport
 * @param {Object} wazuhData - Données brutes de Wazuh
 * @param {string} userId    - ID utilisateur qui crée le scan
 */
function transformWazuhToScan(wazuhData, userId) {
  const vulnerabilities = wazuhData.vulnerabilities || [];

  const findings = {
    critical: vulnerabilities.filter((v) => v.severity === 9 || v.severity === 10).length,
    high:     vulnerabilities.filter((v) => v.severity === 7 || v.severity === 8).length,
    medium:   vulnerabilities.filter((v) => v.severity === 5 || v.severity === 6).length,
    low:      vulnerabilities.filter((v) => v.severity === 3 || v.severity === 4).length,
  };

  return {
    name:        `Wazuh Scan - ${wazuhData.agent?.name || wazuhData.host || 'Unknown'}`,
    target:      wazuhData.agent?.ip || wazuhData.host || 'unknown',
    scanType:    'vulnerability',
    status:      'completed',
    findings,
    rawOutput:   JSON.stringify(wazuhData, null, 2),
    createdBy:   userId,
    startedAt:   new Date(wazuhData.timestamp || Date.now()),
    completedAt: new Date(),
    metadata: {
      source:       'wazuh',
      wazuhAgentId: wazuhData.agent?.id,
      wazuhScanId:  wazuhData.scan?.id,
    },
  };
}

// ─── Import des scans ──────────────────────────────────────────────────────────

/**
 * Importe les scans depuis Wazuh et les sauvegarde en base de données
 * @param {string} userId   - ID utilisateur qui effectue l'import
 * @param {Object} options  - Filtres optionnels
 */
async function importScansFromWazuh(userId, options = {}) {
  try {
    console.log('[WazuhService] 🔄 Début de l\'import des scans Wazuh...');

    const wazuhScans = await getWazuhScans(options);

    if (!wazuhScans || wazuhScans.length === 0) {
      console.log('[WazuhService] ⚠️  Aucun scan trouvé dans Wazuh');
      return { created: 0, failed: 0, scans: [] };
    }

    let created = 0;
    let failed  = 0;
    const importedScans = [];

    for (const wazuhScan of wazuhScans) {
      try {
        const existingScan = await ScanReport.findOne({
          'metadata.wazuhScanId': wazuhScan.scan?.id,
        });

        if (existingScan) {
          console.log(`[WazuhService] ⚠️  Scan ${wazuhScan.scan?.id} déjà importé`);
          continue;
        }

        const scanData   = transformWazuhToScan(wazuhScan, userId);
        const scanReport = new ScanReport(scanData);
        await scanReport.save();

        importedScans.push(scanReport);
        created++;
        console.log(`[WazuhService] ✅ Scan importé: ${scanReport._id} — "${scanReport.name}"`);
      } catch (err) {
        failed++;
        console.error('[WazuhService] ❌ Erreur import scan:', err.message);
      }
    }

    console.log(`[WazuhService] 📈 Import scans terminé: ${created} créé(s), ${failed} échoué(s)`);
    return { created, failed, scans: importedScans };
  } catch (err) {
    console.error('[WazuhService] ❌ Erreur import Wazuh:', err.message);
    throw err;
  }
}

// ─── Import des alertes → Incidents ───────────────────────────────────────────

/**
 * Importe les alertes Wazuh et les transforme en Incidents
 * @param {string} userId   - ID utilisateur système (admin)
 * @param {Object} options  - Filtres: minLevel, agentId, fromDate, limit
 */
async function importAlertsAsIncidents(userId, options = {}) {
  try {
    console.log('[WazuhService] 🔄 Import des alertes Wazuh → Incidents...');

    // Si pas d'userId fourni, prendre le premier admin
    if (!userId) {
      const admin = await User.findOne({ role: 'admin' }).sort({ createdAt: 1 });
      userId = admin?._id || null;
    }

    const alerts = await getWazuhAlerts(options);

    if (!alerts.length) {
      console.log('[WazuhService] ⚠️  Aucune alerte trouvée');
      return { created: 0, skipped: 0, incidents: [] };
    }

    let created  = 0;
    let skipped  = 0;
    const incidents = [];

    for (const alert of alerts) {
      try {
        // Dédoublonnage par ID d'alerte Wazuh
        const exists = await Incident.findOne({ 'metadata.wazuhAlertId': alert.id });
        if (exists) {
          skipped++;
          continue;
        }

        const incidentData = transformAlertToIncident(alert, userId);
        const incident     = new Incident(incidentData);
        await incident.save();

        incidents.push(incident);
        created++;
        console.log(
          `[WazuhService] ✅ Incident créé: ${incident._id} — Règle ${alert.rule?.id} [${incidentData.priority.toUpperCase()}]`
        );
      } catch (err) {
        console.error('[WazuhService] ❌ Erreur création incident:', err.message);
      }
    }

    console.log(
      `[WazuhService] 📊 Import alertes terminé: ${created} créé(s), ${skipped} ignoré(s)`
    );
    return { created, skipped, incidents };
  } catch (err) {
    console.error('[WazuhService] ❌ Erreur import alertes:', err.message);
    throw err;
  }
}

// ─── Export ────────────────────────────────────────────────────────────────────

module.exports = {
  // Auth
  getWazuhToken,
  // Données brutes
  getWazuhAgents,
  getWazuhScans,
  getWazuhAlerts,
  // Transformations
  transformWazuhToScan,
  transformAlertToIncident,
  // Import DB
  importScansFromWazuh,
  importAlertsAsIncidents,
};