/**
 * wazuhAlertListener.js
 * Service d'écoute des alertes Wazuh → création automatique d'Incidents
 * Poll l'API Wazuh à intervalle régulier et crée des incidents depuis les alertes
 */

const axios = require('axios');
const https = require('https');
const Incident = require('../models/Incident');
const User = require('../models/User');
const { sendAlertEmail } = require('./emailNotifier');

// ─── Configuration ─────────────────────────────────────────────────────────────
const POLL_INTERVAL_MS = parseInt(process.env.WAZUH_POLL_INTERVAL) || 60_000;

const indexerClient = axios.create({
  baseURL: process.env.WAZUH_INDEXER_URL,
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  timeout: 10000,
});

let lastPollTime = new Date(Date.now() - POLL_INTERVAL_MS);

// ─── Mapping sévérité Wazuh → priorité Incident ────────────────────────────────

function mapSeverityToPriority(ruleLevel = 0) {
  if (ruleLevel >= 15) return 'critical';
  if (ruleLevel >= 12) return 'high';
  if (ruleLevel >= 7)  return 'medium';
  return 'low';
}

function mapGroupsToCategory(groups = []) {
  const groupStr = groups.join(' ').toLowerCase();
  if (/web|http|nginx|apache/.test(groupStr))        return 'Web';
  if (/authentication|login|pam|ssh/.test(groupStr)) return 'Authentification';
  if (/malware|virus|trojan|rootkit/.test(groupStr)) return 'Malware';
  if (/network|firewall|iptables/.test(groupStr))    return 'Réseau';
  if (/file|integrity|syscheck/.test(groupStr))      return 'Intégrité Fichiers';
  if (/vulnerability|cve/.test(groupStr))            return 'Vulnérabilité';
  if (/policy|compliance/.test(groupStr))            return 'Conformité';
  return 'Sécurité';
}

// ─── Récupération des alertes Wazuh ───────────────────────────────────────────

/**
 * Récupère les nouvelles alertes depuis l'indexer Wazuh (Elasticsearch)
 * Filtre par timestamp et niveau minimum
 */
async function fetchNewAlerts() {
  try {
    const minLevel = parseInt(process.env.WAZUH_MIN_LEVEL) || 7;
    const fromDate = lastPollTime.toISOString();

    // Query Elasticsearch directement
    const wazuhConfig = {
      username: (process.env.WAZUH_API_USER || 'wazuh').trim(),
      password: (process.env.WAZUH_API_PASSWORD || 'wazuh').trim(),
    };

    const response = await indexerClient.post(
      '/wazuh-alerts*/_search',
      {
        size: 100,
        query: {
          bool: {
            must: [
              { range: { '@timestamp': { gte: fromDate } } },
              { range: { 'rule.level': { gte: minLevel } } },
            ],
          },
        },
        sort: [{ '@timestamp': 'desc' }],
      },
      {
        auth: {
          username: wazuhConfig.username,
          password: wazuhConfig.password,
        },
      }
    );

    const alerts = response.data.hits.hits || [];
    console.log(`[WazuhAlerts] 📊 ${alerts.length} nouvelle(s) alerte(s) depuis ${fromDate}`);
    return alerts;
  } catch (err) {
    const status = err.response?.status;
    const code = err.code;
    const detail = err.response?.data?.error || err.message;
    
    // Erreurs de connexion
    if (code === 'ECONNREFUSED') {
      console.error(
        `[WazuhAlerts] ❌ Impossible de se connecter à l'indexer: ${process.env.WAZUH_INDEXER_URL}`
      );
      console.error(
        `[WazuhAlerts] 💡 Vérifiez que:\n` +
        `     • Le service Wazuh indexer est démarré\n` +
        `     • L'adresse ${process.env.WAZUH_INDEXER_URL} est accessible\n` +
        `     • Les identifiants Wazuh (${process.env.WAZUH_API_USER}) sont corrects`
      );
    } else {
      console.error(
        `[WazuhAlerts] ❌ Erreur récupération alertes: ${status ? `HTTP ${status} — ` : ''}${JSON.stringify(detail)}`
      );
    }
    return [];
  }
}

// ─── Transformation Alerte → Incident ─────────────────────────────────────────

function buildIncidentFromAlert(alert, userId) {
  // Les alertes de l'indexer ont la structure: alert._source = {...données}
  const src = alert._source || alert;
  
  const rule    = src.rule    || {};
  const agent   = src.agent   || {};
  const data    = src.data    || {};
  const manager = src.manager || {};

  const priority = mapSeverityToPriority(rule.level);
  const category = mapGroupsToCategory(rule.groups || []);
  const title    = `[Wazuh] ${rule.description || 'Alerte de sécurité'} — Agent: ${agent.name || 'Inconnu'}`;

  const description = `
**Alerte Wazuh importée automatiquement**

| Champ         | Valeur |
|---------------|--------|
| **Agent**     | ${agent.name || 'N/A'} (ID: ${agent.id || 'N/A'}) |
| **IP Agent**  | ${agent.ip || 'N/A'} |
| **Manager**   | ${manager.name || 'N/A'} |
| **Règle**     | ${rule.id || 'N/A'} — Niveau ${rule.level || 0} |
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
      wazuhAlertId:   src.id || alert._id,
      wazuhAgentId:   agent.id,
      wazuhAgentName: agent.name,
      wazuhAgentIp:   agent.ip,
      wazuhRuleId:    rule.id,
      wazuhRuleLevel: rule.level,
      wazuhGroups:    rule.groups,
      wazuhMitre:     rule.mitre?.id,
      rawAlert:       src,
    },
  };
}

// ─── Traitement d'un lot d'alertes ────────────────────────────────────────────

async function processAlerts(alerts) {
  if (!alerts.length) return { created: 0, skipped: 0 };

  const systemUser = await User.findOne({ role: 'admin' }).sort({ createdAt: 1 });
  const userId = systemUser?._id || null;

  let created = 0;
  let skipped = 0;

  for (const alert of alerts) {
    try {
      // L'ID unique vient de Elasticsearch
      const alertId = alert._id || alert._source?.id;
      
      const exists = await Incident.findOne({ 'metadata.wazuhAlertId': alertId });
      if (exists) {
        skipped++;
        continue;
      }

      const incidentData = buildIncidentFromAlert(alert, userId);
      const incident = new Incident(incidentData);
      await incident.save();

      created++;
      const ruleId = alert._source?.rule?.id || 'N/A';
      console.log(
        `[WazuhAlerts] ✅ Incident créé: ${incident._id} — Règle ${ruleId} | ${incident.priority.toUpperCase()}`
      );

      // Notification email pour high et critical uniquement
      if (incident.priority === 'critical' || incident.priority === 'high') {
        await sendAlertEmail(incident).catch(err =>
          console.error('[WazuhAlerts] ❌ Email non envoyé:', err.message)
        );
      }

    } catch (err) {
      console.error('[WazuhAlerts] ❌ Erreur création incident:', err.message);
    }
  }

  return { created, skipped };
}

// ─── Boucle de polling ────────────────────────────────────────────────────────

let pollingTimer = null;

async function pollOnce() {
  const cycleStart = new Date();
  console.log(`[WazuhAlerts] 🔄 Cycle de polling démarré à ${cycleStart.toLocaleTimeString('fr-FR')}`);

  const alerts = await fetchNewAlerts();
  const { created, skipped } = await processAlerts(alerts);

  lastPollTime = cycleStart;

  console.log(`[WazuhAlerts] 📊 Cycle terminé — ${created} créé(s), ${skipped} ignoré(s)`);
}

function startWazuhAlertListener() {
  const enableAlerts = process.env.ENABLE_WAZUH_ALERTS === 'true';
  
  if (!enableAlerts) {
    console.log('[WazuhAlerts] ⊘ Service d\'alerte désactivé (ENABLE_WAZUH_ALERTS=false)');
    return;
  }

  if (pollingTimer) {
    console.warn('[WazuhAlerts] ⚠️  Le service est déjà en cours d\'exécution.');
    return;
  }

  const indexerUrl = process.env.WAZUH_INDEXER_URL;
  if (!indexerUrl) {
    console.warn('[WazuhAlerts] ⚠️  WAZUH_INDEXER_URL non configurée. Service désactivé.');
    return;
  }

  console.log(`[WazuhAlerts] 🚀 Démarrage du service — intervalle: ${POLL_INTERVAL_MS / 1000}s`);
  console.log(`[WazuhAlerts] 🎚️  Niveau minimum d'alerte: ${process.env.WAZUH_MIN_LEVEL || 7}`);

  pollOnce();
  pollingTimer = setInterval(pollOnce, POLL_INTERVAL_MS);
}

function stopWazuhAlertListener() {
  if (pollingTimer) {
    clearInterval(pollingTimer);
    pollingTimer = null;
    console.log('[WazuhAlerts] 🛑 Service arrêté.');
  }
}

// ─── Export ────────────────────────────────────────────────────────────────────

module.exports = {
  startWazuhAlertListener,
  stopWazuhAlertListener,
  pollOnce,
};