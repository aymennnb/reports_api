const cron = require("node-cron");
const { autoSyncNessus } = require("./nessusAutoSync");
const { autoSyncWazuh  } = require("./wazuhAutoSync");

/**
 * schedulerService.js — Cœur du système d'import automatique.
 *
 * ARCHITECTURE :
 *   Ce fichier crée et gère deux tâches cron indépendantes :
 *     1. jobNessus → appelle autoSyncNessus() selon NESSUS_IMPORT_INTERVAL
 *     2. jobWazuh  → appelle autoSyncWazuh()  selon WAZUH_IMPORT_INTERVAL
 *
 * PROTECTION CONTRE LE CHEVAUCHEMENT :
 *   Si un job tourne encore quand le prochain tick arrive, le nouveau tick
 *   est ignoré (via les flags isRunning). Évite les imports en parallèle
 *   qui créeraient des doublons.
 *
 * RETRY :
 *   En cas d'erreur réseau/API, on réessaie jusqu'à MAX_RETRIES fois
 *   avec un délai exponentiel (RETRY_DELAY_MS × 2^tentative).
 *
 * CONFIGURATION via .env :
 *   NESSUS_IMPORT_INTERVAL=0 */6 * * *    (toutes les 6 heures)
 *   WAZUH_IMPORT_INTERVAL=*/5 * * * *     (toutes les 5 minutes)
 *   IMPORT_MAX_RETRIES=3
 *   IMPORT_RETRY_DELAY_MS=5000
 */

// ── Valeurs par défaut si .env absent ────────────────────────────────────────
const NESSUS_CRON  = process.env.NESSUS_IMPORT_INTERVAL  || "0 */6 * * *";
const WAZUH_CRON   = process.env.WAZUH_IMPORT_INTERVAL   || "*/5 * * * *";
const MAX_RETRIES  = parseInt(process.env.IMPORT_MAX_RETRIES   || "3");
const RETRY_DELAY  = parseInt(process.env.IMPORT_RETRY_DELAY_MS || "5000");

// ── Flags anti-chevauchement ──────────────────────────────────────────────────
let isNessusRunning = false;
let isWazuhRunning  = false;

// ── Utilitaire : attendre N millisecondes ────────────────────────────────────
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * withRetry — Exécute une fonction async avec N tentatives en cas d'erreur.
 *
 * @param {Function} fn       - La fonction à exécuter
 * @param {string}   jobName  - Nom du job pour les logs
 * @param {number}   retries  - Nombre max de tentatives restantes
 * @param {number}   attempt  - Numéro de la tentative courante (pour le délai exponentiel)
 */
const withRetry = async (fn, jobName, retries = MAX_RETRIES, attempt = 0) => {
    try {
        return await fn();
    } catch (err) {
        if (retries <= 0) {
            console.error(`[SCHEDULER] ${jobName} — échec définitif après ${MAX_RETRIES} tentatives: ${err.message}`);
            throw err;
        }

        // Délai exponentiel : 5s, 10s, 20s...
        const delay = RETRY_DELAY * Math.pow(2, attempt);
        console.warn(
            `[SCHEDULER] ${jobName} — erreur (tentative ${attempt + 1}/${MAX_RETRIES}), ` +
            `retry dans ${delay / 1000}s: ${err.message}`
        );

        await sleep(delay);
        return withRetry(fn, jobName, retries - 1, attempt + 1);
    }
};

// ── Job Nessus ────────────────────────────────────────────────────────────────
const startNessusJob = () => {
    if (!cron.validate(NESSUS_CRON)) {
        console.error(`[SCHEDULER] Expression cron Nessus invalide: "${NESSUS_CRON}"`);
        return null;
    }

    const job = cron.schedule(NESSUS_CRON, async () => {
        // ── Protection chevauchement ───────────────────────────────────────
        if (isNessusRunning) {
            console.warn("[SCHEDULER] Job Nessus déjà en cours — tick ignoré");
            return;
        }

        isNessusRunning = true;
        console.log(`[SCHEDULER] Job Nessus démarré (${new Date().toISOString()})`);

        try {
            await withRetry(
                () => autoSyncNessus("scheduler"),
                "Nessus"
            );
        } catch (err) {
            // withRetry a déjà loggué — on laisse passer sans crasher le process
        } finally {
            isNessusRunning = false;
            console.log(`[SCHEDULER] Job Nessus terminé (${new Date().toISOString()})`);
        }
    });

    console.log(`[SCHEDULER] ✓ Job Nessus planifié: "${NESSUS_CRON}"`);
    return job;
};

// ── Job Wazuh ─────────────────────────────────────────────────────────────────
const startWazuhJob = () => {
    if (!cron.validate(WAZUH_CRON)) {
        console.error(`[SCHEDULER] Expression cron Wazuh invalide: "${WAZUH_CRON}"`);
        return null;
    }

    const job = cron.schedule(WAZUH_CRON, async () => {
        if (isWazuhRunning) {
            console.warn("[SCHEDULER] Job Wazuh déjà en cours — tick ignoré");
            return;
        }

        isWazuhRunning = true;
        console.log(`[SCHEDULER] Job Wazuh démarré (${new Date().toISOString()})`);

        try {
            await withRetry(
                () => autoSyncWazuh("scheduler"),
                "Wazuh"
            );
        } catch (err) {
            // withRetry a déjà loggué
        } finally {
            isWazuhRunning = false;
            console.log(`[SCHEDULER] Job Wazuh terminé (${new Date().toISOString()})`);
        }
    });

    console.log(`[SCHEDULER] ✓ Job Wazuh planifié: "${WAZUH_CRON}"`);
    return job;
};

/**
 * initScheduler — Appelée UNE SEULE FOIS au démarrage dans server.js.
 * Lance les deux jobs cron et fait un premier import immédiat au démarrage.
 */
const initScheduler = async () => {
    console.log("════════════════════════════════════════════");
    console.log("[SCHEDULER] Initialisation du scheduler...");
    console.log(`[SCHEDULER] Nessus  : ${NESSUS_CRON}`);
    console.log(`[SCHEDULER] Wazuh   : ${WAZUH_CRON}`);
    console.log(`[SCHEDULER] Retries : ${MAX_RETRIES} × ${RETRY_DELAY}ms`);
    console.log("════════════════════════════════════════════");

    // Lancer les jobs cron
    startNessusJob();
    startWazuhJob();

    // ── Import immédiat au démarrage (optionnel, configurable) ────────────
    // Si IMPORT_ON_START=true dans .env, on lance une première sync de suite.
    if (process.env.IMPORT_ON_START === "true") {
        console.log("[SCHEDULER] IMPORT_ON_START=true → import initial dans 5 secondes...");

        setTimeout(async () => {
            // Wazuh d'abord (plus rapide)
            if (!isWazuhRunning) {
                isWazuhRunning = true;
                try {
                    await withRetry(() => autoSyncWazuh("scheduler"), "Wazuh");
                } catch (_) {
                    // déjà loggué dans withRetry
                } finally {
                    isWazuhRunning = false;
                }
            }

            // Puis Nessus
            if (!isNessusRunning) {
                isNessusRunning = true;
                try {
                    await withRetry(() => autoSyncNessus("scheduler"), "Nessus");
                } catch (_) {
                    // déjà loggué dans withRetry
                } finally {
                    isNessusRunning = false;
                }
            }
        }, 5000);
    }
};

module.exports = { initScheduler };