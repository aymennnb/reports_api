const cron = require("node-cron");
const { autoSyncNessus } = require("./nessusAutoSync");
const { autoSyncWazuh  } = require("./wazuhAutoSync");

const NESSUS_CRON  = process.env.NESSUS_IMPORT_INTERVAL;
const WAZUH_CRON   = process.env.WAZUH_IMPORT_INTERVAL;
const MAX_RETRIES  = parseInt(process.env.IMPORT_MAX_RETRIES);
const RETRY_DELAY  = parseInt(process.env.IMPORT_RETRY_DELAY_MS);

let isNessusRunning = false;
let isWazuhRunning  = false;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const withRetry = async (fn, jobName, retries = MAX_RETRIES, attempt = 0) => {
    try {
        return await fn();
    } catch (err) {
        if (retries <= 0) {
            console.error(`[SCHEDULER] ${jobName} — échec définitif après ${MAX_RETRIES} tentatives: ${err.message}`);
            throw err;
        }

        const delay = RETRY_DELAY * Math.pow(2, attempt);
        console.warn(
            `[SCHEDULER] ${jobName} — erreur (tentative ${attempt + 1}/${MAX_RETRIES}), ` +
            `retry dans ${delay / 1000}s: ${err.message}`
        );

        await sleep(delay);
        return withRetry(fn, jobName, retries - 1, attempt + 1);
    }
};

const startNessusJob = () => {
    if (!cron.validate(NESSUS_CRON)) {
        console.error(`[SCHEDULER] Expression cron Nessus invalide: "${NESSUS_CRON}"`);
        return null;
    }

    const job = cron.schedule(NESSUS_CRON, async () => {
        if (isNessusRunning) {
            console.warn("[SCHEDULER] Job Nessus déjà en cours (tick ignoré)");
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
        } finally {
            isNessusRunning = false;
            console.log(`[SCHEDULER] Job Nessus terminé (${new Date().toISOString()})`);
        }
    });

    console.log(`[SCHEDULER] Job Nessus planifié: "${NESSUS_CRON}"`);
    return job;
};

const startWazuhJob = () => {
    if (!cron.validate(WAZUH_CRON)) {
        console.error(`[SCHEDULER] Expression cron Wazuh invalide: "${WAZUH_CRON}"`);
        return null;
    }

    const job = cron.schedule(WAZUH_CRON, async () => {
        if (isWazuhRunning) {
            console.warn("[SCHEDULER] Job Wazuh déjà en cours (tick ignoré)");
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
        } finally {
            isWazuhRunning = false;
            console.log(`[SCHEDULER] Job Wazuh terminé (${new Date().toISOString()})`);
        }
    });

    console.log(`[SCHEDULER] Job Wazuh planifié: "${WAZUH_CRON}"`);
    return job;
};

const initScheduler = async () => {
    console.log("[SCHEDULER] Initialisation du scheduler...");
    console.log(`[SCHEDULER] Nessus  : ${NESSUS_CRON}`);
    console.log(`[SCHEDULER] Wazuh   : ${WAZUH_CRON}`);
    console.log(`[SCHEDULER] Retries : ${MAX_RETRIES} × ${RETRY_DELAY}ms`);
-
    startNessusJob();
    startWazuhJob();

    if (process.env.IMPORT_ON_START === "true") {
        console.log("[SCHEDULER] IMPORT_ON_START=true → import initial dans 5 secondes...");

        setTimeout(async () => {
            if (!isWazuhRunning) {
                isWazuhRunning = true;
                try {
                    await withRetry(() => autoSyncWazuh("scheduler"), "Wazuh");
                } catch (_) {
                } finally {
                    isWazuhRunning = false;
                }
            }

            if (!isNessusRunning) {
                isNessusRunning = true;
                try {
                    await withRetry(() => autoSyncNessus("scheduler"), "Nessus");
                } catch (_) {
                } finally {
                    isNessusRunning = false;
                }
            }
        }, 5000);
    }
};

module.exports = { initScheduler };