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
            console.error("[SCHEDULER] %s — échec définitif après %s tentatives: %s", jobName, MAX_RETRIES, err.message); // SÉCURISATION SAST [CWE-134]
            throw err;
        }

        const delay = RETRY_DELAY * Math.pow(2, attempt);
        console.warn(
            "[SCHEDULER] %s — erreur (tentative %s/%s), retry dans %ss: %s", // SÉCURISATION SAST [CWE-134]
            jobName, attempt + 1, MAX_RETRIES, delay / 1000, err.message
        );

        await sleep(delay);
        return withRetry(fn, jobName, retries - 1, attempt + 1);
    }
};

const startNessusJob = () => {
    if (!cron.validate(NESSUS_CRON)) {
        console.error("[SCHEDULER] Expression cron Nessus invalide: \"%s\"", NESSUS_CRON); // SÉCURISATION SAST [CWE-134]
        return null;
    }

    const job = cron.schedule(NESSUS_CRON, async () => {
        if (isNessusRunning) {
            console.warn("[SCHEDULER] Job Nessus déjà en cours (tick ignoré)");
            return;
        }

        isNessusRunning = true;
        console.log("[SCHEDULER] Job Nessus démarré (%s)", new Date().toISOString()); // SÉCURISATION SAST [CWE-134]

        try {
            await withRetry(
                () => autoSyncNessus("scheduler"),
                "Nessus"
            );
        } catch (err) {
        } finally {
            isNessusRunning = false;
            console.log("[SCHEDULER] Job Nessus terminé (%s)", new Date().toISOString()); // SÉCURISATION SAST [CWE-134]
        }
    });

    console.log("[SCHEDULER] Job Nessus planifié: \"%s\"", NESSUS_CRON); // SÉCURISATION SAST [CWE-134]
    return job;
};

const startWazuhJob = () => {
    if (!cron.validate(WAZUH_CRON)) {
        console.error("[SCHEDULER] Expression cron Wazuh invalide: \"%s\"", WAZUH_CRON); // SÉCURISATION SAST [CWE-134]
        return null;
    }

    const job = cron.schedule(WAZUH_CRON, async () => {
        if (isWazuhRunning) {
            console.warn("[SCHEDULER] Job Wazuh déjà en cours (tick ignoré)");
            return;
        }

        isWazuhRunning = true;
        console.log("[SCHEDULER] Job Wazuh démarré (%s)", new Date().toISOString()); // SÉCURISATION SAST [CWE-134]

        try {
            await withRetry(
                () => autoSyncWazuh("scheduler"),
                "Wazuh"
            );
        } catch (err) {
        } finally {
            isWazuhRunning = false;
            console.log("[SCHEDULER] Job Wazuh terminé (%s)", new Date().toISOString()); // SÉCURISATION SAST [CWE-134]
        }
    });

    console.log("[SCHEDULER] Job Wazuh planifié: \"%s\"", WAZUH_CRON); // SÉCURISATION SAST [CWE-134]
    return job;
};

const initScheduler = async () => {
    console.log("[SCHEDULER] Initialisation du scheduler...");
    console.log("[SCHEDULER] Nessus  : %s", NESSUS_CRON); // SÉCURISATION SAST [CWE-134]
    console.log("[SCHEDULER] Wazuh   : %s", WAZUH_CRON); // SÉCURISATION SAST [CWE-134]
    console.log("[SCHEDULER] Retries : %s × %sms", MAX_RETRIES, RETRY_DELAY); // SÉCURISATION SAST [CWE-134]

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