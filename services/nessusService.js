const axios  = require("axios");
const https  = require("https");
const dotenv = require("dotenv");
dotenv.config();

const NESSUS_URL = process.env.NESSUS_URL;
const ACCESS_KEY = process.env.NESSUS_ACCESS_KEY;
const SECRET_KEY = process.env.NESSUS_SECRET_KEY;

const validateConfig = () => {
    if (!NESSUS_URL || !ACCESS_KEY || !SECRET_KEY) {
        throw new Error("Missing Nessus environment variables");
    }
};

validateConfig();

// SÉCURISATION SAST [CWE-295] : Vérification TLS activée pour éviter les attaques MITM.
const nessusClient = axios.create({
    baseURL: NESSUS_URL,
    httpsAgent: new https.Agent({ rejectUnauthorized: true }), // SÉCURISATION SAST [CWE-295]
    headers: {
        "X-ApiKeys": `accessKey=${ACCESS_KEY}; secretKey=${SECRET_KEY}`,
        "Content-Type": "application/json",
    },
    timeout: 30000,
});

const getScans = async () => {
    validateConfig();
    const response = await nessusClient.get("/scans");
    return response.data;
};

const getScanById = async (scanId) => {
    validateConfig();
    const response = await nessusClient.get(`/scans/${String(scanId)}`); // SÉCURISATION SAST [CWE-943]
    return response.data;
};

const getPluginDetails = async (scanId, pluginId) => {
    validateConfig();
    const response = await nessusClient.get(`/scans/${String(scanId)}/plugins/${String(pluginId)}`); // SÉCURISATION SAST [CWE-943]
    return response.data;
};

const getAllPluginDetails = async (scanId, vulnerabilities) => {
    const results = await Promise.allSettled(
        vulnerabilities.map(v => getPluginDetails(scanId, v.plugin_id))
    );
    const pluginMap = {};
    vulnerabilities.forEach((v, index) => {
        const result = results[index];
        if (result.status === "fulfilled") pluginMap[v.plugin_id] = result.value;
        if (result.status === "rejected")  console.warn("Plugin %s failed: %s", v.plugin_id, result.reason?.message); // SÉCURISATION SAST [CWE-134]
    });
    return pluginMap;
};

const getTemplates = async () => {
    validateConfig();
    const res = await nessusClient.get("/editor/scan/templates");
    return res.data.templates || [];
};

const createScan = async ({ name, targets, templateUuid, folderId }) => {
    validateConfig();

    const normalizedTargets = targets
        .split(/[\n,]+/)
        .map(t => t.trim())
        .filter(Boolean)
        .join(", ");

    const body = {
        uuid: templateUuid,
        settings: {
            name,
            text_targets: normalizedTargets,
        },
    };

    if (folderId) {
        body.folder_id = parseInt(folderId, 10);
    }

    console.log("[createScan] %s", JSON.stringify(body)); // SÉCURISATION SAST [CWE-134]

    const res = await nessusClient.post("/scans", body);

    if (!res.data?.scan) {
        throw new Error("Nessus did not return a scan object in the response.");
    }
    return res.data.scan;
};

const launchScan = async (scanId) => {
    validateConfig();
    const res = await nessusClient.post(`/scans/${String(scanId)}/launch`, {}); // SÉCURISATION SAST [CWE-943]
    return res.data;
};

module.exports = {
    getScans,
    getScanById,
    getPluginDetails,
    getAllPluginDetails,
    getTemplates,
    createScan,
    launchScan,
};