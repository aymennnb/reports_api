const axios  = require("axios");
const https  = require("https");
const dotenv = require("dotenv");
dotenv.config();

const NESSUS_URL    = process.env.NESSUS_URL;
const ACCESS_KEY    = process.env.NESSUS_ACCESS_KEY;
const SECRET_KEY    = process.env.NESSUS_SECRET_KEY;

const validateConfig = () => {
    if (!NESSUS_URL || !ACCESS_KEY || !SECRET_KEY) {
        throw new Error("Missing Nessus environment variables");
    }
};

// ── Configuration axios pour Nessus ───────────────────────────────────────────
validateConfig();
const nessusClient = axios.create({
    baseURL: NESSUS_URL,
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    headers: {
        "X-ApiKeys": `accessKey=${ACCESS_KEY}; secretKey=${SECRET_KEY}`,
        "Content-Type": "application/json"
    },
    timeout: 30000
});


// ── 1. Récupérer la liste de tous les scans ───────────────────────────────────
const getScans = async () => {
    validateConfig();
    const response = await nessusClient.get("/scans");
    return response.data;
};


// ── 2. Récupérer le détail d'un scan par ID ───────────────────────────────────
const getScanById = async (scanId) => {
    validateConfig();
    const response = await nessusClient.get(`/scans/${scanId}`);
    return response.data;
};


// ── 3. Récupérer les détails d'un plugin pour un scan donné ──────────────────
const getPluginDetails = async (scanId, pluginId) => {
    validateConfig();
    const response = await nessusClient.get(`/scans/${scanId}/plugins/${pluginId}`);
    return response.data;
};


// ── 4. Récupérer les détails de TOUS les plugins d'un scan ───────────────────
const getAllPluginDetails = async (scanId, vulnerabilities) => {
    const results = await Promise.allSettled(
        vulnerabilities.map(v => getPluginDetails(scanId, v.plugin_id))
    );

    const pluginMap = {};
    vulnerabilities.forEach((v, index) => {
        const result = results[index];
        if (result.status === "fulfilled") {
            pluginMap[v.plugin_id] = result.value;
        }
        if (result.status === "rejected") {
            console.warn(`Plugin ${v.plugin_id} failed:`, result.reason?.message);
        }
    });

    return pluginMap;
};

module.exports = {getScans, getScanById, getPluginDetails, getAllPluginDetails};