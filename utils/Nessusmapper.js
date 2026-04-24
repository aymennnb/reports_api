// ── Helper : extraire les CVEs depuis ref_information ────────────────────────
const extractCVEs = (pluginAttributes) => {
    const refs = pluginAttributes?.ref_information?.ref || [];
    const cveRef = refs.find(r => r.name === "cve");
    const values = cveRef?.values?.value || [];
    return Array.isArray(values) ? values : [values];
};


// ── Helper : extraire le port depuis outputs[0].ports ────────────────────────
const extractPort = (outputs) => {
    const firstOutput = outputs?.[0];
    if (!firstOutput?.ports) return null;
    const portKeys = Object.keys(firstOutput.ports);
    return portKeys[0] || null;  // Ex: "443 / tcp / https" ou "0 / tcp / "
};


// ── Transformer un seul plugin (response3) en détails propres ────────────────
const mapPluginDetails = (r3) => {
    if (!r3) return {};

    const attrs    = r3?.info?.plugindescription?.pluginattributes || {};
    const risk     = attrs.risk_information || {};
    const outputs  = r3?.outputs || [];

    return {
        synopsis:         attrs.synopsis         || null,
        description:      attrs.description      || null,
        solution:         attrs.solution         || null,
        cvss_base_score:  risk.cvss_base_score   || null,
        cvss3_base_score: risk.cvss3_base_score  || null,
        cve:              extractCVEs(attrs),
        port:             extractPort(outputs),
        plugin_output:    outputs[0]?.plugin_output || null
    };
};


// ── Transformer un scan complet en payload pour syncFromNessus ────────────────
// Input  : scanId (string), scanDetail (response2), pluginMap (map plugin_id → response3)
// Output : payload prêt à être utilisé par vulnerabilityController.syncFromNessus()
const buildSyncPayload = (scanId, scanDetail, pluginMap = {}) => {

    const hosts = (scanDetail.hosts || []).map(h => ({
        hostname: h.hostname,
        host_id:  h.host_id,
        score:    h.score
    }));

    const vulnerabilities = (scanDetail.vulnerabilities || []).map(v => ({
        plugin_id:     v.plugin_id,
        plugin_name:   v.plugin_name,
        plugin_family: v.plugin_family,
        severity:      v.severity,
        vpr_score:     v.vpr_score   || null,
        epss_score:    v.epss_score  || null
    }));

    const plugin_details = {};
    for (const [pluginId, r3] of Object.entries(pluginMap)) {
        plugin_details[pluginId] = mapPluginDetails(r3);
    }

    return {
        scan_id:        String(scanId),
        hosts,
        vulnerabilities,
        plugin_details
    };
};


module.exports = { buildSyncPayload, mapPluginDetails };