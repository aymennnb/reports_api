const Incident = require("../models/Incident");
const { Permission, RolePermission } = require("../models/Permission");
const { syncWazuhIncidents } = require("../services/wazuhIncidentService");


// ── Vérifier qu'un user possède une permission donnée ────────────────
const hasPermission = async (userId, permissionName) => {
    const perm = await Permission.findOne({ permission_name: permissionName });
    if (!perm) return false;
    const assigned = await RolePermission.findOne({
        user_id: userId,
        permission_id: perm.permission_id
    });
    return !!assigned;
};

const canSync = async (user) => {
    if (user.role === "admin") return true;
    return await hasPermission(user.id, "SYNC_INCIDENTS");
};


// CONSULTATION ════════════════════════════════════════════════════════════════

const getAllIncidents = async (req, res) => {
    try {
        const allowed = await hasPermission(req.user.id, "VIEW_INCIDENTS");
        if (!allowed && req.user.role !== "admin") {
            return res.status(403).json({ message: "Permission required: VIEW_INCIDENTS" });
        }

        const filter = {};
        if (req.query.status)   filter.status   = req.query.status;
        if (req.query.severity) filter.severity = parseInt(req.query.severity);
        if (req.query.agent_name) filter.agent_name = req.query.agent_name;
        if (req.query.source)   filter.source   = req.query.source;
        if (req.query.Source)   filter.source   = req.query.Source;

        if (req.query.title) {
            filter.title = { $regex: req.query.title, $options: "i" };
        }

        if (req.query.time_from || req.query.time_to) {
            filter.timestamp = {};
            if (req.query.time_from) {
                filter.timestamp.$gte = new Date(req.query.time_from);
            }
            if (req.query.time_to) {
                const to = new Date(req.query.time_to);
                to.setHours(23, 59, 59, 999);
                filter.timestamp.$lte = to;
            }
        }

        const incidents = await Incident.find(filter)
            .sort({ severity: -1, timestamp: -1 });

        const payload = incidents.map(i => i.toObject({ virtuals: true }));
        res.status(200).json({ count: payload.length, incidents: payload });
    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};

const getIncidentById = async (req, res) => {
    try {
        const allowed = await hasPermission(req.user.id, "VIEW_INCIDENT_DETAILS");
        if (!allowed && req.user.role !== "admin") {
            return res.status(403).json({ message: "Permission required: VIEW_INCIDENT_DETAILS" });
        }
        const incident = await Incident.findById(req.params.id);
        if (!incident) return res.status(404).json({ message: "Incident not found." });
        res.status(200).json(incident.toObject({ virtuals: true }));
    } catch (error) {
        res.status(400).json({ message: "Invalid incident ID format." });
    }
};

const getStats = async (req, res) => {
    try {
        const allowed = await hasPermission(req.user.id, "VIEW_INCIDENTS");
        if (!allowed && req.user.role !== "admin") {
            return res.status(403).json({ message: "Permission required: VIEW_INCIDENTS" });
        }

        const bySeverity = await Incident.aggregate([
            { $match: { status: "open" } },
            { $group: { _id: "$severity", count: { $sum: 1 } } },
            { $sort: { _id: 1 } }
        ]);

        const byStatus = await Incident.aggregate([
            { $group: { _id: "$status", count: { $sum: 1 } } }
        ]);

        const bySource = await Incident.aggregate([
            { $group: { _id: "$source", count: { $sum: 1 } } }
        ]);

        const oldest_open = await Incident.find({ status: "open" })
            .sort({ timestamp: 1 })
            .limit(5)
            .select("title severity agent_name timestamp");

        res.status(200).json({ bySeverity, byStatus, bySource, oldest_open });
    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};


// CRUD MANUEL ════════════════════════════════════════════════════════════════

const createIncident = async (req, res) => {
    try {
        const allowed = await hasPermission(req.user.id, "CREATE_INCIDENT");
        if (!allowed && req.user.role !== "admin") {
            return res.status(403).json({ message: "Permission required: CREATE_INCIDENT" });
        }

        const { title, description, severity, agent_name, rule_id, rule_level } = req.body;

        if (!title || !description || severity === undefined) {
            return res.status(400).json({ message: "title, description and severity are required." });
        }

        await new Incident({
            title,
            description,
            severity:   parseInt(severity),
            agent_name: agent_name  || "unknown",
            rule_id:    rule_id     || null,
            rule_level: rule_level !== undefined ? parseInt(rule_level) : null,
            source:     "manual",
            status:     "open",
        }).save();

        res.status(201).json({ message: "Incident created successfully." });
    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};

const updateIncident = async (req, res) => {
    try {
        const allowed = await hasPermission(req.user.id, "UPDATE_INCIDENT");
        if (!allowed && req.user.role !== "admin") {
            return res.status(403).json({ message: "Permission required: UPDATE_INCIDENT" });
        }

        const incident = await Incident.findById(req.params.id);
        if (!incident) return res.status(404).json({ message: "Incident not found." });

        const updated = await Incident.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true }
        );

        res.status(200).json({ message: "Incident updated successfully.", incident: updated });
    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};

const deleteIncident = async (req, res) => {
    try {
        const allowed = await hasPermission(req.user.id, "DELETE_INCIDENT");
        if (!allowed && req.user.role !== "admin") {
            return res.status(403).json({ message: "Permission required: DELETE_INCIDENT" });
        }

        const incident = await Incident.findById(req.params.id);
        if (!incident) return res.status(404).json({ message: "Incident not found." });

        await Incident.findByIdAndDelete(req.params.id);
        res.status(200).json({ message: "Incident deleted successfully." });
    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};


// SYNCHRONISATION WAZUH ════════════════════════════════════════════════════════════════

const syncFromWazuh = async (req, res) => {
    try {
        const allowed = await canSync(req.user);
        if (!allowed) {
            return res.status(403).json({ message: "Permission required: SYNC_INCIDENTS" });
        }

        const result = await syncWazuhIncidents();

        res.status(200).json({
            message: `Sync completed: ${result.created} created, ${result.skipped} skipped`,
            data: result,
        });
    } catch (error) {
        console.error("[syncFromWazuh]", error.message);
        res.status(500).json({ message: "Sync failed (Check server logs)." });
    }
};


module.exports = {
    getAllIncidents,
    getIncidentById,
    getStats,
    createIncident,
    updateIncident,
    deleteIncident,
    syncFromWazuh,
};