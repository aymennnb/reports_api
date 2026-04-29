const Incident = require('../models/Incident');
const { syncWazuhIncidents } = require('../services/wazuhIncidentService');
const { Permission, RolePermission } = require("../models/Permission");

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

// ─── GET /incidents ───────────────────────────────────────────────────────────
const getAllIncidents = async (req, res) => {
  try {
    const allowed = await hasPermission(req.user.id, "VIEW_INCIDENTS");
    if (!allowed && req.user.role !== "admin") {
      return res.status(403).json({ message: "Permission required: VIEW_INCIDENTS" });
    }

    const filter = {};
    if (req.query.status)   filter.status   = req.query.status;
    if (req.query.severity) filter.severity = parseInt(req.query.severity, 10);
    if (req.query.source)   filter.source   = req.query.source;

    const incidents = await Incident.find(filter)
      .sort({ severity: -1, timestamp: -1 });

    const payload = incidents.map(i => i.toObject({ virtuals: true }));
    res.status(200).json({ count: payload.length, incidents: payload });
  } catch (error) {
    console.error("[getAllIncidents ERROR]:", error);
    res.status(500).json({ message: "Server error." });
  }
};

// ─── GET /incidents/:id ───────────────────────────────────────────────────────
const getIncidentById = async (req, res) => {
  try {
    const allowed = await hasPermission(req.user.id, "VIEW_INCIDENT_DETAILS");
    if (!allowed && req.user.role !== "admin") {
      return res.status(403).json({ message: "Permission required: VIEW_INCIDENT_DETAILS" });
    }

    const incident = await Incident.findById(req.params.id);
    if (!incident) return res.status(404).json({ message: "Incident not found." });

    res.status(200).json(incident.toObject({ virtuals: true }));
  } catch (err) {
    console.error('[IncidentsController] getIncidentById:', err.message);
    res.status(400).json({ message: "Invalid incident ID format." });
  }
};

// ─── POST /incidents ──────────────────────────────────────────────────────────
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
      severity,
      agent_name: agent_name || 'unknown',
      rule_id:    rule_id    || null,
      rule_level: rule_level || null,
      source:     'manual',
      status:     'open',
    }).save();

    res.status(201).json({ message: "Incident created successfully." });
  } catch (err) {
    console.error('[IncidentsController] createIncident:', err.message);
    res.status(500).json({ message: "Server error." });
  }
};

// ─── PUT /incidents/:id ───────────────────────────────────────────────────────
const updateIncident = async (req, res) => {
  try {
    const allowed = await hasPermission(req.user.id, "UPDATE_INCIDENT");
    if (!allowed && req.user.role !== "admin") {
      return res.status(403).json({ message: "Permission required: UPDATE_INCIDENT" });
    }

    const allowedFields = ['status', 'severity', 'title', 'description'];
    const updates = {};
    allowedFields.forEach((field) => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ message: "No updatable fields provided." });
    }

    const incident = await Incident.findByIdAndUpdate(
      req.params.id,
      { $set: updates },
      { new: true, runValidators: true }
    );
    if (!incident) return res.status(404).json({ message: "Incident not found." });

    res.status(200).json({ message: "Incident updated successfully.", incident });
  } catch (err) {
    console.error('[IncidentsController] updateIncident:', err.message);
    res.status(500).json({ message: "Server error." });
  }
};

// ─── DELETE /incidents/:id ────────────────────────────────────────────────────
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
  } catch (err) {
    console.error('[IncidentsController] deleteIncident:', err.message);
    res.status(500).json({ message: "Server error." });
  }
};

// ─── POST /incidents/sync ─────────────────────────────────────────────────────
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
  } catch (err) {
    console.error('[IncidentsController] syncFromWazuh:', err.message);
    res.status(500).json({ message: "Sync failed (Check server logs)." });
  }
};

// ─── GET /incidents/stats ─────────────────────────────────────────────────────
const getStats = async (req, res) => {
  try {
    const allowed = await hasPermission(req.user.id, "VIEW_INCIDENTS");
    if (!allowed && req.user.role !== "admin") {
      return res.status(403).json({ message: "Permission required: VIEW_INCIDENTS" });
    }

    const [byStatus, bySeverity, bySource, total] = await Promise.all([
      Incident.aggregate([{ $group: { _id: '$status',   count: { $sum: 1 } } }]),
      Incident.aggregate([{ $group: { _id: '$severity', count: { $sum: 1 } } }]),
      Incident.aggregate([{ $group: { _id: '$source',   count: { $sum: 1 } } }]),
      Incident.countDocuments(),
    ]);

    res.status(200).json({ total, byStatus, bySeverity, bySource });
  } catch (err) {
    console.error('[IncidentsController] getStats:', err.message);
    res.status(500).json({ message: "Server error." });
  }
};

module.exports = {
  getAllIncidents,
  getIncidentById,
  createIncident,
  updateIncident,
  deleteIncident,
  syncFromWazuh,
  getStats,
};
