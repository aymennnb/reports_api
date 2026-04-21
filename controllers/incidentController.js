const Incident = require('../models/Incident');
const { validationResult } = require('express-validator');

// Create a new incident
exports.createIncident = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { title, description, severity, affectedAssets, scanReportId } = req.body;

    const incident = new Incident({
      title,
      description,
      severity,
      affectedAssets,
      scanReportId,
      createdBy: req.user.id, // from auth middleware
      status: 'open'
    });

    await incident.save();
    res.status(201).json({
      message: 'Incident created successfully',
      incident
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get all incidents with filtering
exports.getAllIncidents = async (req, res) => {
  try {
    const { severity, status, page = 1, limit = 10 } = req.query;
    const filter = {};

    if (severity) filter.severity = severity;
    if (status) filter.status = status;

    const incidents = await Incident.find(filter)
      .populate('scanReportId', 'name')
      .populate('createdBy', 'email')
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ createdAt: -1 });

    const total = await Incident.countDocuments(filter);

    res.status(200).json({
      incidents,
      pagination: {
        total,
        pages: Math.ceil(total / limit),
        currentPage: page
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get incident by ID
exports.getIncidentById = async (req, res) => {
  try {
    const { id } = req.params;
    const incident = await Incident.findById(id)
      .populate('scanReportId')
      .populate('createdBy', 'email');

    if (!incident) {
      return res.status(404).json({ message: 'Incident not found' });
    }

    res.status(200).json(incident);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Update incident
exports.updateIncident = async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, severity, status, affectedAssets } = req.body;

    const incident = await Incident.findByIdAndUpdate(
      id,
      {
        title,
        description,
        severity,
        status,
        affectedAssets,
        updatedAt: Date.now()
      },
      { new: true, runValidators: true }
    );

    if (!incident) {
      return res.status(404).json({ message: 'Incident not found' });
    }

    res.status(200).json({
      message: 'Incident updated successfully',
      incident
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Resolve incident
exports.resolveIncident = async (req, res) => {
  try {
    const { id } = req.params;
    const { resolution, resolvedBy } = req.body;

    const incident = await Incident.findByIdAndUpdate(
      id,
      {
        status: 'resolved',
        resolution,
        resolvedBy,
        resolvedAt: Date.now()
      },
      { new: true }
    );

    if (!incident) {
      return res.status(404).json({ message: 'Incident not found' });
    }

    res.status(200).json({
      message: 'Incident resolved successfully',
      incident
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Delete incident
exports.deleteIncident = async (req, res) => {
  try {
    const { id } = req.params;
    const incident = await Incident.findByIdAndDelete(id);

    if (!incident) {
      return res.status(404).json({ message: 'Incident not found' });
    }

    res.status(200).json({ message: 'Incident deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get incidents by severity
exports.getIncidentsBySeverity = async (req, res) => {
  try {
    const incidents = await Incident.find()
      .sort({ severity: -1 })
      .populate('scanReportId');

    const groupedBySeverity = incidents.reduce((acc, incident) => {
      if (!acc[incident.severity]) {
        acc[incident.severity] = [];
      }
      acc[incident.severity].push(incident);
      return acc;
    }, {});

    res.status(200).json(groupedBySeverity);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};