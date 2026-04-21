const ScanReport = require('../models/ScanReport');
const { validationResult } = require('express-validator');
const wazuhService = require('../services/wazuhService');

// Create a new scan report
exports.createScan = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, target, scanType, description } = req.body;

    const scanReport = new ScanReport({
      name,
      target,
      scanType,
      description,
      createdBy: req.user.id,
      status: 'pending'
    });

    await scanReport.save();
    res.status(201).json({
      message: 'Scan report created successfully',
      scanReport
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get all scans with filtering
exports.getAllScans = async (req, res) => {
  try {
    const { status, scanType, page = 1, limit = 10 } = req.query;
    const filter = {};

    if (status) filter.status = status;
    if (scanType) filter.scanType = scanType;

    const scans = await ScanReport.find(filter)
      .populate('createdBy', 'email')
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ createdAt: -1 });

    const total = await ScanReport.countDocuments(filter);

    res.status(200).json({
      scans,
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

// Get scan report by ID
exports.getScanById = async (req, res) => {
  try {
    const { id } = req.params;
    const scanReport = await ScanReport.findById(id)
      .populate('createdBy', 'email');

    if (!scanReport) {
      return res.status(404).json({ message: 'Scan report not found' });
    }

    res.status(200).json(scanReport);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get scan summary (statistics)
exports.getScanSummary = async (req, res) => {
  try {
    const summary = await ScanReport.aggregate([
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    const typeBreakdown = await ScanReport.aggregate([
      {
        $group: {
          _id: '$scanType',
          count: { $sum: 1 }
        }
      }
    ]);

    res.status(200).json({
      statusBreakdown: summary,
      typeBreakdown: typeBreakdown,
      totalScans: await ScanReport.countDocuments()
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Update scan status
exports.updateScanStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const validStatuses = ['pending', 'running', 'completed', 'failed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Invalid status value' });
    }

    const scanReport = await ScanReport.findByIdAndUpdate(
      id,
      { status, updatedAt: Date.now() },
      { new: true, runValidators: true }
    );

    if (!scanReport) {
      return res.status(404).json({ message: 'Scan report not found' });
    }

    res.status(200).json({
      message: 'Scan status updated successfully',
      scanReport
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Delete scan report
exports.deleteScan = async (req, res) => {
  try {
    const { id } = req.params;
    const scanReport = await ScanReport.findByIdAndDelete(id);

    if (!scanReport) {
      return res.status(404).json({ message: 'Scan report not found' });
    }

    res.status(200).json({ message: 'Scan report deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Import scans from Wazuh
exports.importFromWazuh = async (req, res) => {
  try {
    const { agentId, limit, offset } = req.query;
    
    const options = {};
    if (agentId) options.agentId = agentId;
    if (limit) options.limit = parseInt(limit);
    if (offset) options.offset = parseInt(offset);

    const result = await wazuhService.importScansFromWazuh(req.user.id, options);

    res.status(201).json({
      message: 'Scans imported from Wazuh successfully',
      summary: {
        created: result.created,
        failed: result.failed,
        total: result.created + result.failed
      },
      scans: result.scans
    });
  } catch (error) {
    console.error('Error importing from Wazuh:', error);
    res.status(500).json({ error: error.message || 'Failed to import from Wazuh' });
  }
};

// Get Wazuh agents
exports.getWazuhAgents = async (req, res) => {
  try {
    const agents = await wazuhService.getWazuhAgents();

    res.status(200).json({
      message: 'Wazuh agents retrieved successfully',
      count: agents.length,
      agents
    });
  } catch (error) {
    console.error('Error retrieving Wazuh agents:', error);
    res.status(500).json({ error: error.message || 'Failed to retrieve Wazuh agents' });
  }
};
