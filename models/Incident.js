const mongoose = require('mongoose');

const incidentSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      required: true,
    },
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      required: true,
    },
    agent_name: {
      type: String,
      default: 'unknown',
    },
    rule_id: {
      type: String,
      default: null,
    },
    rule_level: {
      type: Number,
      default: null,
    },
    source: {
      type: String,
      enum: ['wazuh', 'manual'],
      default: 'wazuh',
    },
    status: {
      type: String,
      enum: ['open', 'in_progress', 'closed'],
      default: 'open',
    },
    alert_id: {
      type: String,
      default: null,
      unique: true,
      sparse: true, // permet plusieurs null
    },
    timestamp: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model('Incident', incidentSchema);