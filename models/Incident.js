const mongoose = require('mongoose');

// Severity is stored as a number (same as Wazuh rule.level mapping):
//   0 = info | 1 = low | 2 = medium | 3 = high | 4 = critical

const IncidentSchema = new mongoose.Schema(
    {
        title: {
            type: String,
            required: true,
            trim: true,
        },
        description: {
            type: String,
            default: '',
        },
        severity: {
            type: Number,
            required: true,
            min: 0,
            max: 4,
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
            default: 'manual',
        },
        status: {
            type: String,
            enum: ['open', 'in_progress', 'resolved'],
            default: 'open',
        },
        alert_id: {
            type: String,
            default: null,
            unique: true,
            sparse: true,
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

module.exports = mongoose.model('Incident', IncidentSchema);