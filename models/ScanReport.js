const mongoose = require('mongoose');

const ScanReportSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please provide a scan report name'],
      trim: true,
      maxlength: 150
    },
    target: {
      type: String,
      required: [true, 'Please provide a target IP or hostname'],
      trim: true
    },
    scanType: {
      type: String,
      enum: ['network', 'web', 'system', 'vulnerability'],
      required: true
    },
    status: {
      type: String,
      enum: ['pending', 'running', 'completed', 'failed'],
      default: 'pending'
    },
    startedAt: {
      type: Date
    },
    completedAt: {
      type: Date
    },
    findings: {
      critical: { type: Number, default: 0 },
      high:     { type: Number, default: 0 },
      medium:   { type: Number, default: 0 },
      low:      { type: Number, default: 0 }
    },
    rawOutput: {
      type: String,
      maxlength: 50000
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model('ScanReport', ScanReportSchema);