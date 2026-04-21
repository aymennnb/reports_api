const mongoose = require('mongoose');

const IncidentSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, 'Please provide an incident title'],
      trim: true,
      maxlength: 100
    },
    description: {
      type: String,
      required: [true, 'Please provide a description'],
      maxlength: 1000
    },
    severity: {
      type: String,
      enum: ['critical', 'high', 'medium', 'low'],
      required: [true, 'Please specify severity level'],
      default: 'medium'
    },
    status: {
      type: String,
      enum: ['open', 'in-progress', 'resolved', 'closed'],
      default: 'open'
    },
    affectedAssets: [
      {
        type: String,
        description: 'IP addresses, hostnames, or asset identifiers'
      }
    ],
    scanReportId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'ScanReport',
      required: false
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    resolution: {
      type: String,
      maxlength: 500
    },
    resolvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    resolvedAt: {
      type: Date
    },
    updatedAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model('Incident', IncidentSchema);