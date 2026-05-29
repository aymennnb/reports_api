'use strict'

const mongoose = require('mongoose')

const ticketSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true,
            trim: true,
        },
        incident_id: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Incident',
            required: true,
        },
        created_by: {
            type: String, // Keycloak user id
            required: true,
        },

        department: {
            id: {
                type: String,
                required: true,
            },
            name: {
                type: String,
                required: true,
            },
        },

        status: {
            type: String,
            enum: ['open', 'in_progress', 'resolved', 'closed'],
            default: 'open',
        },
        priority: {
            type: String,
            enum: ['low', 'medium', 'high', 'critical'],
            default: 'medium',
        },
        notes: {
            type: String,
            default: null,
        },
    },
    {
        timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' },
    }
)

ticketSchema.index({ 'department.id': 1 })
ticketSchema.index({ status: 1 })
ticketSchema.index({ priority: 1 })
ticketSchema.index({ created_at: -1 })

module.exports = mongoose.model('Ticket', ticketSchema)