'use strict'

const { Schema, model, Types } = require('mongoose')

const ACTIONS = [
    'CREATE_USER',
    'UPDATE_USER',
    'DELETE_USER',
    'ACTIVATE_USER',
    'DEACTIVATE_USER',
    'ASSIGN_ROLE',

    'CREATE_INCIDENT',
    'UPDATE_INCIDENT',
    'DELETE_INCIDENT',
    'SYNC_INCIDENTS',

    'CREATE_TICKET',
    'UPDATE_TICKET',
    'DELETE_TICKET',
    'ASSIGN_TICKET',
    'CHANGE_TICKET_STATUS',

    'CREATE_VULNERABILITY',
    'UPDATE_VULNERABILITY',
    'DELETE_VULNERABILITY',
    'SYNC_VULNERABILITIES',
    'LOGIN_SUCCESS',
    'LOGIN_FAILED',
    'LOGOUT',

     'ASSIGN_PERMISSION',
     'UNASSIGN_PERMISSION',
]

const TARGET_TYPES = [
    'User',
    'Incident',
    'Ticket',
    'Vulnerability',
    'System',
    'Authentication'
]

const JournalSchema = new Schema(
    {
        user_id: {
            type:     String,
            required: true,
            index:    true,
        },
        username: {
            type:    String,
            default: null,
        },

        action: {
            type:     String,
            required: true,
            enum:     ACTIONS,
            index:    true,
        },

        target_type: {
            type:     String,
            required: true,
            enum:     TARGET_TYPES,
            index:    true,
        },
        target_id: {
            type:    String,
            default: null,
            index:   true,
        },

        metadata: {
            type:    Schema.Types.Mixed,
            default: {},
        },

        ip_address: {
            type:    String,
            default: null,
        },

        status: {
            type:    String,
            enum:    ['success', 'failure'],
            default: 'success',
        },
    },
    {
        timestamps: { createdAt: 'created_at', updatedAt: false },
        versionKey: false,
    }
)

JournalSchema.index({ user_id: 1, created_at: -1 })

JournalSchema.index({ target_type: 1, target_id: 1, created_at: -1 })

JournalSchema.index({ created_at: -1 })

module.exports = model('Journal', JournalSchema, 'journaux')
module.exports.ACTIONS      = ACTIONS
module.exports.TARGET_TYPES = TARGET_TYPES