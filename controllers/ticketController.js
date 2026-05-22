'use strict'

// ─── Ticket Controller ─────────────────────────────────────────────────────
//
// Authorization is enforced BOTH at route-level (ticketRoutes.js middleware)
// AND inside each handler (defense in depth), mirroring vulnerabilityController.js.

const Ticket   = require('../models/Ticket')
const Incident = require('../models/Incident')
const { KeycloakAdmin } = require('../services/keycloakAdmin')
const { Types } = require('mongoose')
const { logAction } = require('../services/journalService')

// ─── Permission helpers (mirrors vulnerabilityController.js exactly) ──────────

const getRoles = (req) => req.keycloakUser?.roles || req.user?.roles || []

const isAdmin = (req) => getRoles(req).includes('admin')

const hasPermission = (req, permissionName) => {
    if (isAdmin(req)) return true
    return getRoles(req).includes(permissionName)
}

// ─── Misc helpers ─────────────────────────────────────────────────────────────

const isValidObjectId = (id) => Types.ObjectId.isValid(id)

// ─── populateTicket ───────────────────────────────────────────────────────────

const populateTicket = async (ticket) => {
    const obj = ticket.toObject({ virtuals: true })

    const incident = await Incident.findById(ticket.incident_id).lean()

    let assignedUser  = null
    let createdByUser = null
    try {
        assignedUser  = await KeycloakAdmin.getUserById(ticket.assigned_to)
        createdByUser = await KeycloakAdmin.getUserById(ticket.created_by)
    } catch (_) {}

    return {
        ...obj,
        incident: incident || null,
        assigned_user: assignedUser
            ? {
                  id:        assignedUser.id,
                  username:  assignedUser.username,
                  email:     assignedUser.email,
                  firstName: assignedUser.firstName,
                  lastName:  assignedUser.lastName,
              }
            : { id: ticket.assigned_to },
        created_by_user: createdByUser
            ? {
                  id:        createdByUser.id,
                  username:  createdByUser.username,
                  email:     createdByUser.email,
                  firstName: createdByUser.firstName,
                  lastName:  createdByUser.lastName,
              }
            : { id: ticket.created_by },
    }
}

// ─── GET /tickets ─────────────────────────────────────────────────────────────

const getAllTickets = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'VIEW_TICKETS')
        if (!allowed) return res.status(403).json({ message: 'Permission required: VIEW_TICKETS' })

        const filter = {}
        if (req.query.status)      filter.status      = req.query.status
        if (req.query.priority)    filter.priority    = req.query.priority
        if (req.query.assigned_to) filter.assigned_to = req.query.assigned_to
        if (req.query.created_by)  filter.created_by  = req.query.created_by

        const tickets = await Ticket.find(filter).sort({ created_at: -1 })
        const payload = await Promise.all(tickets.map(populateTicket))

        res.status(200).json({ count: payload.length, tickets: payload })
    } catch (error) {
        console.error('[getAllTickets]', error)
        res.status(500).json({ message: 'Server error.' })
    }
}

// ─── GET /tickets/mine ────────────────────────────────────────────────────────

const getMyTickets = async (req, res) => {
    try {
        const tickets = await Ticket.find({
            assigned_to: req.keycloakUser.id,
        }).sort({ created_at: -1 })

        const payload = await Promise.all(tickets.map(populateTicket))
        res.status(200).json({ count: payload.length, tickets: payload })
    } catch (error) {
        console.error('[getMyTickets]', error)
        res.status(500).json({ message: 'Server error.' })
    }
}

// ─── GET /tickets/stats ───────────────────────────────────────────────────────

const getTicketStats = async (req, res) => {
    try {
        const canViewAll = hasPermission(req, 'VIEW_TICKETS')
        const matchAll   = canViewAll ? {} : { assigned_to: req.keycloakUser.id }
        const myFilter   = { assigned_to: req.keycloakUser.id }

        const [byStatus, byPriority, myTickets, total] = await Promise.all([
            Ticket.aggregate([{ $match: matchAll }, { $group: { _id: '$status',   count: { $sum: 1 } } }]),
            Ticket.aggregate([{ $match: matchAll }, { $group: { _id: '$priority', count: { $sum: 1 } } }]),
            Ticket.countDocuments(myFilter),
            Ticket.countDocuments(matchAll),
        ])

        res.status(200).json({ total, my_tickets: myTickets, by_status: byStatus, by_priority: byPriority })
    } catch (error) {
        console.error('[getTicketStats]', error)
        res.status(500).json({ message: 'Server error.' })
    }
}

// ─── GET /tickets/:id ─────────────────────────────────────────────────────────

const getTicketById = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'VIEW_TICKETS')
        if (!allowed) return res.status(403).json({ message: 'Permission required: VIEW_TICKETS' })

        if (!isValidObjectId(req.params.id)) {
            return res.status(400).json({ message: 'Invalid ticket ID format.' })
        }
        const ticket = await Ticket.findById(req.params.id)
        if (!ticket) return res.status(404).json({ message: 'Ticket not found.' })

        res.status(200).json(await populateTicket(ticket))
    } catch (error) {
        res.status(400).json({ message: 'Invalid ticket ID format.' })
    }
}

// ─── GET /incidents/:id/tickets ───────────────────────────────────────────────

const getTicketsByIncident = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'VIEW_TICKETS')
        if (!allowed) return res.status(403).json({ message: 'Permission required: VIEW_TICKETS' })

        if (!isValidObjectId(req.params.id)) {
            return res.status(400).json({ message: 'Invalid incident ID format.' })
        }
        const incident = await Incident.findById(req.params.id)
        if (!incident) return res.status(404).json({ message: 'Incident not found.' })

        const tickets = await Ticket.find({ incident_id: req.params.id }).sort({ created_at: -1 })
        const payload = await Promise.all(tickets.map(populateTicket))

        res.status(200).json({ count: payload.length, tickets: payload })
    } catch (error) {
        res.status(400).json({ message: 'Invalid incident ID format.' })
    }
}

// ─── POST /tickets ────────────────────────────────────────────────────────────

const createTicket = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'CREATE_TICKET')
        if (!allowed) return res.status(403).json({ message: 'Permission required: CREATE_TICKET' })

        const { name, incident_id, assigned_to, priority, notes } = req.body

        if (!name?.trim()) {
            return res.status(400).json({ message: 'name is required.' })
        }
        if (!incident_id || !assigned_to) {
            return res.status(400).json({ message: 'incident_id and assigned_to are required.' })
        }
        if (!isValidObjectId(incident_id)) {
            return res.status(400).json({ message: 'Invalid incident_id format.' })
        }

        const incident = await Incident.findById(incident_id)
        if (!incident) return res.status(404).json({ message: 'Incident not found.' })

        try {
            await KeycloakAdmin.getUserById(assigned_to)
        } catch (err) {
            console.error('[createTicket] getUserById failed:', err.response?.status, err.response?.data || err.message)
            return res.status(404).json({ message: 'Assigned user not found in Keycloak.' })
        }

        const ticket = await new Ticket({
            name:        name.trim(),
            incident_id,
            created_by:  req.keycloakUser.id,
            assigned_to,
            priority:    priority || 'medium',
            notes:       notes    || null,
            status:      'open',
        }).save()

        await logAction(req, {
            action:      'CREATE_TICKET',
            target_type: 'Ticket',
            target_id:   ticket._id,
            metadata:    {
                name:        ticket.name,
                incident_id: String(incident_id),
                assigned_to,
                priority:    ticket.priority,
            },
        })

        // Journal secondaire : ASSIGN_TICKET (acte d'affectation explicite à la création)
        await logAction(req, {
            action:      'ASSIGN_TICKET',
            target_type: 'Ticket',
            target_id:   ticket._id,
            metadata:    { assigned_to, incident_id: String(incident_id), on_create: true },
        })

        res.status(201).json({
            message: 'Ticket created successfully.',
            ticket:  await populateTicket(ticket),
        })
    } catch (error) {
        console.error('[createTicket]', error)
        res.status(500).json({ message: 'Server error.' })
    }
}

// ─── PUT /tickets/:id ────────────────────────────────────────────────────────

const updateTicket = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'UPDATE_TICKET')
        if (!allowed) return res.status(403).json({ message: 'Permission required: UPDATE_TICKET' })

        if (!isValidObjectId(req.params.id)) {
            return res.status(400).json({ message: 'Invalid ticket ID format.' })
        }

        const ticket = await Ticket.findById(req.params.id)
        if (!ticket) return res.status(404).json({ message: 'Ticket not found.' })

        const allowed_fields = ['name', 'status', 'priority', 'notes', 'assigned_to']
        const updates = {}
        allowed_fields.forEach(f => { if (req.body[f] !== undefined) updates[f] = req.body[f] })

        if (updates.assigned_to) {
            try {
                await KeycloakAdmin.getUserById(updates.assigned_to)
            } catch (err) {
                console.error('[updateTicket] getUserById failed:', err.response?.status, err.response?.data || err.message)
                return res.status(404).json({ message: 'Assigned user not found in Keycloak.' })
            }
        }

        const updated = await Ticket.findByIdAndUpdate(req.params.id, updates, { new: true })

        // ── Journal UPDATE_TICKET (toujours) ──────────────────────────────────
        await logAction(req, {
            action:      'UPDATE_TICKET',
            target_type: 'Ticket',
            target_id:   ticket._id,
            metadata:    {
                name:            ticket.name,
                fields_updated:  Object.keys(updates),
                incident_id:     String(ticket.incident_id),
            },
        })

        // ── Journal ASSIGN_TICKET (si le champ assigned_to a changé) ─────────
        if (updates.assigned_to && updates.assigned_to !== ticket.assigned_to) {
            await logAction(req, {
                action:      'ASSIGN_TICKET',
                target_type: 'Ticket',
                target_id:   ticket._id,
                metadata:    {
                    previous_assignee: ticket.assigned_to,
                    new_assignee:      updates.assigned_to,
                },
            })
        }

        // ── Journal CHANGE_TICKET_STATUS (si le statut a changé) ─────────────
        if (updates.status && updates.status !== ticket.status) {
            await logAction(req, {
                action:      'CHANGE_TICKET_STATUS',
                target_type: 'Ticket',
                target_id:   ticket._id,
                metadata:    {
                    previous_status: ticket.status,
                    new_status:      updates.status,
                },
            })
        }

        res.status(200).json({ message: 'Ticket updated successfully.', ticket: await populateTicket(updated) })
    } catch (error) {
        console.error('[updateTicket]', error)
        res.status(500).json({ message: 'Server error.' })
    }
}

// ─── DELETE /tickets/:id ──────────────────────────────────────────────────────

const deleteTicket = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'DELETE_TICKET')
        if (!allowed) return res.status(403).json({ message: 'Permission required: DELETE_TICKET' })

        if (!isValidObjectId(req.params.id)) {
            return res.status(400).json({ message: 'Invalid ticket ID format.' })
        }

        const ticket = await Ticket.findById(req.params.id)
        if (!ticket) return res.status(404).json({ message: 'Ticket not found.' })

        await Ticket.findByIdAndDelete(req.params.id)

        await logAction(req, {
            action:      'DELETE_TICKET',
            target_type: 'Ticket',
            target_id:   ticket._id,
            metadata:    {
                name:        ticket.name,
                status:      ticket.status,
                priority:    ticket.priority,
                incident_id: String(ticket.incident_id),
                assigned_to: ticket.assigned_to,
            },
        })

        res.status(200).json({ message: 'Ticket deleted successfully.' })
    } catch (error) {
        console.error('[deleteTicket]', error)
        res.status(500).json({ message: 'Server error.' })
    }
}

module.exports = {
    getAllTickets,
    getMyTickets,
    getTicketById,
    getTicketsByIncident,
    createTicket,
    updateTicket,
    deleteTicket,
    getTicketStats,
}