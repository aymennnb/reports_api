'use strict'

// ─── Ticket Controller ─────────────────────────────────────────────────────

const Ticket   = require('../models/Ticket')
const Incident = require('../models/Incident')
const { KeycloakAdmin } = require('../services/keycloakAdmin')
const { Types } = require('mongoose')
const { logAction } = require('../services/journalService')
const {
    isSimpleText, sanitizeLongText, isSafeLongText, isInEnum,
    TICKET_PRIORITIES, TICKET_STATUSES,
} = require('../utils/validators')

// ─── Permission helpers ────────────────────────────────────────────────────────

const getRoles = (req) => req.keycloakUser?.roles || req.user?.roles || []
const isAdmin  = (req) => getRoles(req).includes('admin')
const hasPermission = (req, permissionName) => {
    if (isAdmin(req)) return true
    return getRoles(req).includes(permissionName)
}

// ─── Misc helpers ──────────────────────────────────────────────────────────────

const isValidObjectId = (id) => typeof id === 'string' && Types.ObjectId.isValid(id)

// ─── Keycloak Group helpers ────────────────────────────────────────────────────

const getAllGroups = async () => {
    const groups = await KeycloakAdmin.getGroups()
    return groups.map(g => ({ id: g.id, name: g.name }))
}

const getUserGroups = async (userId) => {
    const groups = await KeycloakAdmin.getUserGroups(userId)
    return groups.map(g => ({ id: g.id, name: g.name }))
}

// ─── populateTicket ────────────────────────────────────────────────────────────

const populateTicket = async (ticket) => {
    const obj = ticket.toObject({ virtuals: true })

    const incident = await Incident.findById(ticket.incident_id).lean()

    let createdByUser = null
    try {
        createdByUser = await KeycloakAdmin.getUserById(ticket.created_by)
    } catch (_) {}

    return {
        ...obj,
        incident: incident || null,
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

// ─── GET /tickets/departments ──────────────────────────────────────────────────

const getDepartments = async (req, res) => {
    try {
        const departments = await getAllGroups()
        res.status(200).json({ departments })
    } catch (error) {
        console.error('[getDepartments] Failed: %s', error.message)
        res.status(500).json({ message: 'Failed to fetch departments from Keycloak.' })
    }
}

// ─── GET /tickets ──────────────────────────────────────────────────────────────

const getAllTickets = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'VIEW_TICKETS')
        if (!allowed) return res.status(403).json({ message: 'Permission required: VIEW_TICKETS' })

        const filter = {}

        if (req.query.status)        filter.status           = String(req.query.status)
        if (req.query.priority)      filter.priority         = String(req.query.priority)
        if (req.query.department_id) filter['department.id'] = String(req.query.department_id)
        if (req.query.created_by)    filter.created_by       = String(req.query.created_by)

        const tickets = await Ticket.find(filter).sort({ created_at: -1 })
        const payload = await Promise.all(tickets.map(populateTicket))

        res.status(200).json({ count: payload.length, tickets: payload })
    } catch (error) {
        console.error('[getAllTickets] %s', error.message)
        res.status(500).json({ message: 'Server error.' })
    }
}

// ─── GET /tickets/mine ─────────────────────────────────────────────────────────

const getMyTickets = async (req, res) => {
    try {
        let userGroups = []
        try {
            userGroups = await getUserGroups(req.keycloakUser.id)
        } catch (err) {
            console.error('[getMyTickets] getUserGroups failed: %s', err.message)
            return res.status(200).json({ count: 0, tickets: [] })
        }
        if (userGroups.length === 0) {
            return res.status(200).json({ count: 0, tickets: [] })
        }

        const groupIds = userGroups.map(g => String(g.id))
        const tickets  = await Ticket.find({ 'department.id': { $in: groupIds } }).sort({ created_at: -1 })
        const payload  = await Promise.all(tickets.map(populateTicket))

        res.status(200).json({ count: payload.length, tickets: payload })
    } catch (error) {
        console.error('[getMyTickets] %s', error.message)
        res.status(500).json({ message: 'Server error.' })
    }
}

// ─── GET /tickets/stats ────────────────────────────────────────────────────────

const getTicketStats = async (req, res) => {
    try {
        const canViewAll = hasPermission(req, 'VIEW_TICKETS')
        let deptFilter = {}

        if (!canViewAll) {
            let userGroups = []
            try { userGroups = await getUserGroups(req.keycloakUser.id) } catch (_) {}
            const groupIds = userGroups.map(g => String(g.id))
            deptFilter = { 'department.id': { $in: groupIds } }
        }

        const myGroupFilter = await (async () => {
            try {
                const g = await getUserGroups(req.keycloakUser.id)
                return { 'department.id': { $in: g.map(x => String(x.id)) } }
            } catch (_) { return { 'department.id': { $in: [] } } }
        })()

        const matchAll = canViewAll ? {} : deptFilter

        const [byStatus, byPriority, deptTickets, total] = await Promise.all([
            Ticket.aggregate([{ $match: matchAll },      { $group: { _id: '$status',   count: { $sum: 1 } } }]),
            Ticket.aggregate([{ $match: matchAll },      { $group: { _id: '$priority', count: { $sum: 1 } } }]),
            Ticket.countDocuments(myGroupFilter),
            Ticket.countDocuments(matchAll),
        ])

        res.status(200).json({
            total,
            my_tickets:  deptTickets,
            by_status:   byStatus,
            by_priority: byPriority,
        })
    } catch (error) {
        console.error('[getTicketStats] %s', error.message)
        res.status(500).json({ message: 'Server error.' })
    }
}

// ─── GET /tickets/:id ──────────────────────────────────────────────────────────

const getTicketById = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'VIEW_TICKETS')
        if (!allowed) return res.status(403).json({ message: 'Permission required: VIEW_TICKETS' })

        const safeId = String(req.params.id)
        if (!isValidObjectId(safeId))
            return res.status(400).json({ message: 'Invalid ticket ID format.' })

        const ticket = await Ticket.findById(safeId)
        if (!ticket) return res.status(404).json({ message: 'Ticket not found.' })

        res.status(200).json(await populateTicket(ticket))
    } catch (error) {
        res.status(400).json({ message: 'Invalid ticket ID format.' })
    }
}

// ─── GET /incidents/:id/tickets ────────────────────────────────────────────────

const getTicketsByIncident = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'VIEW_TICKETS')
        if (!allowed) return res.status(403).json({ message: 'Permission required: VIEW_TICKETS' })

        const safeId = String(req.params.id)
        if (!isValidObjectId(safeId))
            return res.status(400).json({ message: 'Invalid incident ID format.' })

        const incident = await Incident.findById(safeId)
        if (!incident) return res.status(404).json({ message: 'Incident not found.' })

        const tickets = await Ticket.find({ incident_id: safeId }).sort({ created_at: -1 })
        const payload = await Promise.all(tickets.map(populateTicket))

        res.status(200).json({ count: payload.length, tickets: payload })
    } catch (error) {
        res.status(400).json({ message: 'Invalid incident ID format.' })
    }
}

// ─── POST /tickets ─────────────────────────────────────────────────────────────

const createTicket = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'CREATE_TICKET')
        if (!allowed) return res.status(403).json({ message: 'Permission required: CREATE_TICKET' })

        const { name, incident_id, department_id, department_name, priority, notes } = req.body

        if (!name?.trim())
            return res.status(400).json({ message: 'name is required.' })

        if (!incident_id || !department_id || !department_name)
            return res.status(400).json({ message: 'incident_id, department_id and department_name are required.' })

        const safeIncidentId = String(incident_id)
        if (!isValidObjectId(safeIncidentId))
            return res.status(400).json({ message: 'Invalid incident_id format.' })

        if (!isSimpleText(name)) {
            return res.status(400).json({ message: 'Le nom du ticket contient des caractères non autorisés (lettres, chiffres, espaces, - et _ uniquement).' })
        }

        if (!isSimpleText(department_id)) {
            return res.status(400).json({ message: 'department_id contient des caractères non autorisés.' })
        }

        if (!isSimpleText(department_name)) {
            return res.status(400).json({ message: 'department_name contient des caractères non autorisés.' })
        }

        if (priority !== undefined && priority !== null && priority !== '' && !isInEnum(priority, TICKET_PRIORITIES)) {
            return res.status(400).json({ message: `priority invalide. Valeurs autorisées: ${TICKET_PRIORITIES.join(', ')}.` })
        }

        let cleanNotes = notes || null
        if (notes !== undefined && notes !== null && notes !== '') {
            if (typeof notes !== 'string' || !isSafeLongText(notes)) {
                return res.status(400).json({ message: 'notes contient des caractères non autorisés ($).' })
            }
            cleanNotes = sanitizeLongText(notes)
        }

        const incident = await Incident.findById(safeIncidentId)
        if (!incident) return res.status(404).json({ message: 'Incident not found.' })

        try {
            const groups = await getAllGroups()
            const exists = groups.some(g => g.id === String(department_id))
            if (!exists) return res.status(404).json({ message: 'Department (Keycloak group) not found.' })
        } catch (err) {
            console.error('[createTicket] getGroups validation failed: %s', err.message)
        }

        const ticket = await new Ticket({
            name:        name.trim(),
            incident_id: safeIncidentId,
            created_by:  req.keycloakUser.id,
            department: {
                id:   String(department_id),
                name: String(department_name),
            },
            priority: priority || 'medium',
            notes:    cleanNotes,
            status:   'open',
        }).save()

        await logAction(req, {
            action:      'CREATE_TICKET',
            target_type: 'Ticket',
            target_id:   ticket._id,
            metadata: {
                name:            ticket.name,
                incident_id:     safeIncidentId,
                department_id:   String(department_id),
                department_name: String(department_name),
                priority:        ticket.priority,
            },
        })

        await logAction(req, {
            action:      'ASSIGN_TICKET',
            target_type: 'Ticket',
            target_id:   ticket._id,
            metadata: {
                department_id:   String(department_id),
                department_name: String(department_name),
                incident_id:     safeIncidentId,
                on_create:       true,
            },
        })

        res.status(201).json({
            message: 'Ticket created successfully.',
            ticket:  await populateTicket(ticket),
        })
    } catch (error) {
        console.error('[createTicket] %s', error.message)
        res.status(500).json({ message: 'Server error.' })
    }
}

// ─── PUT /tickets/:id ──────────────────────────────────────────────────────────

const updateTicket = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'UPDATE_TICKET')
        if (!allowed) return res.status(403).json({ message: 'Permission required: UPDATE_TICKET' })

        const safeId = String(req.params.id)
        if (!isValidObjectId(safeId))
            return res.status(400).json({ message: 'Invalid ticket ID format.' })

        const ticket = await Ticket.findById(safeId)
        if (!ticket) return res.status(404).json({ message: 'Ticket not found.' })

        const updates = {}

        if (req.body.name !== undefined) {
            if (!isSimpleText(req.body.name)) {
                return res.status(400).json({ message: 'Le nom du ticket contient des caractères non autorisés (lettres, chiffres, espaces, - et _ uniquement).' })
            }
            updates.name = req.body.name
        }

        if (req.body.status !== undefined) {
            if (!isInEnum(req.body.status, TICKET_STATUSES)) {
                return res.status(400).json({ message: `status invalide. Valeurs autorisées: ${TICKET_STATUSES.join(', ')}.` })
            }
            updates.status = req.body.status
        }

        if (req.body.priority !== undefined) {
            if (!isInEnum(req.body.priority, TICKET_PRIORITIES)) {
                return res.status(400).json({ message: `priority invalide. Valeurs autorisées: ${TICKET_PRIORITIES.join(', ')}.` })
            }
            updates.priority = req.body.priority
        }

        if (req.body.notes !== undefined) {
            if (req.body.notes !== null && req.body.notes !== '') {
                if (typeof req.body.notes !== 'string' || !isSafeLongText(req.body.notes)) {
                    return res.status(400).json({ message: 'notes contient des caractères non autorisés ($).' })
                }
                updates.notes = sanitizeLongText(req.body.notes)
            } else {
                updates.notes = req.body.notes
            }
        }

        if (req.body.department_id || req.body.department_name) {
            const newId   = req.body.department_id   || ticket.department.id
            const newName = req.body.department_name || ticket.department.name

            if (!isSimpleText(newId)) {
                return res.status(400).json({ message: 'department_id contient des caractères non autorisés.' })
            }
            if (!isSimpleText(newName)) {
                return res.status(400).json({ message: 'department_name contient des caractères non autorisés.' })
            }

            try {
                const groups = await getAllGroups()
                const exists = groups.some(g => g.id === String(newId))
                if (!exists) return res.status(404).json({ message: 'Department (Keycloak group) not found.' })
            } catch (err) {
                console.error('[updateTicket] getGroups validation failed: %s', err.message)
            }

            updates['department.id']   = String(newId)
            updates['department.name'] = String(newName)
        }

        const updated = await Ticket.findByIdAndUpdate(safeId, updates, { new: true })

        await logAction(req, {
            action:      'UPDATE_TICKET',
            target_type: 'Ticket',
            target_id:   ticket._id,
            metadata: {
                name:           ticket.name,
                fields_updated: Object.keys(updates),
                incident_id:    String(ticket.incident_id),
            },
        })

        if (updates['department.id'] && updates['department.id'] !== ticket.department.id) {
            await logAction(req, {
                action:      'ASSIGN_TICKET',
                target_type: 'Ticket',
                target_id:   ticket._id,
                metadata: {
                    previous_department_id:   ticket.department.id,
                    previous_department_name: ticket.department.name,
                    new_department_id:        updates['department.id'],
                    new_department_name:      updates['department.name'],
                },
            })
        }

        if (updates.status && updates.status !== ticket.status) {
            await logAction(req, {
                action:      'CHANGE_TICKET_STATUS',
                target_type: 'Ticket',
                target_id:   ticket._id,
                metadata: {
                    previous_status: ticket.status,
                    new_status:      updates.status,
                },
            })
        }

        res.status(200).json({ message: 'Ticket updated successfully.', ticket: await populateTicket(updated) })
    } catch (error) {
        console.error('[updateTicket] %s', error.message)
        res.status(500).json({ message: 'Server error.' })
    }
}

// ─── DELETE /tickets/:id ───────────────────────────────────────────────────────

const deleteTicket = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'DELETE_TICKET')
        if (!allowed) return res.status(403).json({ message: 'Permission required: DELETE_TICKET' })

        const safeId = String(req.params.id)
        if (!isValidObjectId(safeId))
            return res.status(400).json({ message: 'Invalid ticket ID format.' })

        const ticket = await Ticket.findById(safeId)
        if (!ticket) return res.status(404).json({ message: 'Ticket not found.' })

        await Ticket.findByIdAndDelete(safeId)

        await logAction(req, {
            action:      'DELETE_TICKET',
            target_type: 'Ticket',
            target_id:   ticket._id,
            metadata: {
                name:            ticket.name,
                status:          ticket.status,
                priority:        ticket.priority,
                incident_id:     String(ticket.incident_id),
                department_id:   ticket.department.id,
                department_name: ticket.department.name,
            },
        })

        res.status(200).json({ message: 'Ticket deleted successfully.' })
    } catch (error) {
        console.error('[deleteTicket] %s', error.message)
        res.status(500).json({ message: 'Server error.' })
    }
}

module.exports = {
    getDepartments,
    getAllTickets,
    getMyTickets,
    getTicketById,
    getTicketsByIncident,
    createTicket,
    updateTicket,
    deleteTicket,
    getTicketStats,
}