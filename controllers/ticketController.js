'use strict'

// ─── Ticket Controller ─────────────────────────────────────────────────────
//
// Logique d'assignation migrée de "utilisateur unique" → "département Keycloak".
// Les tickets sont désormais assignés à un Keycloak Group (department.id / department.name).
// La logique "My Tickets" devient "Department Tickets" : on filtre par les groupes
// du user connecté.

const Ticket   = require('../models/Ticket')
const Incident = require('../models/Incident')
const { KeycloakAdmin } = require('../services/keycloakAdmin')
const { Types } = require('mongoose')
const { logAction } = require('../services/journalService')

// ─── Permission helpers ────────────────────────────────────────────────────────

const getRoles = (req) => req.keycloakUser?.roles || req.user?.roles || []
const isAdmin  = (req) => getRoles(req).includes('admin')
const hasPermission = (req, permissionName) => {
    if (isAdmin(req)) return true
    return getRoles(req).includes(permissionName)
}

// ─── Misc helpers ──────────────────────────────────────────────────────────────

const isValidObjectId = (id) => Types.ObjectId.isValid(id)

// ─── Keycloak Group helpers ────────────────────────────────────────────────────

/**
 * Récupère tous les groupes Keycloak du realm.
 * Retourne un tableau de { id, name }.
 */
const getAllGroups = async () => {
    const groups = await KeycloakAdmin.getGroups()   // GET /admin/realms/{realm}/groups
    return groups.map(g => ({ id: g.id, name: g.name }))
}

/**
 * Récupère les groupes Keycloak d'un utilisateur (par son id Keycloak).
 * Retourne un tableau de { id, name }.
 */
const getUserGroups = async (userId) => {
    const groups = await KeycloakAdmin.getUserGroups(userId) // GET /admin/realms/{realm}/users/{id}/groups
    return groups.map(g => ({ id: g.id, name: g.name }))
}

// ─── populateTicket ────────────────────────────────────────────────────────────
//
// Enrichit un document Ticket avec :
//  - incident     : données de l'incident lié
//  - created_by_user : infos Keycloak du créateur
//
// Plus de `assigned_user` : le département est déjà embarqué dans ticket.department.

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
//
// Retourne la liste des groupes Keycloak utilisables comme départements.
// Utilisé par les selects frontend pour choisir un département.

const getDepartments = async (req, res) => {
    try {
        const departments = await getAllGroups()
        res.status(200).json({ departments })
    } catch (error) {
        console.error('[getDepartments]', error)
        res.status(500).json({ message: 'Failed to fetch departments from Keycloak.' })
    }
}

// ─── GET /tickets ──────────────────────────────────────────────────────────────

const getAllTickets = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'VIEW_TICKETS')
        if (!allowed) return res.status(403).json({ message: 'Permission required: VIEW_TICKETS' })

        const filter = {}
        if (req.query.status)        filter.status          = req.query.status
        if (req.query.priority)      filter.priority        = req.query.priority
        if (req.query.department_id) filter['department.id'] = req.query.department_id
        if (req.query.created_by)    filter.created_by      = req.query.created_by

        const tickets = await Ticket.find(filter).sort({ created_at: -1 })
        const payload = await Promise.all(tickets.map(populateTicket))

        res.status(200).json({ count: payload.length, tickets: payload })
    } catch (error) {
        console.error('[getAllTickets]', error)
        res.status(500).json({ message: 'Server error.' })
    }
}

// ─── GET /tickets/mine  →  "Department Tickets" ────────────────────────────────
//
// Retourne les tickets dont department.id correspond à l'un des groupes Keycloak
// du user connecté. Remplace la logique "assigned_to === userId".

const getMyTickets = async (req, res) => {
    try {
        // Récupérer les groupes du user connecté
        let userGroups = []
        try {
            userGroups = await getUserGroups(req.keycloakUser.id)
        } catch (err) {
            console.error('[getMyTickets] getUserGroups failed:', err.message)
            // Si l'appel échoue, on retourne un tableau vide plutôt qu'une 500
            return res.status(200).json({ count: 0, tickets: [] })
        }

        if (userGroups.length === 0) {
            return res.status(200).json({ count: 0, tickets: [] })
        }

        const groupIds = userGroups.map(g => g.id)
        const tickets  = await Ticket.find({ 'department.id': { $in: groupIds } }).sort({ created_at: -1 })
        const payload  = await Promise.all(tickets.map(populateTicket))

        res.status(200).json({ count: payload.length, tickets: payload })
    } catch (error) {
        console.error('[getMyTickets]', error)
        res.status(500).json({ message: 'Server error.' })
    }
}

// ─── GET /tickets/stats ────────────────────────────────────────────────────────

const getTicketStats = async (req, res) => {
    try {
        const canViewAll = hasPermission(req, 'VIEW_TICKETS')

        // Pour les stats "department", on récupère les groupes du user
        let deptFilter = {}
        let deptCount  = 0

        if (!canViewAll) {
            let userGroups = []
            try { userGroups = await getUserGroups(req.keycloakUser.id) } catch (_) {}
            const groupIds = userGroups.map(g => g.id)
            deptFilter = { 'department.id': { $in: groupIds } }
        }

        const myGroupFilter = await (async () => {
            try {
                const g = await getUserGroups(req.keycloakUser.id)
                return { 'department.id': { $in: g.map(x => x.id) } }
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
            my_tickets:  deptTickets,   // gardé pour compatibilité frontend (label renommé côté UI)
            by_status:   byStatus,
            by_priority: byPriority,
        })
    } catch (error) {
        console.error('[getTicketStats]', error)
        res.status(500).json({ message: 'Server error.' })
    }
}

// ─── GET /tickets/:id ──────────────────────────────────────────────────────────

const getTicketById = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'VIEW_TICKETS')
        if (!allowed) return res.status(403).json({ message: 'Permission required: VIEW_TICKETS' })

        if (!isValidObjectId(req.params.id))
            return res.status(400).json({ message: 'Invalid ticket ID format.' })

        const ticket = await Ticket.findById(req.params.id)
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

        if (!isValidObjectId(req.params.id))
            return res.status(400).json({ message: 'Invalid incident ID format.' })

        const incident = await Incident.findById(req.params.id)
        if (!incident) return res.status(404).json({ message: 'Incident not found.' })

        const tickets = await Ticket.find({ incident_id: req.params.id }).sort({ created_at: -1 })
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

        if (!isValidObjectId(incident_id))
            return res.status(400).json({ message: 'Invalid incident_id format.' })

        const incident = await Incident.findById(incident_id)
        if (!incident) return res.status(404).json({ message: 'Incident not found.' })

        // Valider que le groupe Keycloak existe réellement
        try {
            const groups = await getAllGroups()
            const exists = groups.some(g => g.id === department_id)
            if (!exists) return res.status(404).json({ message: 'Department (Keycloak group) not found.' })
        } catch (err) {
            console.error('[createTicket] getGroups validation failed:', err.message)
            // Non-bloquant si Keycloak est temporairement indisponible
        }

        const ticket = await new Ticket({
            name:        name.trim(),
            incident_id,
            created_by:  req.keycloakUser.id,
            department: {
                id:   department_id,
                name: department_name,
            },
            priority: priority || 'medium',
            notes:    notes    || null,
            status:   'open',
        }).save()

        await logAction(req, {
            action:      'CREATE_TICKET',
            target_type: 'Ticket',
            target_id:   ticket._id,
            metadata: {
                name:            ticket.name,
                incident_id:     String(incident_id),
                department_id,
                department_name,
                priority:        ticket.priority,
            },
        })

        await logAction(req, {
            action:      'ASSIGN_TICKET',
            target_type: 'Ticket',
            target_id:   ticket._id,
            metadata: {
                department_id,
                department_name,
                incident_id: String(incident_id),
                on_create:   true,
            },
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

// ─── PUT /tickets/:id ──────────────────────────────────────────────────────────

const updateTicket = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'UPDATE_TICKET')
        if (!allowed) return res.status(403).json({ message: 'Permission required: UPDATE_TICKET' })

        if (!isValidObjectId(req.params.id))
            return res.status(400).json({ message: 'Invalid ticket ID format.' })

        const ticket = await Ticket.findById(req.params.id)
        if (!ticket) return res.status(404).json({ message: 'Ticket not found.' })

        const updates = {}

        // Champs scalaires autorisés
        const SCALAR_FIELDS = ['name', 'status', 'priority', 'notes']
        SCALAR_FIELDS.forEach(f => { if (req.body[f] !== undefined) updates[f] = req.body[f] })

        // Réassignation de département
        if (req.body.department_id || req.body.department_name) {
            const newId   = req.body.department_id   || ticket.department.id
            const newName = req.body.department_name || ticket.department.name

            // Valider le groupe
            try {
                const groups = await getAllGroups()
                const exists = groups.some(g => g.id === newId)
                if (!exists) return res.status(404).json({ message: 'Department (Keycloak group) not found.' })
            } catch (err) {
                console.error('[updateTicket] getGroups validation failed:', err.message)
            }

            updates['department.id']   = newId
            updates['department.name'] = newName
        }

        const updated = await Ticket.findByIdAndUpdate(req.params.id, updates, { new: true })

        // Journal UPDATE_TICKET
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

        // Journal ASSIGN_TICKET si le département a changé
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

        // Journal CHANGE_TICKET_STATUS si le statut a changé
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
        console.error('[updateTicket]', error)
        res.status(500).json({ message: 'Server error.' })
    }
}

// ─── DELETE /tickets/:id ───────────────────────────────────────────────────────

const deleteTicket = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'DELETE_TICKET')
        if (!allowed) return res.status(403).json({ message: 'Permission required: DELETE_TICKET' })

        if (!isValidObjectId(req.params.id))
            return res.status(400).json({ message: 'Invalid ticket ID format.' })

        const ticket = await Ticket.findById(req.params.id)
        if (!ticket) return res.status(404).json({ message: 'Ticket not found.' })

        await Ticket.findByIdAndDelete(req.params.id)

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
        console.error('[deleteTicket]', error)
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