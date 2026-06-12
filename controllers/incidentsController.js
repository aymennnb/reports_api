'use strict'

const Incident = require('../models/Incident')
const { syncWazuhIncidents } = require('../services/wazuhIncidentService')
const { logAction } = require('../services/journalService')
const {
    isSimpleText, sanitizeLongText, isSafeLongText, isInEnum,
    INCIDENT_SEVERITIES, INCIDENT_STATUSES,
} = require('../utils/validators')

const getRoles = (req) => req.keycloakUser?.roles || req.user?.roles || []

const isAdmin = (req) => getRoles(req).includes('admin')

const hasPermission = (req, permissionName) => {
    if (isAdmin(req)) return true
    return getRoles(req).includes(permissionName)
}

const canSync = (req) => {
    if (isAdmin(req)) return true
    return getRoles(req).includes('SYNC_INCIDENTS') || getRoles(req).includes('soc')
}

const getAllIncidents = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'VIEW_INCIDENTS')
        if (!allowed) {
            return res.status(403).json({ message: 'Permission required: VIEW_INCIDENTS' })
        }

        const filter = {}
        if (req.query.status)      filter.status     = req.query.status
        if (req.query.severity)    filter.severity   = parseInt(req.query.severity)
        if (req.query.agent_name)  filter.agent_name = req.query.agent_name
        if (req.query.source)      filter.source     = req.query.source
        if (req.query.Source)      filter.source     = req.query.Source
        if (req.query.title)       filter.title      = { $regex: req.query.title, $options: 'i' }

        if (req.query.time_from || req.query.time_to) {
            filter.timestamp = {}
            if (req.query.time_from) filter.timestamp.$gte = new Date(req.query.time_from)
            if (req.query.time_to) {
                const to = new Date(req.query.time_to)
                to.setHours(23, 59, 59, 999)
                filter.timestamp.$lte = to
            }
        }

        const incidents = await Incident.find(filter).sort({ severity: -1, timestamp: -1 })
        const payload   = incidents.map(i => i.toObject({ virtuals: true }))
        res.status(200).json({ count: payload.length, incidents: payload })
    } catch (error) {
        res.status(500).json({ message: 'Server error.' })
    }
}

const getIncidentById = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'VIEW_INCIDENT_DETAILS')
        if (!allowed) return res.status(403).json({ message: 'Permission required: VIEW_INCIDENT_DETAILS' })
        const incident = await Incident.findById(req.params.id)
        if (!incident) return res.status(404).json({ message: 'Incident not found.' })
        res.status(200).json(incident.toObject({ virtuals: true }))
    } catch (error) {
        res.status(400).json({ message: 'Invalid incident ID format.' })
    }
}

const getStats = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'VIEW_INCIDENTS')
        if (!allowed) return res.status(403).json({ message: 'Permission required: VIEW_INCIDENTS' })

        const [bySeverity, byStatus, bySource, oldest_open] = await Promise.all([
            Incident.aggregate([{ $match: { status: 'open' } }, { $group: { _id: '$severity', count: { $sum: 1 } } }, { $sort: { _id: 1 } }]),
            Incident.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }]),
            Incident.aggregate([{ $group: { _id: '$source', count: { $sum: 1 } } }]),
            Incident.find({ status: 'open' }).sort({ timestamp: 1 }).limit(5).select('title severity agent_name timestamp'),
        ])

        res.status(200).json({ bySeverity, byStatus, bySource, oldest_open })
    } catch (error) {
        res.status(500).json({ message: 'Server error.' })
    }
}

const createIncident = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'CREATE_INCIDENT')
        if (!allowed) return res.status(403).json({ message: 'Permission required: CREATE_INCIDENT' })

        const { title, description, severity, agent_name, rule_id, rule_level } = req.body
        if (!title || !description || severity === undefined) {
            return res.status(400).json({ message: 'title, description and severity are required.' })
        }

        // ── Validation: title (texte simple) ──────────────────────────────
        if (!isSimpleText(title)) {
            return res.status(400).json({ message: 'Le titre contient des caractères non autorisés (lettres, chiffres, espaces, - et _ uniquement).' })
        }

        // ── Validation: description (texte long, sanitization) ─────────────
        if (typeof description !== 'string' || !isSafeLongText(description)) {
            return res.status(400).json({ message: 'La description contient des caractères non autorisés ($).' })
        }
        const cleanDescription = sanitizeLongText(description)

        // ── Validation: severity (enum) ─────────────────────────────────────
        const parsedSeverity = parseInt(severity)
        if (!isInEnum(parsedSeverity, INCIDENT_SEVERITIES)) {
            return res.status(400).json({ message: `severity invalide. Valeurs autorisées: ${INCIDENT_SEVERITIES.join(', ')}.` })
        }

        // ── Validation: agent_name (texte simple, optionnel) ─────────────────
        if (agent_name !== undefined && agent_name !== null && agent_name !== '' && !isSimpleText(agent_name)) {
            return res.status(400).json({ message: 'agent_name contient des caractères non autorisés.' })
        }

        // ── Validation: rule_id (texte simple, optionnel) ────────────────────
        if (rule_id !== undefined && rule_id !== null && rule_id !== '' && !isSimpleText(String(rule_id))) {
            return res.status(400).json({ message: 'rule_id contient des caractères non autorisés.' })
        }

        // ── Validation: rule_level (numérique, optionnel) ────────────────────
        let parsedRuleLevel = null
        if (rule_level !== undefined && rule_level !== null && rule_level !== '') {
            parsedRuleLevel = parseInt(rule_level)
            if (Number.isNaN(parsedRuleLevel)) {
                return res.status(400).json({ message: 'rule_level doit être un nombre.' })
            }
        }

        const incident = await new Incident({
            title, description: cleanDescription,
            severity:   parsedSeverity,
            agent_name: agent_name  || 'unknown',
            rule_id:    rule_id     || null,
            rule_level: parsedRuleLevel,
            source:     'manual',
            status:     'open',
        }).save()

        try {
            await logAction(req, {
                action:      'CREATE_INCIDENT',
                target_type: 'Incident',
                target_id:   incident._id,
                metadata:    {
                    title:       incident.title,
                    severity:    incident.severity,
                    agent_name:  incident.agent_name,
                    source:      incident.source,
                    rule_id:     incident.rule_id,
                    rule_level:  incident.rule_level,
                    status:      incident.status,
                },
            })
        } catch (logError) {
            console.error('[createIncident] logAction failed:', logError?.message || logError)
        }

        res.status(201).json({ message: 'Incident created successfully.' })
    } catch (error) {
        res.status(500).json({ message: 'Server error.' })
    }
}

const updateIncident = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'UPDATE_INCIDENT')
        if (!allowed) return res.status(403).json({ message: 'Permission required: UPDATE_INCIDENT' })
        const incident = await Incident.findById(req.params.id)
        if (!incident) return res.status(404).json({ message: 'Incident not found.' })

        const body = { ...req.body }

        // ── Validation: title ────────────────────────────────────────────
        if (body.title !== undefined) {
            if (!isSimpleText(body.title)) {
                return res.status(400).json({ message: 'Le titre contient des caractères non autorisés (lettres, chiffres, espaces, - et _ uniquement).' })
            }
        }

        // ── Validation: description ──────────────────────────────────────
        if (body.description !== undefined) {
            if (typeof body.description !== 'string' || !isSafeLongText(body.description)) {
                return res.status(400).json({ message: 'La description contient des caractères non autorisés ($).' })
            }
            body.description = sanitizeLongText(body.description)
        }

        // ── Validation: severity (enum) ──────────────────────────────────
        if (body.severity !== undefined) {
            const parsedSeverity = parseInt(body.severity)
            if (!isInEnum(parsedSeverity, INCIDENT_SEVERITIES)) {
                return res.status(400).json({ message: `severity invalide. Valeurs autorisées: ${INCIDENT_SEVERITIES.join(', ')}.` })
            }
            body.severity = parsedSeverity
        }

        // ── Validation: status (enum) ────────────────────────────────────
        if (body.status !== undefined) {
            if (!isInEnum(body.status, INCIDENT_STATUSES)) {
                return res.status(400).json({ message: `status invalide. Valeurs autorisées: ${INCIDENT_STATUSES.join(', ')}.` })
            }
        }

        // ── Validation: agent_name ───────────────────────────────────────
        if (body.agent_name !== undefined && body.agent_name !== null && body.agent_name !== '' && !isSimpleText(body.agent_name)) {
            return res.status(400).json({ message: 'agent_name contient des caractères non autorisés.' })
        }

        // ── Validation: rule_id ───────────────────────────────────────────
        if (body.rule_id !== undefined && body.rule_id !== null && body.rule_id !== '' && !isSimpleText(String(body.rule_id))) {
            return res.status(400).json({ message: 'rule_id contient des caractères non autorisés.' })
        }

        // ── Validation: rule_level ─────────────────────────────────────────
        if (body.rule_level !== undefined && body.rule_level !== null && body.rule_level !== '') {
            const parsedRuleLevel = parseInt(body.rule_level)
            if (Number.isNaN(parsedRuleLevel)) {
                return res.status(400).json({ message: 'rule_level doit être un nombre.' })
            }
            body.rule_level = parsedRuleLevel
        }

        const updated = await Incident.findByIdAndUpdate(req.params.id, body, { new: true })

        try {
            await logAction(req, {
                action:      'UPDATE_INCIDENT',
                target_type: 'Incident',
                target_id:   incident._id,
                metadata:    {
                    title:   incident.title,
                    source:  incident.source,
                    changes: Object.keys(body),
                },
            })
        } catch (logError) {
            console.error('[updateIncident] logAction failed:', logError?.message || logError)
        }

        res.status(200).json({ message: 'Incident updated successfully.', incident: updated })
    } catch (error) {
        res.status(500).json({ message: 'Server error.' })
    }
}

const deleteIncident = async (req, res) => {
    try {
        const allowed = hasPermission(req, 'DELETE_INCIDENT')
        if (!allowed) return res.status(403).json({ message: 'Permission required: DELETE_INCIDENT' })
        const incident = await Incident.findById(req.params.id)
        if (!incident) return res.status(404).json({ message: 'Incident not found.' })
        await Incident.findByIdAndDelete(req.params.id)

        try {
            await logAction(req, {
                action:      'DELETE_INCIDENT',
                target_type: 'Incident',
                target_id:   incident._id,
                metadata:    {
                    title:      incident.title,
                    severity:   incident.severity,
                    agent_name: incident.agent_name,
                    source:     incident.source,
                    status:     incident.status,
                    rule_id:    incident.rule_id || null,
                },
            })
        } catch (logError) {
            console.error('[deleteIncident] logAction failed:', logError?.message || logError)
        }

        res.status(200).json({ message: 'Incident deleted successfully.' })
    } catch (error) {
        res.status(500).json({ message: 'Server error.' })
    }
}

const syncFromWazuh = async (req, res) => {
    try {
        const allowed = canSync(req)
        if (!allowed) return res.status(403).json({ message: 'Permission required: SYNC_INCIDENTS' })
        const result = await syncWazuhIncidents()

        try {
            await logAction(req, {
                action:      'SYNC_INCIDENTS',
                target_type: 'Incident',
                target_id:   'wazuh',
                metadata:    {
                    created: result.created,
                    skipped: result.skipped,
                },
            })
        } catch (logError) {
            console.error('[syncFromWazuh] logAction failed:', logError?.message || logError)
        }

        res.status(200).json({
            message: `Sync completed: ${result.created} created, ${result.skipped} skipped`,
            data: result,
        })
    } catch (error) {
        console.error('[syncFromWazuh]', error.message)

        try {
            await logAction(req, {
                action:      'SYNC_INCIDENTS',
                target_type: 'Incident',
                target_id:   'wazuh',
                metadata:    {
                    error: error.message,
                },
                status: 'failure',
            })
        } catch (logError) {
            console.error('[syncFromWazuh] logAction failed:', logError?.message || logError)
        }

        res.status(500).json({ message: 'Sync failed (Check server logs).' })
    }
}

module.exports = { getAllIncidents, getIncidentById, getStats, createIncident, updateIncident, deleteIncident, syncFromWazuh }