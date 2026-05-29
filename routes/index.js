'use strict'

const express = require('express')
const router  = express.Router()

const { authenticate }                = require('../middlewares/authenticate')
const { requireRole, requireAnyRole } = require('../middlewares/authorize')

const {
    getMyProfile, updateMyProfile,
    getUsers, getUserById, createUser, updateUser, deleteUser, setUserStatus,
    getAllPermissions, getUserPermissions,assignPermission,
    unassignPermission, syncPermissions
} = require('../controllers/userController')

const {
    getVulnerabilities, getVulnerabilityById, getStats: getVulnStats,
    createVulnerability, updateVulnerability, deleteVulnerability,
    syncFromNessusById, getScansGroupedByFolder, getTemplates, launchNessusScan
} = require('../controllers/vulnerabilityController')

const {
    getAllIncidents, getIncidentById, createIncident, updateIncident,
    deleteIncident, syncFromWazuh, getStats: getIncidentStats,
} = require('../controllers/incidentsController')

const {
    getLogs, getLogById, getLogStats, triggerManualImport,
} = require('../controllers/importLogsController')

const {
    getAllTickets, getMyTickets, getTicketById, getTicketsByIncident,
    createTicket, updateTicket, deleteTicket, getTicketStats, getDepartments
} = require('../controllers/ticketController')

const { getAllJournals } = require('../controllers/journalController')

router.get('/users/me',    authenticate, getMyProfile)
router.put('/users/me',    authenticate, updateMyProfile)

router.get('/users',                   authenticate, requireRole('admin'), getUsers)
router.get('/users/:id',               authenticate, requireRole('admin'), getUserById)
router.post('/users',                  authenticate, requireRole('admin'), createUser)
router.put('/users/:id',               authenticate, requireRole('admin'), updateUser)
router.delete('/users/:id',            authenticate, requireRole('admin'), deleteUser)
router.put('/users/:id/activate',      authenticate, requireRole('admin'), setUserStatus(true))
router.put('/users/:id/deactivate',    authenticate, requireRole('admin'), setUserStatus(false))
router.post('/:id/permissions/assign',   authenticate,requireRole('admin'), assignPermission)
router.post('/:id/permissions/unassign', authenticate,requireRole('admin'), unassignPermission)
router.post('/users/:id/permissions/sync',     authenticate,requireRole('admin'), syncPermissions)

router.get('/permissions',             authenticate, getAllPermissions)
router.get('/users/:id/permissions',   authenticate, getUserPermissions)

router.get('/vulnerabilities/stats',    authenticate, getVulnStats)
router.get('/vulnerabilities',          authenticate, getVulnerabilities)
router.get('/vulnerabilities/:id',      authenticate, getVulnerabilityById)

router.post('/vulnerabilities',         authenticate, createVulnerability)
router.put('/vulnerabilities/:id',      authenticate, updateVulnerability)
router.delete('/vulnerabilities/:id',   authenticate, deleteVulnerability)

router.get('/scans',                                   authenticate, getScansGroupedByFolder)
router.post('/vulnerabilities/sync/nessus/:scanId',    authenticate, syncFromNessusById)

router.get('/nessus/templates', authenticate, getTemplates)
router.post('/vulnerabilities/nessus/launch-scan', authenticate, launchNessusScan)

router.get('/incidents/stats',    authenticate, getIncidentStats)
router.get('/incidents',          authenticate, getAllIncidents)
router.get('/incidents/:id',      authenticate, getIncidentById)

router.put('/incidents/:id',      authenticate, updateIncident)
router.post('/incidents',         authenticate, createIncident)
router.delete('/incidents/:id',   authenticate, deleteIncident)
router.post('/incidents/sync',    authenticate, syncFromWazuh)

router.get('/tickets/departments', authenticate, getDepartments)
router.get('/tickets/stats',              authenticate, getTicketStats)
router.get('/tickets/mine',               authenticate, getMyTickets)
router.get('/tickets',                    authenticate, getAllTickets)
router.get('/tickets/:id',                authenticate, getTicketById)
router.post('/tickets',                   authenticate, createTicket)
router.put('/tickets/:id',                authenticate, updateTicket)
router.delete('/tickets/:id',             authenticate, requireAnyRole('admin'), deleteTicket)
router.get('/incidents/:id/tickets',      authenticate, getTicketsByIncident)

router.get('/import-logs/stats',            authenticate, requireAnyRole('admin'), getLogStats)
router.get('/import-logs',                  authenticate, requireAnyRole('admin'), getLogs)
router.get('/import-logs/:id',              authenticate, requireAnyRole('admin'), getLogById)
router.post('/import-logs/trigger/:source', authenticate, requireAnyRole('admin'), triggerManualImport)

router.get('/journals', authenticate, requireAnyRole('admin'), getAllJournals)

module.exports = router