// middlewares/authorize.js
// ─────────────────────────────────────────────────────────────────────────────
// Middlewares d'autorisation RBAC basés sur les rôles Keycloak.
// À utiliser APRÈS authenticate().
//
// USAGE dans les routes :
//
//   router.delete('/incidents/:id',
//     authenticate,
//     requireRole('admin'),           // admin seulement
//     deleteIncident
//   )
//
//   router.post('/incidents/sync',
//     authenticate,
//     requireAnyRole('admin', 'soc'), // admin OU soc
//     syncFromWazuh
//   )
//
//   router.get('/vulnerabilities',
//     authenticate,                   // authentifié seulement (rôle vérifié dans le controller)
//     getVulnerabilities
//   )
// ─────────────────────────────────────────────────────────────────────────────
'use strict'

// ─── requireRole(role) ───────────────────────────────────────────────────────
// L'utilisateur DOIT avoir exactement ce rôle.
const requireRole = (role) => (req, res, next) => {
    const user = req.keycloakUser || req.user
    if (!user) {
        return res.status(401).json({ message: 'Not authenticated.', code: 'NOT_AUTHENTICATED' })
    }

    const roles = user.roles || (user.role ? [user.role] : [])
    if (!roles.includes(role)) {
        console.warn(`[AuthZ] requireRole('${role}') denied for user '${user.username}' (roles: ${roles.join(', ')})`)
        return res.status(403).json({
            message: `Access denied. Required role: ${role}`,
            code:    'INSUFFICIENT_ROLE',
        })
    }

    next()
}

// ─── requireAnyRole(...roles) ────────────────────────────────────────────────
// L'utilisateur doit avoir AU MOINS UN des rôles listés (logique OR).
const requireAnyRole = (...roles) => (req, res, next) => {
    const user = req.keycloakUser || req.user
    if (!user) {
        return res.status(401).json({ message: 'Not authenticated.', code: 'NOT_AUTHENTICATED' })
    }

    const userRoles = user.roles || (user.role ? [user.role] : [])
    const authorized = roles.some(r => userRoles.includes(r))

    if (!authorized) {
        console.warn(`[AuthZ] requireAnyRole(${roles.join('|')}) denied for '${user.username}' (roles: ${userRoles.join(', ')})`)
        return res.status(403).json({
            message: `Access denied. Required one of: ${roles.join(', ')}`,
            code:    'INSUFFICIENT_ROLE',
        })
    }

    next()
}

// ─── requireAllRoles(...roles) ───────────────────────────────────────────────
// L'utilisateur doit avoir TOUS les rôles listés (logique AND, cas rare).
const requireAllRoles = (...roles) => (req, res, next) => {
    const user = req.keycloakUser || req.user
    if (!user) {
        return res.status(401).json({ message: 'Not authenticated.', code: 'NOT_AUTHENTICATED' })
    }

    const userRoles = user.roles || (user.role ? [user.role] : [])
    const authorized = roles.every(r => userRoles.includes(r))

    if (!authorized) {
        return res.status(403).json({
            message: `Access denied. All required roles: ${roles.join(', ')}`,
            code:    'INSUFFICIENT_ROLE',
        })
    }

    next()
}

// ─── isAdmin (helper booléen, utilisable dans les controllers) ───────────────
// Usage dans un controller : if (isAdmin(req)) { ... }
const isAdmin = (req) => {
    const user = req.keycloakUser || req.user
    const roles = user?.roles || (user?.role ? [user.role] : [])
    return roles.includes('admin')
}

module.exports = { requireRole, requireAnyRole, requireAllRoles, isAdmin }