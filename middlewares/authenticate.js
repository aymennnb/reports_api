// middlewares/authenticate.js
// ─────────────────────────────────────────────────────────────────────────────
// Remplace l'ancien middleware verifyToken (jsonwebtoken local).
//
// AVANT :
//   jwt.verify(token, process.env.JWT_SECRET)
//   → req.user = { id, username, role }   ← payload JWT maison
//
// APRÈS :
//   verifyToken(token)  ← valide via JWKS Keycloak
//   → req.keycloakUser = { id, username, email, roles[], raw }
//
// RÉTROCOMPATIBILITÉ :
//   req.user est aussi peuplé avec le même format que l'ancien middleware
//   pour ne pas casser les controllers qui utilisent encore req.user.id / req.user.role.
//   Une fois tous les controllers migrés vers req.keycloakUser, req.user peut être retiré.
// ─────────────────────────────────────────────────────────────────────────────
'use strict'

const { verifyToken } = require('../services/tokenVerifier')

const authenticate = async (req, res, next) => {
    // Extraire le token du header Authorization: Bearer <token>
    const authHeader = req.headers['authorization'] || req.headers['Authorization']
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null

    if (!token) {
        return res.status(401).json({
            message: 'Access denied. No token provided.',
            code:    'NO_TOKEN',
        })
    }

    try {
        const keycloakUser = await verifyToken(token)

        // API principale : req.keycloakUser (nouveau standard)
        req.keycloakUser = keycloakUser

        // Rétrocompatibilité : req.user avec le format de l'ancien middleware
        // Permet de ne pas tout casser d'un coup dans les controllers existants
        req.user = {
            id:       keycloakUser.id,
            username: keycloakUser.username,
            email:    keycloakUser.email,
            // "role" au singulier pour les anciens controllers
            // Priorité : admin > soc > user
            role: keycloakUser.roles.includes('admin') ? 'admin'
                : keycloakUser.roles.includes('soc')   ? 'soc'
                : 'user',
            roles: keycloakUser.roles,
        }

        next()
    } catch (err) {
        // err vient de tokenVerifier.js avec { status, code, message }
        const status  = err.status  || 401
        const message = err.message || 'Authentication failed.'
        const code    = err.code    || 'AUTH_ERROR'

        console.warn(`[Auth] ${code}: ${message} — IP: ${req.ip}`)

        return res.status(status).json({ message, code })
    }
}

module.exports = { authenticate }