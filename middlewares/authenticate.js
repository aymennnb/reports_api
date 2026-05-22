'use strict'

const { verifyToken } = require('../services/tokenVerifier')

const authenticate = async (req, res, next) => {
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

        req.keycloakUser = keycloakUser

        req.user = {
            id:       keycloakUser.id,
            username: keycloakUser.username,
            email:    keycloakUser.email,
            role: keycloakUser.roles.includes('admin') ? 'admin'
                : keycloakUser.roles.includes('soc')   ? 'soc'
                : 'user',
            roles: keycloakUser.roles,
        }

        next()
    } catch (err) {
        const status  = err.status  || 401
        const message = err.message || 'Authentication failed.'
        const code    = err.code    || 'AUTH_ERROR'

        console.warn(`[Auth] ${code}: ${message} — IP: ${req.ip}`)

        return res.status(status).json({ message, code })
    }
}

module.exports = { authenticate }