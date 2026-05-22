'use strict'

const jwt     = require('jsonwebtoken')
const jwksRsa = require('jwks-rsa')
const config  = require('../config/keycloak.config')

const jwksClient = jwksRsa({
    jwksUri:               config.jwksUri,
    cache:                 true,
    cacheMaxEntries:       10,
    cacheMaxAge:           config.jwksCacheDuration,
    rateLimit:             true,
    jwksRequestsPerMinute: 10,
})

const getPublicKey = (header, callback) => {
    jwksClient.getSigningKey(header.kid, (err, key) => {
        if (err) {
            return callback(
                new Error(`[JWKS] Cannot retrieve signing key (kid: ${header.kid}): ${err.message}`)
            )
        }
        callback(null, key.getPublicKey())
    })
}

const extractRoles = (decoded) => {
    const realmRoles  = decoded?.realm_access?.roles || []
    const clientRoles = decoded?.resource_access?.[config.clientId]?.roles || []
    const frontendId  = process.env.KEYCLOAK_FRONTEND_CLIENT_ID
    const frontendRoles = decoded?.resource_access?.[frontendId]?.roles || []

    return [...new Set([...realmRoles, ...clientRoles, ...frontendRoles])]
}

const verifyToken = (rawToken) => {
    return new Promise((resolve, reject) => {
        jwt.verify(
            rawToken,
            getPublicKey,
            {
                algorithms: config.algorithms,
                issuer:     config.issuer,
            },
            (err, decoded) => {
                if (err) {
                    if (err.name === 'TokenExpiredError') {
                        return reject({ status: 401, code: 'TOKEN_EXPIRED',    message: 'Token has expired. Please refresh your session.' })
                    }
                    if (err.name === 'JsonWebTokenError') {
                        return reject({ status: 401, code: 'TOKEN_INVALID',    message: 'Token signature is invalid.' })
                    }
                    if (err.name === 'NotBeforeError') {
                        return reject({ status: 401, code: 'TOKEN_NOT_ACTIVE', message: 'Token is not yet valid.' })
                    }
                    return reject({ status: 401, code: 'TOKEN_ERROR', message: err.message })
                }

                if (decoded.azp && !config.allowedClients.includes(decoded.azp)) {
                    return reject({
                        status:  403,
                        code:    'TOKEN_WRONG_CLIENT',
                        message: `Token issued for unauthorized client: ${decoded.azp}`,
                    })
                }

                const keycloakUser = {
                    id:        decoded.sub,
                    username:  decoded.preferred_username,
                    email:     decoded.email     || null,
                    firstName: decoded.given_name  || null,
                    lastName:  decoded.family_name || null,
                    roles:     extractRoles(decoded),
                    raw:       decoded,
                }

                resolve(keycloakUser)
            }
        )
    })
}

module.exports = { verifyToken, extractRoles }