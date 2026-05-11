// services/tokenVerifier.js
// ─────────────────────────────────────────────────────────────────────────────
// Validation du token JWT Keycloak via la clé publique RSA (JWKS).
//
// POURQUOI PAS keycloak-connect ?
//   keycloak-connect est conçu pour les apps web avec sessions (redirections).
//   Pour une API REST pure (bearer-only), la validation JWT directe via JWKS
//   est plus légère, explicite, et sans effet de bord (pas de session).
//
// FLUX DE VALIDATION :
//   1. Extraire le "kid" (Key ID) du header du token
//   2. Récupérer la clé publique correspondante depuis le JWKS de Keycloak
//   3. Vérifier la signature RSA, l'expiration, l'issuer
//   4. Vérifier que le token vient bien d'un client autorisé (azp)
//   5. Retourner le payload décodé
// ─────────────────────────────────────────────────────────────────────────────
'use strict'

const jwt     = require('jsonwebtoken')
const jwksRsa = require('jwks-rsa')
const config  = require('../config/keycloak.config')

// Client JWKS avec cache intégré
// rate-limit → max 10 appels/min au JWKS endpoint Keycloak
const jwksClient = jwksRsa({
    jwksUri:               config.jwksUri,
    cache:                 true,
    cacheMaxEntries:       10,
    cacheMaxAge:           config.jwksCacheDuration,
    rateLimit:             true,
    jwksRequestsPerMinute: 10,
})

// Callback pour jsonwebtoken : récupère la clé publique par "kid"
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

// ─── Extraction des rôles depuis le token décodé ─────────────────────────────
// Keycloak stocke les rôles à deux endroits :
//   realm_access.roles          → rôles du realm (admin, soc, user...)
//   resource_access[clientId].roles → rôles spécifiques au client
const extractRoles = (decoded) => {
    const realmRoles  = decoded?.realm_access?.roles || []
    const clientRoles = decoded?.resource_access?.[config.clientId]?.roles || []
    // On inclut aussi les rôles du client frontend si présents
    const frontendId  = process.env.KEYCLOAK_FRONTEND_CLIENT_ID || 'reports_frontend'
    const frontendRoles = decoded?.resource_access?.[frontendId]?.roles || []

    return [...new Set([...realmRoles, ...clientRoles, ...frontendRoles])]
}

// ─── Fonction principale de validation ───────────────────────────────────────
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
                    // Distinguer les erreurs pour des réponses HTTP appropriées
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

                // Vérifier que le token a bien été émis par un client autorisé
                // "azp" (Authorized Party) = le clientId qui a demandé le token
                if (decoded.azp && !config.allowedClients.includes(decoded.azp)) {
                    return reject({
                        status:  403,
                        code:    'TOKEN_WRONG_CLIENT',
                        message: `Token issued for unauthorized client: ${decoded.azp}`,
                    })
                }

                // Construire req.keycloakUser à partir du token décodé
                const keycloakUser = {
                    id:        decoded.sub,                  // UUID Keycloak (stable)
                    username:  decoded.preferred_username,
                    email:     decoded.email     || null,
                    firstName: decoded.given_name  || null,
                    lastName:  decoded.family_name || null,
                    roles:     extractRoles(decoded),
                    raw:       decoded,                      // payload complet si besoin
                }

                resolve(keycloakUser)
            }
        )
    })
}

module.exports = { verifyToken, extractRoles }