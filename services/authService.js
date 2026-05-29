'use strict'

/**
 * services/authService.js
 * ─────────────────────────────────────────────────────────────────────────────
 * NOUVEAU FICHIER
 *
 * Responsabilité unique : dialoguer avec Keycloak pour le compte du backend.
 * Le frontend ne communique JAMAIS directement avec Keycloak.
 *
 * Méthodes exposées :
 *   loginWithPassword(username, password) → { accessToken, refreshToken, expiresIn, userInfo }
 *   refreshAccessToken(refreshToken)      → { accessToken, refreshToken, expiresIn, userInfo }
 *   revokeToken(refreshToken)             → void
 */

const axios  = require('axios')
const config = require('../config/keycloak.config')
const { verifyToken } = require('./tokenVerifier')

// ─── URL du token endpoint Keycloak ──────────────────────────────────────────
const TOKEN_URL = `${config.url}/realms/${config.realm}/protocol/openid-connect/token`

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Transforme une réponse Keycloak brute en objet propre exploitable par le
 * controller et par le frontend.
 */
const _buildResult = async (kcData) => {
    const { access_token, refresh_token, expires_in } = kcData

    // Vérifier et décoder le token (réutilise la logique JWKS existante)
    const keycloakUser = await verifyToken(access_token)

    return {
        accessToken:  access_token,
        refreshToken: refresh_token || null,
        expiresIn:    expires_in,       // secondes
        userInfo: {
            id:        keycloakUser.id,
            username:  keycloakUser.username,
            email:     keycloakUser.email,
            firstName: keycloakUser.firstName,
            lastName:  keycloakUser.lastName,
            roles:     keycloakUser.roles,
        },
    }
}

/**
 * Convertit une erreur Axios Keycloak en erreur lisible.
 */
const _handleKcError = (err) => {
    const status = err.response?.status
    const kcError = err.response?.data?.error

    if (status === 401 || kcError === 'invalid_grant') {
        const e = new Error('Invalid username or password.')
        e.status = 401
        e.code   = 'INVALID_CREDENTIALS'
        throw e
    }

    if (status === 400) {
        const e = new Error('Bad authentication request.')
        e.status = 400
        e.code   = 'BAD_REQUEST'
        throw e
    }

    const e = new Error('Authentication service unavailable.')
    e.status = 503
    e.code   = 'KC_UNAVAILABLE'
    throw e
}

// ─── Service ──────────────────────────────────────────────────────────────────

/**
 * Authentifie un utilisateur via le Resource Owner Password Credentials flow.
 *
 * ⚠️  Ce flow est acceptable dans un contexte enterprise où le frontend
 *     est une application first-party contrôlée, et où Keycloak est interne.
 *     Le backend est le seul à connaître le client_secret.
 */
const loginWithPassword = async (username, password) => {
    const params = new URLSearchParams({
        grant_type:    'password',
        client_id:     process.env.KEYCLOAK_CLIENT_ID,
        client_secret: process.env.KEYCLOAK_CLIENT_SECRET,
        username,
        password,
        scope:         'openid profile email',
    })

    let kcData
    try {
        const { data } = await axios.post(TOKEN_URL, params, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            timeout: 10_000,
        })
        kcData = data
    } catch (err) {
        _handleKcError(err)
    }

    return _buildResult(kcData)
}

/**
 * Renouvelle un access_token à partir d'un refresh_token.
 */
const refreshAccessToken = async (refreshToken) => {
    if (!refreshToken) {
        const e = new Error('No refresh token provided.')
        e.status = 400
        e.code   = 'NO_REFRESH_TOKEN'
        throw e
    }

    const params = new URLSearchParams({
        grant_type:     'refresh_token',
        client_id:      process.env.KEYCLOAK_CLIENT_ID,
        client_secret:  process.env.KEYCLOAK_CLIENT_SECRET,
        refresh_token:  refreshToken,
    })

    let kcData
    try {
        const { data } = await axios.post(TOKEN_URL, params, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            timeout: 10_000,
        })
        kcData = data
    } catch (err) {
        _handleKcError(err)
    }

    return _buildResult(kcData)
}

/**
 * Révoque un refresh_token (logout côté Keycloak).
 * N'échoue pas si Keycloak est indisponible (best-effort).
 */
const revokeToken = async (refreshToken) => {
    if (!refreshToken) return

    const REVOKE_URL = `${config.url}/realms/${config.realm}/protocol/openid-connect/logout`

    const params = new URLSearchParams({
        client_id:      process.env.KEYCLOAK_CLIENT_ID,
        client_secret:  process.env.KEYCLOAK_CLIENT_SECRET,
        refresh_token:  refreshToken,
    })

    try {
        await axios.post(REVOKE_URL, params, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            timeout: 5_000,
        })
    } catch (err) {
        // Erreur non fatale : la session locale sera quand même détruite
        console.warn('[AuthService] Token revocation failed (non-fatal):', err.message)
    }
}

module.exports = { loginWithPassword, refreshAccessToken, revokeToken }