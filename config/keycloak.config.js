// config/keycloak.config.js
// ─────────────────────────────────────────────────────────────────────────────
// Source unique de vérité pour la configuration Keycloak côté backend.
// ─────────────────────────────────────────────────────────────────────────────
'use strict'

const required = (name) => {
    const val = process.env[name]
    if (!val) throw new Error(`[Config] Missing required env variable: ${name}`)
    return val
}

const keycloakConfig = {
    url:      required('KEYCLOAK_URL'),
    realm:    required('KEYCLOAK_REALM'),
    clientId: required('KEYCLOAK_CLIENT_ID'),

    // Clients autorisés à émettre des tokens acceptés par ce backend.
    // Le token frontend (reports_frontend) et le token backend (reports_api)
    // sont tous les deux valides — même realm, clé publique identique.
    get allowedClients() {
        return [
            this.clientId,
            process.env.KEYCLOAK_FRONTEND_CLIENT_ID || 'reports_frontend',
        ]
    },

    // URL du JWKS endpoint — clés publiques RSA de Keycloak
    get jwksUri() {
        return `${this.url}/realms/${this.realm}/protocol/openid-connect/certs`
    },

    // Issuer exact attendu dans le claim "iss" du token
    get issuer() {
        return `${this.url}/realms/${this.realm}`
    },

    algorithms: ['RS256'],

    // Cache des clés publiques JWKS : 10 minutes
    // Évite d'appeler Keycloak à chaque requête
    jwksCacheDuration: 10 * 60 * 1000,
}

module.exports = keycloakConfig