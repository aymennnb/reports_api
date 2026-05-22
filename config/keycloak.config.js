'use strict'

/**
 * config/keycloak.config.js
 * ─────────────────────────────────────────────────────────────────────────────
 * CHANGEMENT :
 *   ✓ AJOUTÉ  — clientSecret (KEYCLOAK_CLIENT_SECRET) requis pour le flow password
 *
 * Variables d'environnement nécessaires :
 *   KEYCLOAK_URL              — ex: https://auth.example.com
 *   KEYCLOAK_REALM            — ex: exia
 *   KEYCLOAK_CLIENT_ID        — client_id du client backend (confidential)
 *   KEYCLOAK_CLIENT_SECRET    — ← NOUVEAU : client_secret du client backend
 *   KEYCLOAK_ADMIN_CLIENT_ID     — pour keycloakAdmin.js (inchangé)
 *   KEYCLOAK_ADMIN_CLIENT_SECRET — pour keycloakAdmin.js (inchangé)
 *   KEYCLOAK_FRONTEND_CLIENT_ID  — optionnel, pour valider azp des anciens tokens
 *
 * ⚠️  Dans Keycloak, s'assurer que le client est configuré :
 *   - Access Type: confidential
 *   - Direct Access Grants Enabled: ON  (requis pour grant_type=password)
 */

const required = (name) => {
    const val = process.env[name]
    if (!val) throw new Error(`[Config] Missing required env variable: ${name}`)
    return val
}

const keycloakConfig = {
    url:          required('KEYCLOAK_URL'),
    realm:        required('KEYCLOAK_REALM'),
    clientId:     required('KEYCLOAK_CLIENT_ID'),
    clientSecret: required('KEYCLOAK_CLIENT_SECRET'),

    get allowedClients() {
        return [
            this.clientId,
            process.env.KEYCLOAK_FRONTEND_CLIENT_ID,
        ].filter(Boolean)
    },

    get jwksUri() {
        return `${this.url}/realms/${this.realm}/protocol/openid-connect/certs`
    },

    get issuer() {
        return `${this.url}/realms/${this.realm}`
    },

    algorithms: ['RS256'],

    jwksCacheDuration: 10 * 60 * 1000,
}

module.exports = keycloakConfig