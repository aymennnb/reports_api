'use strict'

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