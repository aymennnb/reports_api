'use strict'

const axios  = require('axios')
const config = require('../config/keycloak.config')

const KC_URL   = config.url
const REALM    = config.realm
const BASE_URL = `${KC_URL}/admin/realms/${REALM}`

let _adminToken  = null
let _tokenExpiry = 0

const getUserRealmRoles = async (userId) => {
    const token = await getAdminToken()

    const response = await axios.get(
        `${BASE_URL}/users/${userId}/role-mappings/realm`,
        {
            headers: {
                Authorization: `Bearer ${token}`
            }
        }
    )

    return response.data.map(role => role.name)
}

const getAdminToken = async () => {
    if (_adminToken && Date.now() < _tokenExpiry) return _adminToken

    const params = new URLSearchParams({
        grant_type:    'client_credentials',
        client_id:     process.env.KEYCLOAK_ADMIN_CLIENT_ID,
        client_secret: process.env.KEYCLOAK_ADMIN_CLIENT_SECRET,
    })

    const { data } = await axios.post(
        `${KC_URL}/realms/${REALM}/protocol/openid-connect/token`,
        params,
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    )

    _adminToken  = data.access_token
    _tokenExpiry = Date.now() + (data.expires_in - 30) * 1000
    return _adminToken
}

const adminAxios = async () => {
    const token = await getAdminToken()
    return axios.create({
        baseURL: BASE_URL,
        headers: { Authorization: `Bearer ${token}` },
    })
}

const KeycloakAdmin = {
    async getUsers() {
        const client = await adminAxios()
        const { data } = await client.get('/users?max=200')
        return data
    },
    async getUserById(id) {
        const client = await adminAxios()
        const { data } = await client.get(`/users/${id}`)
        return data
    },
    async createUser({ username, email, firstName, lastName, password }) {
        const client = await adminAxios()
        const res = await client.post('/users', {
            username, email, firstName, lastName, enabled: true,
            credentials: [{ type: 'password', value: password, temporary: false }],
        })
        const id = res.headers['location'].split('/').pop()
        return { id }
    },
    async updateUser(id, updates) {
        const client = await adminAxios()
        await client.put(`/users/${id}`, updates)
    },
    async deleteUser(id) {
        const client = await adminAxios()
        await client.delete(`/users/${id}`)
    },
    async assignRealmRole(userId, roleName) {
        const client = await adminAxios()
        const { data: role } = await client.get(`/roles/${roleName}`)
        await client.post(`/users/${userId}/role-mappings/realm`, [role])
    },
}

module.exports = {KeycloakAdmin, getUserRealmRoles}