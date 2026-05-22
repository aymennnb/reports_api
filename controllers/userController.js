'use strict'

const User = require('../models/User')
const { KeycloakAdmin, getUserRealmRoles } = require('../services/keycloakAdmin')
const { logAction } = require('../services/journalService')

const getMyProfile = async (req, res) => {
    try {
        const { id: keycloak_id, username, email } = req.keycloakUser

        const user = await User.findOneAndUpdate(
            { keycloak_id },
            { $setOnInsert: { keycloak_id, username, email } },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        )

        res.status(200).json({
            keycloak_id: user.keycloak_id,
            username:    user.username,
            email:       user.email,
            roles:       req.keycloakUser.roles,
            department:  user.department,
            preferences: user.preferences,
            created_at:  user.created_at,
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ message: 'Server error.' })
    }
}

const updateMyProfile = async (req, res) => {
    try {
        const { id: keycloak_id } = req.keycloakUser
        const allowed = ['department', 'avatar_url', 'preferences']
        const updates = {}
        allowed.forEach(field => {
            if (req.body[field] !== undefined) updates[field] = req.body[field]
        })

        const updatedUser = await User.findOneAndUpdate(
            { keycloak_id },
            { $set: { ...updates, updated_at: new Date() } },
            { new: true }
        )

        if (!updatedUser) return res.status(404).json({ message: 'User not found in local DB.' })

        await logAction(req, {
            action:      'UPDATE_USER',
            target_type: 'User',
            target_id:   keycloak_id,
            metadata:    { self_update: true, fields_updated: Object.keys(updates) },
        })

        res.status(200).json({ message: 'Profile updated.', user: updatedUser })
    } catch (error) {
        res.status(500).json({ message: 'Server error.' })
    }
}

const getUsers = async (req, res) => {
    try {
        const users = await KeycloakAdmin.getUsers()
        res.status(200).json(users)
    } catch (error) {
        console.error(error)
        res.status(500).json({ message: 'Failed to fetch users from Keycloak.' })
    }
}

const getUserById = async (req, res) => {
    try {
        const user = await KeycloakAdmin.getUserById(req.params.id)
        if (!user) return res.status(404).json({ message: 'User not found.' })
        res.status(200).json(user)
    } catch (error) {
        res.status(500).json({ message: 'Server error.' })
    }
}

const createUser = async (req, res) => {
    try {
        const { username, email, password, role, firstName, lastName } = req.body

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required.' })
        }

        let kcUser
        try {
            kcUser = await KeycloakAdmin.createUser({ username, email, firstName, lastName, password })
        } catch (createError) {
            const kcStatus  = createError?.response?.status
            const kcMessage = createError?.response?.data?.errorMessage
                           || createError?.response?.data?.error_description
                           || createError?.response?.data?.error
                           || createError?.message

            if (kcStatus === 409) {
                return res.status(409).json({ message: 'A user with this username or email already exists.' })
            }

            console.error('[createUser] Keycloak user creation failed:', kcMessage)
            return res.status(500).json({ message: kcMessage || 'Failed to create user in Keycloak.' })
        }

        if (role) {
            try {
                await KeycloakAdmin.assignRealmRole(kcUser.id, role)

                await logAction(req, {
                    action:      'ASSIGN_ROLE',
                    target_type: 'User',
                    target_id:   kcUser.id,
                    metadata:    { username, role },
                })
            } catch (roleError) {
                const kcMessage = roleError?.response?.data?.errorMessage || roleError?.message
                console.error(`[createUser] Role assignment failed for user ${kcUser.id}:`, kcMessage)

                await logAction(req, {
                    action:      'CREATE_USER',
                    target_type: 'User',
                    target_id:   kcUser.id,
                    metadata:    { username, email, firstName, lastName, role_requested: role },
                })

                return res.status(201).json({
                    message: `User created but role assignment failed: ${kcMessage || 'unknown error'}. You can assign the role manually.`,
                    id:      kcUser.id,
                    warning: true,
                })
            }
        }

        await logAction(req, {
            action:      'CREATE_USER',
            target_type: 'User',
            target_id:   kcUser.id,
            metadata:    { username, email, firstName, lastName, role: role || null },
        })

        return res.status(201).json({ message: 'User created successfully.', id: kcUser.id })

    } catch (error) {
        console.error('[createUser] Unexpected error:', error)
        const msg = error?.response?.data?.errorMessage || error?.message || 'Server error.'
        return res.status(500).json({ message: msg })
    }
}

const updateUser = async (req, res) => {
    try {
        await KeycloakAdmin.updateUser(req.params.id, req.body)

        await logAction(req, {
            action:      'UPDATE_USER',
            target_type: 'User',
            target_id:   req.params.id,
            metadata:    { fields_updated: Object.keys(req.body) },
        })

        res.status(200).json({ message: 'User updated in Keycloak.' })
    } catch (error) {
        res.status(500).json({ message: 'Server error.' })
    }
}

const deleteUser = async (req, res) => {
    try {
        let deletedUserInfo = null
        try {
            deletedUserInfo = await KeycloakAdmin.getUserById(req.params.id)
        } catch (_) {}

        await KeycloakAdmin.deleteUser(req.params.id)
        await User.findOneAndDelete({ keycloak_id: req.params.id })

        await logAction(req, {
            action:      'DELETE_USER',
            target_type: 'User',
            target_id:   req.params.id,
            metadata:    {
                username: deletedUserInfo?.username || null,
                email:    deletedUserInfo?.email    || null,
            },
        })

        res.status(200).json({ message: 'User deleted.' })
    } catch (error) {
        res.status(500).json({ message: 'Server error.' })
    }
}

const setUserStatus = (enabled) => async (req, res) => {
    try {
        await KeycloakAdmin.updateUser(req.params.id, { enabled })

        await logAction(req, {
            action:      enabled ? 'ACTIVATE_USER' : 'DEACTIVATE_USER',
            target_type: 'User',
            target_id:   req.params.id,
            metadata:    { enabled },
        })

        res.status(200).json({ message: `User ${enabled ? 'activated' : 'deactivated'}.` })
    } catch (error) {
        res.status(500).json({ message: 'Server error.' })
    }
}

const getAllPermissions = async (req, res) => {
    try {
        res.status(200).json({ permissions: req.keycloakUser.roles })
    } catch (error) {
        res.status(500).json({ message: 'Server error.' })
    }
}

const getUserPermissions = async (req, res) => {
    try {
        const requestedId = req.params.id
        const currentId   = req.keycloakUser.id
        const roles       = req.keycloakUser.roles || []

        if (requestedId === currentId) {
            return res.status(200).json({ permissions: roles })
        }

        if (!roles.includes('admin')) {
            return res.status(403).json({ message: 'Access denied.' })
        }

        if (typeof getUserRealmRoles !== 'function') {
            return res.status(501).json({ message: 'getUserRealmRoles not implemented.' })
        }

        const userRoles = await getUserRealmRoles(requestedId)
        res.status(200).json({ permissions: userRoles })
    } catch (error) {
        res.status(500).json({ message: 'Server error.' })
    }
}

module.exports = {
    getMyProfile, updateMyProfile,
    getUsers, getUserById, createUser, updateUser, deleteUser, setUserStatus,
    getAllPermissions, getUserPermissions,
}