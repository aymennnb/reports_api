'use strict'

const Journal = require('../models/Journal')

const extractIp = (req) => {
    const forwarded = req?.headers?.['x-forwarded-for']
    if (forwarded) return forwarded.split(',')[0].trim()
    return req?.socket?.remoteAddress || req?.ip || null
}

const extractActor = (req) => ({
    user_id:  req?.keycloakUser?.id   || req?.user?.id   || 'unknown',
    username: req?.keycloakUser?.username || req?.user?.username || null,
})

const logAction = async (req, { action, target_type, target_id = null, metadata = {}, status = 'success', actor = null }) => {
    try {
        const { user_id, username } = actor ?? extractActor(req)

        await Journal.create({
            user_id,
            username,
            action,
            target_type,
            target_id:  target_id ? String(target_id) : null,
            metadata,
            ip_address: extractIp(req),
            status,
        })
    } catch (err) {
        console.error('[Journal] Failed to write audit log:', err.message, { action, target_type, target_id })
    }
}

module.exports = { logAction, extractIp, extractActor }