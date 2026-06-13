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

const logAction = async (req, { action, target_type, target_id = null, metadata = {}, status = 'success', actor = null, user_id, username, ip_address }) => {
    try {
        const resolvedActor = actor ?? (user_id ? { user_id, username } : extractActor(req))

        await Journal.create({
            user_id:    resolvedActor.user_id,
            username:   resolvedActor.username ?? username ?? null,
            action,
            target_type,
            target_id:  target_id ? String(target_id) : null,
            metadata,
            ip_address: ip_address ?? extractIp(req),
            status,
        })
    } catch (err) {
        console.error('[Journal] Failed to write audit log: %s', err.message, { action, target_type, target_id })
    }
}

module.exports = { logAction, extractIp, extractActor }