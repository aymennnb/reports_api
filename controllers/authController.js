'use strict'

const { loginWithPassword, refreshAccessToken, revokeToken } = require('../services/authService')
const { logAction } = require('../services/journalService')

const getIp = (req) =>
    req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    ?? req.socket?.remoteAddress
    ?? req.ip
    ?? null

const safeLog = async (payload) => {
    try {
        await logAction(null, payload)
    } catch (err) {
        console.warn('[AuthLog] Failed to write audit log (non-fatal): %s', err.message) // SÉCURISATION SAST [CWE-134]
    }
}

const login = async (req, res) => {
    const { username, password } = req.body

    if (!username || !password) {
        return res.status(400).json({
            message: 'username and password are required.',
            code:    'MISSING_CREDENTIALS',
        })
    }

    const ip = getIp(req)

    try {
        const result = await loginWithPassword(username.trim(), password)

        console.log('[Auth] Login successful for user: %s', result.userInfo.username) // SÉCURISATION SAST [CWE-134]

        await safeLog({
            user_id:     result.userInfo.id,
            username:    result.userInfo.username,
            action:      'LOGIN_SUCCESS',
            target_type: 'Authentication',
            target_id:   result.userInfo.username,
            status:      'success',
            ip_address:  ip,
            metadata: {
                roles: result.userInfo.roles,
                email: result.userInfo.email ?? null,
            },
        })

        return res.status(200).json({
            token:        result.accessToken,
            refreshToken: result.refreshToken,
            expiresIn:    result.expiresIn,
            userInfo:     result.userInfo,
        })

    } catch (err) {
        console.warn('[Auth] Login failed for "%s" — %s: %s', username, err.code, err.message) // SÉCURISATION SAST [CWE-134]

        await safeLog({
            user_id:     'anonymous',
            username:    username.trim(),
            action:      'LOGIN_FAILED',
            target_type: 'Authentication',
            target_id:   username.trim(),
            status:      'failure',
            ip_address:  ip,
            metadata: {
                reason: err.code    ?? 'UNKNOWN',
                error:  err.message ?? 'Authentication failed.',
            },
        })

        return res.status(err.status || 401).json({
            message: err.message,
            code:    err.code || 'AUTH_FAILED',
        })
    }
}

const refresh = async (req, res) => {
    const { refreshToken } = req.body

    if (!refreshToken) {
        return res.status(400).json({
            message: 'refreshToken is required.',
            code:    'MISSING_REFRESH_TOKEN',
        })
    }

    try {
        const result = await refreshAccessToken(refreshToken)

        return res.status(200).json({
            token:        result.accessToken,
            refreshToken: result.refreshToken,
            expiresIn:    result.expiresIn,
            userInfo:     result.userInfo,
        })
    } catch (err) {
        console.warn('[Auth] Token refresh failed — %s: %s', err.code, err.message) // SÉCURISATION SAST [CWE-134]

        return res.status(err.status || 401).json({
            message: err.message,
            code:    err.code || 'REFRESH_FAILED',
        })
    }
}

const logout = async (req, res) => {
    const { refreshToken } = req.body
    const ip = getIp(req)

    await revokeToken(refreshToken)

    const userId   = req.user?.id       ?? 'anonymous'
    const username = req.user?.username ?? 'unknown'

    console.log('[Auth] Logout for user: %s', username) // SÉCURISATION SAST [CWE-134]

    await safeLog({
        user_id:     userId,
        username,
        action:      'LOGOUT',
        target_type: 'Authentication',
        target_id:   username,
        status:      'success',
        ip_address:  ip,
        metadata:    {},
    })

    return res.status(200).json({ message: 'Logged out successfully.' })
}

module.exports = { login, refresh, logout }