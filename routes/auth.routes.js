'use strict'

/**
 * routes/auth.routes.js
 * ─────────────────────────────────────────────────────────────────────────────
 * NOUVEAU FICHIER
 *
 * À monter dans app.js / server.js :
 *   const authRoutes = require('./routes/auth.routes')
 *   app.use('/auth', authRoutes)
 *
 * Routes exposées :
 *   POST /auth/login    — public   (pas de middleware authenticate)
 *   POST /auth/refresh  — public   (le refresh_token EST la preuve d'identité)
 *   POST /auth/logout   — protégée (optionnel, utile pour les audit logs)
 */

const express     = require('express')
const router      = express.Router()
const { authenticate } = require('../middlewares/authenticate')
const { login, refresh, logout } = require('../controllers/authController')

// ── Routes publiques ──────────────────────────────────────────────────────────
router.post('/login',   login)
router.post('/refresh', refresh)

// ── Logout : authenticate optionnel pour les audit logs ───────────────────────
// Si le token est déjà expiré on veut quand même pouvoir logout,
// donc on ne bloque pas sur échec d'auth.
router.post('/logout', (req, res, next) => {
    // Tenter l'authentification mais continuer même si elle échoue
    authenticate(req, res, (err) => {
        if (err) {
            // Token invalide/expiré — on logout quand même
            req.user = null
        }
        next()
    })
}, logout)

module.exports = router