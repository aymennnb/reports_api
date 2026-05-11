// server.js
// ─────────────────────────────────────────────────────────────────────────────
// MIGRATION :
//   SUPPRIMÉ : express-session, keycloak-connect, JWT_SECRET
//   CONSERVÉ : mongoose, express, cors
//   AJOUTÉ   : CORS strict, helmet, rate limiting
// ─────────────────────────────────────────────────────────────────────────────
'use strict'

require('dotenv').config()

const express    = require('express')
const mongoose   = require('mongoose')
const cors       = require('cors')
const helmet     = require('helmet')
const rateLimit  = require('express-rate-limit')

const app = express()

// ─── SÉCURITÉ HTTP ───────────────────────────────────────────────────────────
// helmet ajoute des headers de sécurité (CSP, HSTS, X-Frame-Options...)
app.use(helmet())

// ─── CORS ────────────────────────────────────────────────────────────────────
// Autorise UNIQUEMENT le frontend React.
// En production, remplace par ton domaine réel.
const ALLOWED_ORIGINS = (process.env.FRONTEND_URL)
    .split(',')
    .map(o => o.trim())

app.use(cors({
    origin: (origin, callback) => {
        // Autorise les requêtes sans origin (Postman, curl, scripts serveur)
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
            return callback(null, true)
        }
        console.warn(`[CORS] Blocked origin: ${origin}`)
        callback(new Error(`CORS: origin ${origin} not allowed`))
    },
    methods:          ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders:   ['Content-Type', 'Authorization'],
    exposedHeaders:   ['X-Total-Count'],
    credentials:      true,
    optionsSuccessStatus: 200,
}))

// ─── RATE LIMITING ───────────────────────────────────────────────────────────
// Limite globale : 200 req/15min par IP
// Protège contre les attaques par force brute et le scraping
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max:      200,
    standardHeaders: true,
    legacyHeaders:   false,
    message: { message: 'Too many requests, please try again later.' },
})
app.use('/api', globalLimiter)

// ─── BODY PARSING ────────────────────────────────────────────────────────────
app.use(express.json({ limit: '5mb' }))
app.use(express.urlencoded({ extended: true }))

// ─── ROUTES ──────────────────────────────────────────────────────────────────
// Toutes les routes sous /api — la validation Keycloak est dans chaque route
app.use('/api', require('./routes/index'))

// ─── HEALTHCHECK ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({
    status: 'ok',
    keycloak: process.env.KEYCLOAK_URL,
    db:       mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
}))

// ─── 404 ─────────────────────────────────────────────────────────────────────
app.use((req, res) => {
    res.status(404).json({ message: `Route ${req.method} ${req.path} not found.` })
})

// ─── GESTION D'ERREURS GLOBALE ───────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    // Erreur CORS → 403
    if (err.message?.startsWith('CORS:')) {
        return res.status(403).json({ message: err.message })
    }
    console.error('[Server Error]', err)
    res.status(500).json({ message: 'Internal server error.' })
})

// ─── MONGODB + DÉMARRAGE ─────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000

mongoose
    .connect(process.env.MONGODB_URL)
    .then(() => {
        console.log('MongoDB connected')
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`)
            console.log(`Keycloak: ${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}`)
            console.log(`CORS allowed: ${ALLOWED_ORIGINS.join(', ')}`)
        })
    })
    .catch(err => {
        console.error('MongoDB connection error:', err.message)
        process.exit(1)
    })