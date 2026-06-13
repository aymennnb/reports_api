'use strict'

require('dotenv').config()

const express    = require('express')
const mongoose   = require('mongoose')
const cors       = require('cors')
const helmet     = require('helmet')
const rateLimit  = require('express-rate-limit')

const app = express()

// ── Helmet ────────────────────────────────────────────────────────────────────
app.use(helmet({
    contentSecurityPolicy:          false,
    hsts:                           false,
    frameguard:                     false,
    referrerPolicy:                 false,
    xssFilter:                      false,
    noSniff:                        false,
    permittedCrossDomainPolicies:   false,
    crossOriginEmbedderPolicy:      false,
    crossOriginOpenerPolicy:        false,
    crossOriginResourcePolicy:      false,
    originAgentCluster:             false,
    hidePoweredBy:                  true,
    ieNoOpen:                       true,
}))

const ALLOWED_ORIGINS = (process.env.FRONTEND_URL)
    .split(',')
    .map(o => o.trim())

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
            return callback(null, true)
        }
        console.warn("[CORS] Blocked origin: %s", origin)
        callback(new Error(`CORS: origin ${origin} not allowed`))
    },
    methods:          ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders:   ['Content-Type', 'Authorization'],
    exposedHeaders:   ['X-Total-Count'],
    credentials:      true,
    optionsSuccessStatus: 200,
}))

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max:      500,
    standardHeaders: true,
    legacyHeaders:   false,
    keyGenerator: (req) => req.ip,
    skip: (req) => {
        const whitelist = (process.env.IP_WHITELIST || '').split(',').map(ip => ip.trim()).filter(Boolean)
        return whitelist.includes(req.ip)
    },
    message: { message: 'Too many requests, please try again later.' },
})
app.use('/api', globalLimiter)

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max:      50,               // Plus permissif : Nginx limite déjà à 1r/s
    standardHeaders: true,
    legacyHeaders:   false,
    keyGenerator: (req) => req.ip,
    skip: (req) => {
        const whitelist = (process.env.IP_WHITELIST || '').split(',').map(ip => ip.trim()).filter(Boolean)
        return whitelist.includes(req.ip)
    },
    message: { message: 'Too many login attempts, please try again later.' },
})

app.set('trust proxy', 1)

// ── Body parsers ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: '5mb' }))
app.use(express.urlencoded({ extended: true }))

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/api/auth', authLimiter, require('./routes/auth.routes'))
app.use('/api', require('./routes/index'))

// ── Utilitaires ───────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({
    status: 'ok',
    keycloak: process.env.KEYCLOAK_URL,
    db:       mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
}))

app.use((req, res) => {
    res.status(404).json({ message: `Route ${req.method} ${req.path} not found.` })
})

app.use((err, req, res, next) => {
    if (err.message?.startsWith('CORS:')) {
        return res.status(403).json({ message: err.message })
    }
    console.error('[Server Error] %s', err.message || err)
    res.status(500).json({ message: 'Internal server error.' })
})

// ── Démarrage ─────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000

mongoose
    .connect(process.env.MONGODB_URL)
    .then(() => {
        console.log('MongoDB connected')
        app.listen(PORT, () => {
            console.log("Server running on port %s", PORT)
            console.log(`Auth endpoints: POST /auth/login | POST /auth/refresh | POST /auth/logout`)
            console.log("Keycloak: %s/realms/%s", process.env.KEYCLOAK_URL, process.env.KEYCLOAK_REALM)
            console.log("CORS allowed: %s", ALLOWED_ORIGINS.join(', '))
        })
    })
    .catch(err => {
        console.error('MongoDB connection error: %s', err.message)
        process.exit(1)
    })