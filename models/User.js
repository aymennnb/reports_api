// models/User.js
// ─────────────────────────────────────────────────────────────────────────────
// MIGRATION :
//   SUPPRIMÉ : password, is_active, login_attempts, role  → gérés par Keycloak
//   CONSERVÉ : username, email, created_at
//   AJOUTÉ   : keycloak_id (sub UUID), department, preferences
//
// Ce modèle ne stocke que les métadonnées applicatives.
// Les credentials et rôles vivent dans Keycloak.
// ─────────────────────────────────────────────────────────────────────────────
'use strict'

const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    // Sub Keycloak — clé de liaison entre le token JWT et ce document MongoDB
    keycloak_id: {
        type:     String,
        required: true,
        unique:   true,
        index:    true,
    },
    username: {
        type:     String,
        required: true,
        unique:   true,
        trim:     true,
    },
    email: {
        type:      String,
        trim:      true,
        lowercase: true,
        default:   null,
    },
    // Métadonnées applicatives (optionnelles)
    department:  { type: String,  default: null },
    avatar_url:  { type: String,  default: null },
    preferences: { type: mongoose.Schema.Types.Mixed, default: {} },
    created_at:  { type: Date, default: Date.now },
    updated_at:  { type: Date, default: Date.now },
})

userSchema.pre('save', function (next) {
    this.updated_at = new Date()
    next()
})

module.exports = mongoose.model('User', userSchema)