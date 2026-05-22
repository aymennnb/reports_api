const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
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