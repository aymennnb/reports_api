const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    username: {type: String, required: true, unique: true, trim: true},
    password: {type: String, required: true},
    is_active: {type: Boolean, default: true},
    role: {type: String, enum: ["admin", "user"], default: "user"},
    login_attempts: {type: Number, default: 0},
    created_at: {type: Date, default: Date.now}
});

module.exports = mongoose.model("User", userSchema);