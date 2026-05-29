const mongoose = require("mongoose");

const permissionSchema = new mongoose.Schema({
    permission_id: { type: Number, required: true, unique: true },
    permission_name: { type: String, required: true, trim: true }
});

const rolePermissionSchema = new mongoose.Schema({
    user_id: { type: String, required: true },
    permission_id: { type: Number, required: true }
});

const Permission = mongoose.model("Permission", permissionSchema);
const RolePermission = mongoose.model("RolePermission", rolePermissionSchema);

module.exports = { Permission, RolePermission };