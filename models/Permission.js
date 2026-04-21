const mongoose = require('mongoose');

// ─── PERMISSION SCHEMA ─────────────────────────────────────────────────────────
const PermissionSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Permission name is required'],
      unique: true,
      trim: true,
      enum: [
        'view_incidents',
        'create_incidents',
        'edit_incidents',
        'delete_incidents',
        'resolve_incidents',
        'view_reports',
        'create_reports',
        'edit_reports',
        'delete_reports',
        'manage_users',
        'manage_permissions',
        'view_analytics',
        'export_data'
      ]
    },
    description: {
      type: String,
      default: ''
    }
  },
  { timestamps: true }
);

// ─── ROLE PERMISSION SCHEMA ────────────────────────────────────────────────────
const RolePermissionSchema = new mongoose.Schema(
  {
    role: {
      type: String,
      required: [true, 'Role is required'],
      enum: ['admin', 'analyst', 'user', 'viewer'],
      unique: true
    },
    permissions: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Permission'
      }
    ]
  },
  { timestamps: true }
);

// ─── EXPORTS ───────────────────────────────────────────────────────────────────
const Permission = mongoose.model('Permission', PermissionSchema);
const RolePermission = mongoose.model('RolePermission', RolePermissionSchema);

module.exports = { Permission, RolePermission };
