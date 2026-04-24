const express = require("express");
const { verifyToken, isAdmin } = require("../middlewares/authMiddleware");
const {
    loginUser,
    createUser,
    getUsers,
    getUserById,
    updateUser,
    deleteUser,
    activateUser,
    assignPermission,
    removePermission,
    getUserPermissions,
    getAllPermissions
} = require("../controllers/userController");

const router = express.Router();

// ─── AUTHENTIFICATION ────────────────────────────────────────────
// Public
router.post("/auth/login", loginUser);

// ─── GESTION DES UTILISATEURS ────────────────────────────────────
// verifyToken ────────────────────────────────────
// isAdmin ────────────────────────────────────
router.post("/users", verifyToken, isAdmin, createUser);
router.get("/users", verifyToken, getUsers);
router.get("/users/:id", verifyToken, getUserById);
router.put("/users/:id", verifyToken, isAdmin, updateUser);
router.delete("/users/:id", verifyToken, isAdmin, deleteUser);
router.put("/users/:id/activate", verifyToken, isAdmin, activateUser);

// ─── GESTION DES PERMISSIONS ─────────────────────────────────────
router.get("/permissions", verifyToken, getAllPermissions);
router.get("/users/:id/permissions", verifyToken, getUserPermissions);
router.post("/users/:id/permissions", verifyToken, isAdmin, assignPermission);
router.delete("/users/:id/permissions/:permission_id", verifyToken, isAdmin, removePermission);

module.exports = router;