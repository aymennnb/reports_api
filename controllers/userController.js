const User = require("../models/User");
const { Permission, RolePermission } = require("../models/Permission");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

//  AUTHENTIFICATION ════════════════════════════════════════════════════════════════
// POST /api/auth/login
const loginUser = async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ message: "Username and password are required." });
        }

        const user = await User.findOne({ username });

        if (!user) {
            return res.status(401).json({ message: "Invalid credentials." });
        }

        if (!user.is_active) {
            return res.status(403).json({ message: "Account is disabled (Contact an administrator)." });
        }

        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            user.login_attempts += 1;

            if (user.role === "user" && user.login_attempts >= 3) {
                user.is_active = false;
                await user.save();
                return res.status(403).json({ message: "Account blocked after 3 failed attempts (Contact an administrator)." });
            }

            await user.save();
            return res.status(401).json({ message: "Invalid credentials." });
        }

        user.login_attempts = 0;
        await user.save();

        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.status(200).json({ message: "Login successful.", token });

    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};

// GESTION DES UTILISATEURS ════════════════════════════════════════════════════════════════
// POST /api/users (ADMIN seulement)
const createUser = async (req, res) => {
    try {
        const { username, password, role } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: "Username and password are required." });
        }

        const existing = await User.findOne({ username });
        if (existing) {
            return res.status(400).json({ message: "Username already exists." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({username, password: hashedPassword, role: role});
        await newUser.save();

        res.status(201).json({ message: "User created successfully." });

    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};

// GET /api/users (utilisateurs authentifié)
const getUsers = async (req, res) => {
    try {
        const users = await User.find({ _id: { $ne: req.user.id } })
            .select("-password -login_attempts")
            .sort({ created_at: -1 });

        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};

// GET /api/users/:id (utilisateur par ID authentifié)
const getUserById = async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select("-password -login_attempts");

        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        res.status(200).json(user);

    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};

// PUT /api/users/:id (Modifier un utilisateur) - ADMIN seulement
const updateUser = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);

        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        if (req.body.password) {
            req.body.password = await bcrypt.hash(req.body.password, 10);
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true }
        ).select("-password -login_attempts");

        res.status(200).json({ message: "User updated successfully.", user: updatedUser });

    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};

// DELETE /api/users/:id (Supprimer un utilisateur) - ADMIN seulement
const deleteUser = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);

        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        await User.findByIdAndDelete(req.params.id);

        res.status(200).json({ message: "User deleted successfully." });

    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};

// PUT /api/users/:id/activate (Réactiver un compte bloqué) — ADMIN seulement
const activateUser = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);

        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        user.is_active = true;
        user.login_attempts = 0;
        await user.save();

        res.status(200).json({ message: "User account reactivated successfully." });

    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};


//  GESTION DES PERMISSIONS ════════════════════════════════════════════════════════════════
// GET /api/permissions
const getAllPermissions = async (req, res) => {
    try {
        const permissions = await Permission.find().sort({ permission_id: 1 });
        res.status(200).json({ permissions });
    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};

// POST /api/users/:id/permissions (Assigner une permission) — ADMIN seulement
const assignPermission = async (req, res) => {
    try {
        const { permission_id } = req.body;
        const user_id = req.params.id;

        if (!permission_id) {
            return res.status(400).json({ message: "permission_id is required." });
        }

        const user = await User.findById(user_id);
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        // Vérifier que la permission existe
        const permission = await Permission.findOne({ permission_id });
        if (!permission) {
            return res.status(404).json({ message: "Permission not found." });
        }

        // Vérifier que la permission n'est pas déjà assignée
        const alreadyAssigned = await RolePermission.findOne({ user_id, permission_id });
        if (alreadyAssigned) {
            return res.status(400).json({ message: "Permission already assigned to this user." });
        }

        await new RolePermission({ user_id, permission_id }).save();

        res.status(201).json({ message: "Permission assigned successfully." });

    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};

// DELETE /api/users/:id/permissions/:permission_id (Retirer une permission) — ADMIN seulement
const removePermission = async (req, res) => {
    try {
        const user_id = req.params.id;
        const permission_id = parseInt(req.params.permission_id);

        const entry = await RolePermission.findOneAndDelete({ user_id, permission_id });

        if (!entry) {
            return res.status(404).json({ message: "Permission not found for this user." });
        }

        res.status(200).json({ message: "Permission removed successfully." });

    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};

// GET /api/users/:id/permissions (Voir les permissions d'un user) (authentifié)
const getUserPermissions = async (req, res) => {
    try {
        const user_id = req.params.id;

        // Récupérer toutes les permissions assignées au user
        const rolePermissions = await RolePermission.find({ user_id });

        if (rolePermissions.length === 0) {
            return res.status(200).json({ permissions: [] });
        }

        // Récupérer les détails de chaque permission
        const permissionIds = rolePermissions.map(rp => rp.permission_id);
        const permissions = await Permission.find({ permission_id: { $in: permissionIds } });

        res.status(200).json({ permissions });

    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
};

module.exports = {
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
};