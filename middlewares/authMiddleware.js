const jwt = require("jsonwebtoken");

// ─── Middleware 1 : Vérifier le token JWT ───────────────────────────────────
// Ce middleware protège toutes les routes qui nécessitent une connexion
const verifyToken = (req, res, next) => {
    const authHeader = req.header("Authorization");
    const token = authHeader && authHeader.split(" ")[1]; // Format : "Bearer <token>"

    if (!token) {
        return res.status(401).json({ message: "Access denied. No token provided." });
    }

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified; // On attache les infos du user au request
        next();
    } catch (error) {
        return res.status(403).json({ message: "Invalid token." });
    }
};

// ─── Middleware 2 : Vérifier que le user est ADMIN ──────────────────────────
// Ce middleware s'utilise APRÈS verifyToken
const isAdmin = (req, res, next) => {
    if (req.user.role !== "admin") {
        return res.status(403).json({ message: "Access denied (Admins only)" });
    }
    next();
};

module.exports = { verifyToken, isAdmin };