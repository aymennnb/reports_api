/**
 * Service d'écoute des emails entrants → création automatique d'incidents
 * Utilise IMAP pour se connecter à une boîte mail et crée des incidents via le modèle Incident
 */

const Imap = require("imap");
const { simpleParser } = require("mailparser");
const Incident = require("../models/Incident");
const User = require("../models/User");

// ─── Configuration IMAP ────────────────────────────────────────────────────────
const imapConfig = {
  user: process.env.EMAIL_USER,
  password: process.env.EMAIL_PASSWORD,
  host: process.env.EMAIL_HOST || "imap.gmail.com",
  port: parseInt(process.env.EMAIL_PORT) || 993,
  tls: true,
  tlsOptions: { rejectUnauthorized: false },
  authTimeout: 10000,
};

// ─── Utilitaires ───────────────────────────────────────────────────────────────

/**
 * Détermine la priorité de l'incident selon des mots-clés dans le sujet/corps.
 */
function detectPriority(subject = "", body = "") {
  const text = (subject + " " + body).toLowerCase();
  if (/urgent|critique|critique|critical|emergency|alerte rouge/.test(text))
    return "high";
  if (/important|moyen|medium|attention/.test(text)) return "medium";
  return "low";
}

/**
 * Extrait une catégorie d'incident depuis le sujet de l'email.
 * Ex: "[RESEAU] Panne switch" → catégorie "RESEAU"
 */
function detectCategory(subject = "") {
  const match = subject.match(/\[([^\]]+)\]/);
  return match ? match[1].trim() : "Général";
}

/**
 * Cherche un utilisateur système par défaut pour l'attribution des incidents
 * venant de mails (compte de service ou premier admin).
 */
async function getSystemUser() {
  const systemUser = await User.findOne({ role: "admin" }).sort({
    createdAt: 1,
  });
  return systemUser ? systemUser._id : null;
}

// ─── Traitement d'un email → Incident ──────────────────────────────────────────

/**
 * Parse un email brut et crée un incident dans la base de données.
 * @param {Buffer} rawEmail - Le contenu brut du message IMAP
 */
async function processEmail(rawEmail) {
  try {
    const parsed = await simpleParser(rawEmail);

    const subject = parsed.subject || "(Sans objet)";
    const from = parsed.from?.text || "Inconnu";

    if (!from.toLowerCase().includes("wazuh")) {
  console.log("[EmailListener] Email ignoré (pas Wazuh)");
  return;
}
    const bodyText = parsed.text || parsed.html || "";
    const receivedAt = parsed.date || new Date();

    console.log(`[EmailListener]  Nouvel email reçu de: ${from}`);
    console.log(`[EmailListener]    Sujet: ${subject}`);

    // Vérifier si un incident identique (même sujet + même expéditeur) existe déjà récemment
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const duplicate = await Incident.findOne({
      title: subject,
      source: "email",
      createdAt: { $gte: oneHourAgo },
    });

    if (duplicate) {
      console.log(
        `[EmailListener] ⚠️  Doublon détecté, incident ignoré: ${subject}`
      );
      return;
    }

    const assignedTo = await getSystemUser();
    const priority = detectPriority(subject, bodyText);
    const category = detectCategory(subject);

    // Construire la description avec les métadonnées de l'email
    const description = `
**Incident créé automatiquement depuis un email**

**De :** ${from}
**Reçu le :** ${receivedAt.toLocaleString("fr-FR")}
**Catégorie détectée :** ${category}

---

${bodyText.substring(0,700)}${bodyText.length > 700 ? "\n\n[Message tronqué...]" : ""}
    `.trim();

    const incident = new Incident({
      title: subject,
      description,
      priority,
      category,
      status: "open",
      source: "email",
      reportedBy: from,
      assignedTo,
      metadata: {
        emailFrom: from,
        emailDate: receivedAt,
        emailSubject: subject,
        createdBy: assignedTo,
        scanReportId: null, 
      },
    });

    await incident.save();
    console.log(
      `[EmailListener] ✅ Incident créé avec succès: ${incident._id} — "${subject}" [${priority}]`
    );
  } catch (err) {
    console.error("[EmailListener] ❌ Erreur lors du traitement de l'email:", err.message);
  }
}

// ─── Connexion IMAP & surveillance de la boîte ────────────────────────────────

/**
 * Ouvre la boîte INBOX et écoute les nouveaux messages en temps réel.
 * @param {Imap} imap - Instance IMAP connectée et prête
 */
function watchInbox(imap) {
  imap.openBox("INBOX", false, (err, box) => {
    if (err) {
      console.error("[EmailListener] ❌ Impossible d'ouvrir la boîte INBOX:", err.message);
      return;
    }

    console.log(
      `[EmailListener] Surveillance de la boîte INBOX — ${box.messages.total} message(s) existant(s)`
    );

    // ── Traiter les emails non lus au démarrage ──
    imap.search(["UNSEEN"], (searchErr, results) => {
      if (searchErr || !results || results.length === 0) {
        console.log("[EmailListener] Aucun email non lu au démarrage.");
        return;
      }

      console.log(
        `[EmailListener] 📥 ${results.length} email(s) non lu(s) trouvé(s) au démarrage.`
      );
      fetchMessages(imap, results);
    });

    // ── Écouter les nouveaux emails en temps réel ──
    imap.on("mail", (numNewMsgs) => {
      console.log(`[EmailListener] 📨 ${numNewMsgs} nouveau(x) email(s) reçu(s).`);

      imap.search(["UNSEEN"], (searchErr, results) => {
        if (searchErr || !results || results.length === 0) return;
        fetchMessages(imap, results);
      });
    });
  });
}

/**
 * Récupère et traite une liste de messages par leurs UIDs.
 * @param {Imap} imap - Instance IMAP
 * @param {number[]} uids - Liste des UIDs à récupérer
 */
function fetchMessages(imap, uids) {
  const fetch = imap.fetch(uids, { bodies: "", markSeen: true });

  fetch.on("message", (msg) => {
    const chunks = [];

    msg.on("body", (stream) => {
      stream.on("data", (chunk) => chunks.push(chunk));
      stream.on("end", () => {
        const rawEmail = Buffer.concat(chunks);
        processEmail(rawEmail);
      });
    });
  });

  fetch.on("error", (err) => {
    console.error("[EmailListener] ❌ Erreur lors de la récupération des messages:", err.message);
  });
}

// ─── Point d'entrée principal ──────────────────────────────────────────────────

/**
 * Démarre le service d'écoute des emails.
 * Gère la reconnexion automatique en cas de déconnexion.
 */
function startEmailListener() {
  const imap = new Imap(imapConfig);

  imap.once("ready", () => {
    console.log("[EmailListener] 🔌 Connexion IMAP établie.");
    watchInbox(imap);
  });

  imap.once("error", (err) => {
    console.error("[EmailListener] ❌ Erreur IMAP:", err.message);
    scheduleReconnect();
  });

  imap.once("end", () => {
    console.warn("[EmailListener] ⚡ Connexion IMAP fermée. Reconnexion...");
    scheduleReconnect();
  });

  imap.connect();

  function scheduleReconnect() {
    const delay = 15000; // 15 secondes
    console.log(`[EmailListener] 🔄 Reconnexion dans ${delay / 1000}s...`);
    setTimeout(startEmailListener, delay);
  }
}

module.exports = { startEmailListener };
/**
 *Email reçu
   ↓

*Boîte mail surveillée (IMAP)
   ↓

*Lecture email
   ↓

*Détection priorité + catégorie
   ↓

*Vérification doublon
   ↓

*   Création Incident
   ↓
*Sauvegarde MongoDB
*/