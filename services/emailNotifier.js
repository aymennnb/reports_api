const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // STARTTLS
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD, 
  },
});

async function sendAlertEmail(incident) {
  await transporter.sendMail({
    from: `"SIEM Alert" <${process.env.EMAIL_USER}>`,
    to: process.env.ALERT_EMAIL_RECIPIENT || process.env.EMAIL_USER,
    subject: `🚨 [${incident.priority.toUpperCase()}] ${incident.title}`,
    text: `
Nouvel incident détecté par Wazuh

Titre    : ${incident.title}
Priorité : ${incident.priority}
Catégorie: ${incident.category}
Agent    : ${incident.metadata?.wazuhAgentName || 'N/A'}
IP       : ${incident.metadata?.wazuhAgentIp || 'N/A'}
Règle    : ${incident.metadata?.wazuhRuleId || 'N/A'} (niveau ${incident.metadata?.wazuhRuleLevel || 'N/A'})
Heure    : ${new Date().toLocaleString('fr-FR')}
    `.trim(),
  });
  console.log(`[EmailNotifier] ✅ Email envoyé pour incident ${incident._id}`);
}

module.exports = { sendAlertEmail };