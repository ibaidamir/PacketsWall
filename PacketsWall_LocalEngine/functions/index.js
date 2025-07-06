const { onDocumentWritten } = require("firebase-functions/v2/firestore");
const { defineSecret } = require("firebase-functions/params");
const functions = require("firebase-functions");
const admin = require("firebase-admin");
const nodemailer = require("nodemailer");

admin.initializeApp();

const GMAIL_USER = "amiribaid@gmail.com";
const GMAIL_PASS = defineSecret("GMAIL_PASS");

exports.sendDdosAlertEmail = onDocumentWritten(
  {
    document: "network_logs/{docId}",
    region: "europe-west1",
    timeoutSeconds: 30,
    secrets: [GMAIL_PASS],
  },
  async (event) => {
    const log = event.data?.after?.data();
    if (!log || log.type !== "DDoS Alert") return;

    // 🔍 قراءة إعدادات البريد من Firestore
    let recipientEmail;
    try {
      const settingsSnap = await admin.firestore().doc("settings/email_notifications").get();
      const settings = settingsSnap.data();

      if (!settings || !settings.enabled || !settings.email) {
        console.log("🔕 Email notifications are disabled or email is missing.");
        return null;
      }

      recipientEmail = settings.email;
    } catch (error) {
      console.error("❌ Failed to fetch email settings:", error);
      return null;
    }

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: GMAIL_USER,
        pass: GMAIL_PASS.value(),
      },
    });

    const mailOptions = {
      from: `"PacketsWall Alerts" <${GMAIL_USER}>`,
      to: recipientEmail,
      subject: `[⚠️ DDoS ALERT] - ${log.protocol}`,
      html: `
        <h2>🚨 DDoS Attack Detected</h2>
        <p><strong>Timestamp:</strong> ${log.timestamp}</p>
        <p><strong>Suspect IP:</strong> ${log.suspect_ip}</p>
        <p><strong>Protocol:</strong> ${log.protocol}</p>
        <hr />
        <p style="color:gray;">Sent automatically by PacketsWall system</p>
      `,
    };

    try {
      await transporter.sendMail(mailOptions);
      console.log(`✅ Email sent successfully to ${recipientEmail}`);
    } catch (err) {
      console.error("❌ Failed to send email:", err);
    }
  }
);
