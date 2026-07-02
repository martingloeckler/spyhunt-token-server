const { RtcTokenBuilder, RtcRole } = require('agora-token');
const admin = require('firebase-admin');

// Firebase Admin – einmalig initialisieren (Vercel hält die Instanz zwischen Requests warm)
if (!admin.apps.length) {
  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!serviceAccountJson) {
    throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON Umgebungsvariable fehlt');
  }
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(serviceAccountJson)),
  });
}

// Erlaubte Origins für CORS (Capacitor WebView)
const ALLOWED_ORIGINS = [
  'capacitor://localhost',
  'ionic://localhost',
  'http://localhost',
  'http://localhost:4200',
];

const TOKEN_EXPIRE_SECONDS = 3600; // 1 Stunde – ausreichend für max. 30-minütige Spielsitzung

function setCorsHeaders(req, res) {
  const origin = req.headers.origin ?? '';
  const allowed =
    ALLOWED_ORIGINS.includes(origin) ||
    // Vercel-Preview-URLs für lokales Testen zulassen
    origin.endsWith('.vercel.app');

  res.setHeader('Access-Control-Allow-Origin', allowed ? origin : '');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

module.exports = async function handler(req, res) {
  setCorsHeaders(req, res);

  // Preflight-Request (CORS)
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  // Firebase ID Token verifizieren
  const authHeader = req.headers.authorization ?? '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const idToken = authHeader.slice(7);
  try {
    await admin.auth().verifyIdToken(idToken);
  } catch (err) {
    console.error('[agora-token] Ungültiger Firebase ID Token:', err.code);
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const appId = process.env.AGORA_APP_ID;
  const appCertificate = process.env.AGORA_APP_CERTIFICATE;

  if (!appId || !appCertificate) {
    console.error('[agora-token] AGORA_APP_ID oder AGORA_APP_CERTIFICATE fehlt in den Umgebungsvariablen');
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  const { channelName, uid } = req.body ?? {};

  // Input-Validierung (Security Boundary)
  if (typeof channelName !== 'string' || channelName.trim().length === 0) {
    return res.status(400).json({ error: 'channelName fehlt oder ungültig' });
  }
  if (typeof uid !== 'string' || uid.trim().length === 0) {
    return res.status(400).json({ error: 'uid fehlt oder ungültig' });
  }
  // Lobby-Code-Format: nur alphanumerisch, 4–10 Zeichen
  if (!/^[a-zA-Z0-9]{4,10}$/.test(channelName)) {
    return res.status(400).json({ error: 'channelName hat ungültiges Format' });
  }

  const expireTimestamp = Math.floor(Date.now() / 1000) + TOKEN_EXPIRE_SECONDS;

  try {
    const token = RtcTokenBuilder.buildTokenWithUserAccount(
      appId,
      appCertificate,
      channelName.toLowerCase(),
      uid,
      RtcRole.PUBLISHER,
      expireTimestamp,
      expireTimestamp,
    );

    return res.status(200).json({ token });
  } catch (err) {
    console.error('[agora-token] Token-Generierung fehlgeschlagen:', err);
    return res.status(500).json({ error: 'Token generation failed' });
  }
};
