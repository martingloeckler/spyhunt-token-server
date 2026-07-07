const { RtcTokenBuilder, RtcRole } = require('agora-token');

const ALLOWED_ORIGINS = [
  'capacitor://localhost',
  'ionic://localhost',
  'http://localhost',
  'http://localhost:4200',
  'https://localhost',
];

const TOKEN_EXPIRE_SECONDS = 3600;

function setCorsHeaders(req, res) {
  const origin = req.headers.origin ?? '';
  const allowed = ALLOWED_ORIGINS.includes(origin) || origin.endsWith('.vercel.app');
  res.setHeader('Access-Control-Allow-Origin', allowed ? origin : '');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

async function verifyFirebaseToken(idToken) {
  const apiKey = process.env.FIREBASE_WEB_API_KEY;
  if (!apiKey) throw new Error('FIREBASE_WEB_API_KEY Umgebungsvariable fehlt');
  const response = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${apiKey}`,
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken }) }
  );
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err?.error?.message ?? 'Token ungueltig');
  }
  const data = await response.json();
  if (!data.users?.length) throw new Error('Kein User gefunden');
  return data.users[0];
}

module.exports = async function handler(req, res) {
  setCorsHeaders(req, res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

  const authHeader = req.headers.authorization ?? '';
  if (!authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const idToken = authHeader.slice(7);
  try {
    await verifyFirebaseToken(idToken);
  } catch (err) {
    console.error('[agora-token] Token-Verifikation fehlgeschlagen:', err.message);
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const appId = process.env.AGORA_APP_ID;
  const appCertificate = process.env.AGORA_APP_CERTIFICATE;
  if (!appId || !appCertificate) return res.status(500).json({ error: 'Server misconfigured' });

  const { channelName, uid } = req.body ?? {};
  if (typeof channelName !== 'string' || channelName.trim().length === 0)
    return res.status(400).json({ error: 'channelName fehlt oder ungueltig' });
  if (typeof uid !== 'string' || uid.trim().length === 0)
    return res.status(400).json({ error: 'uid fehlt oder ungueltig' });
  if (!/^[a-zA-Z0-9]{4,10}$/.test(channelName))
    return res.status(400).json({ error: 'channelName hat ungueltiges Format' });

  const expireTimestamp = Math.floor(Date.now() / 1000) + TOKEN_EXPIRE_SECONDS;
  try {
    const token = RtcTokenBuilder.buildTokenWithUserAccount(
      appId, appCertificate, channelName.toLowerCase(), uid,
      RtcRole.PUBLISHER, expireTimestamp, expireTimestamp
    );
    return res.status(200).json({ token });
  } catch (err) {
    console.error('[agora-token] Token-Generierung fehlgeschlagen:', err);
    return res.status(500).json({ error: 'Token generation failed' });
  }
};
