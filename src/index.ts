import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import forge from 'node-forge';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

// ─── Config ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
const SERVER_SECRET = process.env.ACTIVATION_SECRET || 'CHANGE_THIS_IN_PRODUCTION_PLEASE';
const DB_PATH = path.join(__dirname, '..', 'data', 'activations.json');
const PUBLIC_KEY_PATH = path.join(__dirname, '..', 'keys', 'public.pem');

if (!fs.existsSync(path.dirname(DB_PATH))) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
}

// ─── Types ───────────────────────────────────────────────────────────────────
interface LicensePayload {
  id: string;
  customer_email: string;
  customer_name: string;
  license_type: string;
  expiry_date: string | null;
  max_activations: number;
  features: string[];
  issue_date: string;
  signature: string;
}

interface Activation {
  license_id: string;
  fingerprint_hash: string;
  activated_at: string;
  last_checkin: string;
  activation_token: string;
}

interface ActivationDB {
  activations: Activation[];
  revoked_ids: string[];
}

// ─── DB helpers ──────────────────────────────────────────────────────────────
function loadDB(): ActivationDB {
  if (!fs.existsSync(DB_PATH)) return { activations: [], revoked_ids: [] };
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
}

function saveDB(db: ActivationDB): void {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

// ─── Crypto helpers ──────────────────────────────────────────────────────────
function verifyLicenseSignature(payload: LicensePayload): boolean {
  try {
    const publicPem = fs.readFileSync(PUBLIC_KEY_PATH, 'utf-8');
    const publicKey = forge.pki.publicKeyFromPem(publicPem);
    const { signature, ...rest } = payload;
    const payloadStr = JSON.stringify(rest);
    const md = forge.md.sha256.create();
    md.update(payloadStr, 'utf8');
    const sigBytes = forge.util.decode64(signature);
    return publicKey.verify(md.digest().bytes(), sigBytes);
  } catch {
    return false;
  }
}

function generateActivationToken(licenseId: string, fingerprintHash: string): string {
  const data = `${licenseId}:${fingerprintHash}:${Date.now()}`;
  return crypto.createHmac('sha256', SERVER_SECRET).update(data).digest('hex');
}

function parseLicenseKey(keyString: string): LicensePayload | null {
  try {
    const cleaned = keyString.replace(/-/g, '');
    const json = Buffer.from(cleaned, 'base64').toString('utf-8');
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function isLicenseExpired(payload: LicensePayload): boolean {
  if (!payload.expiry_date) return false; // lifetime
  return new Date(payload.expiry_date) < new Date();
}

// ─── App ─────────────────────────────────────────────────────────────────────
const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json());

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true });
app.use(limiter);

// Health check
app.get('/health', (_req, res) => res.json({ ok: true, ts: Date.now() }));

// ─── POST /activate ───────────────────────────────────────────────────────────
// Called when customer first activates their license key
app.post('/activate', (req, res) => {
  const { license_key, fingerprint_hash } = req.body;

  if (!license_key || !fingerprint_hash) {
    return res.status(400).json({ error: 'Missing license_key or fingerprint_hash' });
  }

  const payload = parseLicenseKey(license_key);
  if (!payload) return res.status(400).json({ error: 'Invalid license key format' });

  if (!verifyLicenseSignature(payload)) {
    return res.status(403).json({ error: 'License signature invalid' });
  }

  if (isLicenseExpired(payload)) {
    return res.status(403).json({ error: 'License has expired' });
  }

  const db = loadDB();

  if (db.revoked_ids.includes(payload.id)) {
    return res.status(403).json({ error: 'License has been revoked' });
  }

  const existing = db.activations.filter(a => a.license_id === payload.id);

  // Check if this fingerprint is already activated
  const alreadyActivated = existing.find(a => a.fingerprint_hash === fingerprint_hash);
  if (alreadyActivated) {
    // Refresh last check-in and return same token
    alreadyActivated.last_checkin = new Date().toISOString();
    saveDB(db);
    return res.json({
      success: true,
      activation_token: alreadyActivated.activation_token,
      license_id: payload.id,
      features: payload.features,
      expiry_date: payload.expiry_date,
    });
  }

  // Check activation count
  if (existing.length >= payload.max_activations) {
    return res.status(403).json({
      error: `Maximum activations (${payload.max_activations}) reached for this license`,
    });
  }

  const token = generateActivationToken(payload.id, fingerprint_hash);
  const activation: Activation = {
    license_id: payload.id,
    fingerprint_hash,
    activated_at: new Date().toISOString(),
    last_checkin: new Date().toISOString(),
    activation_token: token,
  };

  db.activations.push(activation);
  saveDB(db);

  return res.json({
    success: true,
    activation_token: token,
    license_id: payload.id,
    features: payload.features,
    expiry_date: payload.expiry_date,
  });
});

// ─── POST /checkin ────────────────────────────────────────────────────────────
// Called every 14 days to refresh status and check for revocation
app.post('/checkin', (req, res) => {
  const { license_id, fingerprint_hash, activation_token } = req.body;

  if (!license_id || !fingerprint_hash || !activation_token) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const db = loadDB();

  if (db.revoked_ids.includes(license_id)) {
    return res.status(403).json({ error: 'License has been revoked', revoked: true });
  }

  const activation = db.activations.find(
    a => a.license_id === license_id &&
         a.fingerprint_hash === fingerprint_hash &&
         a.activation_token === activation_token
  );

  if (!activation) {
    return res.status(403).json({ error: 'Activation not found or token mismatch' });
  }

  activation.last_checkin = new Date().toISOString();
  saveDB(db);

  return res.json({ success: true, revoked: false, next_checkin_days: 14 });
});

// ─── POST /revoke (admin endpoint — protect with secret header) ───────────────
app.post('/revoke', (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (adminSecret !== SERVER_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { license_id } = req.body;
  if (!license_id) return res.status(400).json({ error: 'Missing license_id' });

  const db = loadDB();
  if (!db.revoked_ids.includes(license_id)) {
    db.revoked_ids.push(license_id);
    saveDB(db);
  }

  return res.json({ success: true, revoked: license_id });
});

// ─── GET /activations (admin — view all) ─────────────────────────────────────
app.get('/activations', (req, res) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (adminSecret !== SERVER_SECRET) return res.status(401).json({ error: 'Unauthorized' });

  const db = loadDB();
  return res.json({ activations: db.activations, revoked_ids: db.revoked_ids });
});

app.listen(PORT, () => {
  console.log(`\n🔐 InvoiceMaker Licensing Server`);
  console.log(`   Running on port ${PORT}`);
  console.log(`   Activation endpoint: POST /activate`);
  console.log(`   Checkin endpoint:    POST /checkin`);
  console.log(`   Admin revoke:        POST /revoke  (requires x-admin-secret header)\n`);
});
