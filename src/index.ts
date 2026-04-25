import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import forge from 'node-forge';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const PORT   = process.env.PORT || 4000;
const SECRET = process.env.ACTIVATION_SECRET || 'change-this-in-production';
const DB     = path.join(__dirname, '..', 'data', 'activations.json');
const PUB    = path.join(__dirname, '..', 'keys', 'public.pem');

if (!fs.existsSync(path.dirname(DB))) fs.mkdirSync(path.dirname(DB), { recursive: true });

interface Activation {
  license_id: string; fingerprint_hash: string;
  activated_at: string; last_checkin: string; token: string;
}
interface DB { activations: Activation[]; revoked: string[]; }

const loadDB = (): DB => fs.existsSync(DB)
  ? JSON.parse(fs.readFileSync(DB,'utf-8'))
  : { activations: [], revoked: [] };

const saveDB = (db: DB) => fs.writeFileSync(DB, JSON.stringify(db, null, 2));

function verifyLicense(payload: any): boolean {
  console.log('[SERVER] Verifying license signature...');
  try {
    const pubPem = fs.readFileSync(PUB, 'utf-8');
    console.log(`[SERVER]   Public key file: ${PUB} (${pubPem.length} chars)`);
    const pub = forge.pki.publicKeyFromPem(pubPem);
    console.log('[SERVER]   ✅ Public key parsed OK');

    const { signature, ...rest } = payload;
    const signString = `${rest.id}|${rest.customer_email}|${rest.license_type}|${rest.expiry_date || 'never'}|${rest.max_activations}|${rest.issue_date}`;
    console.log(`[SERVER]   Sign string: ${signString}`);
    console.log(`[SERVER]   Signature (first 40): ${signature?.substring(0, 40)}... (${signature?.length} chars)`);

    const md = forge.md.sha256.create();
    md.update(signString, 'utf8');
    const result = pub.verify(md.digest().bytes(), forge.util.decode64(signature));
    console.log(`[SERVER]   Verification result: ${result}`);
    return result;
  } catch (e: any) {
    console.log(`[SERVER]   ❌ Verification EXCEPTION: ${e.message}`);
    console.log(`[SERVER]   Stack: ${e.stack}`);
    return false;
  }
}

function parseKey(keyStr: string): any {
  console.log('[SERVER] Parsing license key...');
  console.log(`[SERVER]   Key length: ${keyStr.length} chars`);
  console.log(`[SERVER]   Key preview: ${keyStr.substring(0, 40)}...`);
  try {
    const clean = keyStr.replace(/-/g, '');
    console.log(`[SERVER]   After dash removal: ${clean.length} chars`);
    const decoded = Buffer.from(clean, 'base64').toString('utf8');
    console.log(`[SERVER]   Decoded JSON preview: ${decoded.substring(0, 120)}...`);
    const parsed = JSON.parse(decoded);
    console.log('[SERVER]   ✅ Parsed OK');
    console.log(`[SERVER]     id:              ${parsed.id}`);
    console.log(`[SERVER]     customer_email:  ${parsed.customer_email}`);
    console.log(`[SERVER]     license_type:    ${parsed.license_type}`);
    console.log(`[SERVER]     expiry_date:     ${parsed.expiry_date}`);
    console.log(`[SERVER]     max_activations: ${parsed.max_activations}`);
    console.log(`[SERVER]     issue_date:      ${parsed.issue_date}`);
    return parsed;
  } catch (e: any) {
    console.log(`[SERVER]   ❌ Parse FAILED: ${e.message}`);
    return null;
  }
}

function makeToken(licId: string, fp: string): string {
  return crypto.createHmac('sha256', SECRET).update(`${licId}:${fp}:${Date.now()}`).digest('hex');
}

const app = express();
app.use(helmet()); app.use(cors()); app.use(express.json());
app.use(rateLimit({ windowMs: 15*60*1000, max: 50 }));

app.get('/health', (_,res) => res.json({ ok: true, ts: Date.now() }));

app.post('/activate', (req, res) => {
  console.log('\n' + '='.repeat(60));
  console.log('[SERVER] === ACTIVATION REQUEST ===');
  console.log('='.repeat(60));

  const { license_key, fingerprint_hash } = req.body;
  console.log(`[SERVER]   fingerprint_hash: ${fingerprint_hash}`);

  if (!license_key || !fingerprint_hash) {
    console.log('[SERVER]   ❌ Missing fields');
    return res.status(400).json({ error: 'Missing fields' });
  }

  const payload = parseKey(license_key);
  if (!payload) {
    console.log('[SERVER]   ❌ Invalid key format');
    return res.status(400).json({ error: 'Invalid key format' });
  }

  if (!verifyLicense(payload)) {
    console.log('[SERVER]   ❌ Signature invalid — REJECTING');
    return res.status(403).json({ error: 'Signature invalid' });
  }
  console.log('[SERVER]   ✅ Signature valid');

  if (payload.expiry_date && new Date(payload.expiry_date) < new Date()) {
    console.log(`[SERVER]   ❌ License expired (${payload.expiry_date})`);
    return res.status(403).json({ error: 'License expired' });
  }
  console.log('[SERVER]   ✅ Not expired');

  const db = loadDB();
  console.log(`[SERVER]   DB: ${db.activations.length} activations, ${db.revoked.length} revoked`);

  if (db.revoked.includes(payload.id)) {
    console.log(`[SERVER]   ❌ License is REVOKED`);
    return res.status(403).json({ error: 'License revoked' });
  }

  const existing = db.activations.filter(a => a.license_id === payload.id);
  const already  = existing.find(a => a.fingerprint_hash === fingerprint_hash);
  console.log(`[SERVER]   Existing activations for this license: ${existing.length}`);
  console.log(`[SERVER]   Already activated on this machine: ${!!already}`);

  if (already) {
    already.last_checkin = new Date().toISOString();
    saveDB(db);
    console.log('[SERVER]   ✅ Re-activation (same machine) — returning existing token');
    return res.json({ success: true, activation_token: already.token,
      license_id: payload.id, features: payload.features, expiry_date: payload.expiry_date });
  }

  if (existing.length >= payload.max_activations) {
    console.log(`[SERVER]   ❌ Max activations reached (${existing.length}/${payload.max_activations})`);
    return res.status(403).json({ error: `Max activations (${payload.max_activations}) reached` });
  }

  const token: Activation = {
    license_id: payload.id, fingerprint_hash,
    activated_at: new Date().toISOString(),
    last_checkin: new Date().toISOString(),
    token: makeToken(payload.id, fingerprint_hash),
  };
  db.activations.push(token);
  saveDB(db);

  console.log(`[SERVER]   ✅ ACTIVATION SUCCESS — token: ${token.token.substring(0, 20)}...`);
  console.log('='.repeat(60) + '\n');

  return res.json({ success: true, activation_token: token.token,
    license_id: payload.id, features: payload.features, expiry_date: payload.expiry_date });
});

app.post('/checkin', (req, res) => {
  console.log('\n[SERVER] === CHECK-IN REQUEST ===');

  const { license_id, fingerprint_hash, activation_token } = req.body;
  console.log(`[SERVER]   license_id:       ${license_id}`);
  console.log(`[SERVER]   fingerprint_hash: ${fingerprint_hash}`);
  console.log(`[SERVER]   activation_token: ${activation_token?.substring(0, 20)}...`);

  if (!license_id || !fingerprint_hash || !activation_token) {
    console.log('[SERVER]   ❌ Missing fields');
    return res.status(400).json({ error: 'Missing fields' });
  }

  const db = loadDB();
  if (db.revoked.includes(license_id)) {
    console.log('[SERVER]   ❌ License REVOKED');
    return res.status(403).json({ error: 'License revoked', revoked: true });
  }

  const act = db.activations.find(
    a => a.license_id === license_id &&
         a.fingerprint_hash === fingerprint_hash &&
         a.token === activation_token
  );

  if (!act) {
    console.log('[SERVER]   ❌ Activation not found — searching for partial matches...');
    const byId = db.activations.filter(a => a.license_id === license_id);
    console.log(`[SERVER]     Activations with this license_id: ${byId.length}`);
    byId.forEach((a, i) => {
      console.log(`[SERVER]     [${i}] fp: ${a.fingerprint_hash.substring(0, 20)}... token: ${a.token.substring(0, 20)}...`);
      console.log(`[SERVER]         fp match: ${a.fingerprint_hash === fingerprint_hash}, token match: ${a.token === activation_token}`);
    });
    return res.status(403).json({ error: 'Activation not found' });
  }

  act.last_checkin = new Date().toISOString();
  saveDB(db);
  console.log('[SERVER]   ✅ CHECK-IN SUCCESS');
  return res.json({ success: true, revoked: false });
});

app.post('/revoke', (req, res) => {
  if (req.headers['x-admin-secret'] !== SECRET)
    return res.status(401).json({ error: 'Unauthorized' });
  const { license_id } = req.body;
  if (!license_id) return res.status(400).json({ error: 'Missing license_id' });
  const db = loadDB();
  if (!db.revoked.includes(license_id)) { db.revoked.push(license_id); saveDB(db); }
  console.log(`[SERVER] License revoked: ${license_id}`);
  return res.json({ success: true });
});

app.get('/activations', (req, res) => {
  if (req.headers['x-admin-secret'] !== SECRET)
    return res.status(401).json({ error: 'Unauthorized' });
  return res.json(loadDB());
});

app.listen(PORT, () => {
  console.log(`\n🔐 BillFlow Licensing Server running on :${PORT}`);
  console.log(`   POST /activate   — customer key activation`);
  console.log(`   POST /checkin    — 14-day phone-home`);
  console.log(`   POST /revoke     — revoke a license (admin)`);
  console.log(`   Public key:      ${PUB}`);
  console.log(`   DB file:         ${DB}\n`);
});
