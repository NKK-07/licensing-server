# InvoiceMaker — Licensing Server

Handles license activation, periodic check-in, and revocation.

## Deploy to Railway (Free)

1. Push this folder to a GitHub repo
2. Go to railway.app → New Project → Deploy from GitHub
3. Set environment variable: `ACTIVATION_SECRET=your-random-64-char-string`
4. Copy the provided URL (e.g. `https://your-app.railway.app`)
5. Set this URL in `desktop/src-tauri/src/licensing.rs` as `LICENSING_SERVER_URL`

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ACTIVATION_SECRET` | YES | Random secret for HMAC tokens and admin endpoints |
| `PORT` | No | Defaults to 4000 |

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Health check |
| POST | `/activate` | License key | Activate a new machine |
| POST | `/checkin` | Activation token | 14-day refresh / revocation check |
| POST | `/revoke` | x-admin-secret header | Revoke a license |
| GET | `/activations` | x-admin-secret header | View all activations |

## Local Testing

```bash
npm install
npm run dev
# Server on http://localhost:4000

# Test activation
curl -X POST http://localhost:4000/activate \
  -H "Content-Type: application/json" \
  -d '{"license_key":"YOUR_KEY","fingerprint_hash":"abc123"}'

# Revoke a license (replace secret and ID)
curl -X POST http://localhost:4000/revoke \
  -H "Content-Type: application/json" \
  -H "x-admin-secret: CHANGE_THIS_IN_PRODUCTION_PLEASE" \
  -d '{"license_id":"the-uuid-here"}'
```
