# biokey-server

Auth server for the BioKey protocol. Bun + Hono + SQLite. Handles challenge issuance, enrollment, and full WebAuthn assertion signature verification. Railway-ready.

## Stack

- **Runtime:** Bun
- **Framework:** Hono
- **Database:** SQLite (`bun:sqlite`)
- **Deploy:** Railway (or any host with Bun support)

## Run locally

```bash
cd packages/biokey-server
bun install
bun run dev        # watch mode
bun run start      # production
```

Server starts on port `3000` by default. Set `PORT` env variable to override.

## Deploy to Railway

```bash
railway init
railway up
```

Railway auto-detects Bun. The `railway.json` config is included.

## API

All endpoints accept and return `application/json`.

---

### `GET /challenge/:userId`

Issue a fresh authentication challenge for a userId.

- Challenges are 32 bytes, cryptographically random, hex-encoded (64 chars)
- Single-use — consumed and deleted on first `/verify` call
- Expire after **5 minutes**
- Max **3 outstanding challenges** per userId at once (flood protection)

**Response (200):**
```json
{ "challenge": "a3f1c29e847d0b5f..." }
```

**Response (429):** Too many pending challenges for this userId.

---

### `POST /enroll`

Register a new identity. Extracts and stores the authenticator's credential public key from the `attestationObject` for future assertion signature verification.

**Request body:**
```json
{
  "userId":            "a3f1c29e847d0b5f...",
  "publicKey":         "64-char hex",
  "deviceId":          "16-char hex",
  "method":            "prf" | "rawid",
  "attestationObject": "base64url",
  "clientDataJSON":    "base64url"
}
```

**userId requirements:**
- Lowercase hex string
- Minimum 32 characters (128-bit entropy)
- Rejects anything shorter or non-hex

**Response (200):**
```json
{ "ok": true, "userId": "...", "publicKey": "...", "method": "prf" }
```

**Response (400):** Missing fields, invalid `publicKey` format, invalid `userId`, bad `clientDataJSON`, or failed attestation parsing.

---

### `POST /verify`

Verify an authentication attempt. Runs three checks in sequence:

1. **Per-userId lockout** — rejects if userId is locked after repeated failures
2. **Challenge validation** — challenge must have been issued by this server, unused, and within 5 minutes
3. **clientDataJSON binding** — verifies `type: webauthn.get` and challenge match
4. **Assertion signature verification** — cryptographically verifies the signature over `authData || SHA-256(clientDataJSON)` using the stored credential public key

**Request body:**
```json
{
  "userId":            "a3f1c29e847d0b5f...",
  "challenge":         "64-char hex",
  "authenticatorData": "base64url",
  "clientDataJSON":    "base64url",
  "signature":         "base64url"
}
```

**Response (200):**
```json
{
  "verified":  true,
  "publicKey": "64-char hex",
  "userId":    "...",
  "method":    "prf" | "rawid"
}
```

**Response (401):** Authentication failed. All failure reasons return the same generic message to prevent enumeration.

**Response (429):** userId is temporarily locked (15 minutes) after 5 consecutive failures.

---

## Brute force protection

Protection is userId-based — no IP tracking.

| Layer | Mechanism | Limit |
|---|---|---|
| Challenge flood | Max outstanding challenges per userId | 3 |
| Verify failures | Consecutive failure counter per userId | 5 failures → 15 min lockout |
| Lockout persistence | SQLite `lockouts` table | Survives server restarts |
| Error responses | Generic `Authentication failed` for all 401s | Prevents userId enumeration |

## Database

SQLite file at `biokey.db` (created automatically on first run). Three tables:

| Table | Purpose |
|---|---|
| `identities` | userId, derived public key, credential public key (COSE hex), deviceId, method |
| `challenges` | Pending challenges with userId and TTL |
| `lockouts` | Per-userId failure counts and lockout expiry |

## Signature verification

The server performs full WebAuthn Level 1 assertion verification using a zero-dependency CBOR decoder and the Web Crypto API (built into Bun):

- Parses COSE key from stored `credential_public_key`
- Reconstructs signed data: `authData || SHA-256(clientDataJSON)`
- Verifies ECDSA P-256 (ES256) or RSA PKCS#1 v1.5 (RS256) signature

Supported credential algorithms: **ES256** (`-7`) and **RS256** (`-257`).

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP port |

## License

MIT
