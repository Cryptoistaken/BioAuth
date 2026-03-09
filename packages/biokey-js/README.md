# biokey-js

Browser SDK for the BioKey protocol. Drop-in WebAuthn fingerprint identity — enrollment, authentication, PRF key derivation, and full server-side assertion verification.

## Install

```bash
bun add biokey-js
```

## Usage

### Standalone (no server)

```js
import { BioKeyClient } from 'biokey-js'

const biokey = new BioKeyClient()

const identity = await biokey.enroll()
// → { publicKey, credentialId, deviceId, enrolledAt, method }

const result = await biokey.authenticate()
// → { verified: true, publicKey, method }
```

### With server (full verification)

```js
const biokey = new BioKeyClient({
	serverUrl: 'https://your-biokey-server.railway.app'
})

// userId must be a hex string of at least 32 characters (128-bit entropy)
// Generate it once and store it: crypto.randomUUID().replace(/-/g, '')
const userId = 'a3f1c29e847d0b5f6a2e91c47d3b8f0e'

await biokey.enroll(userId)
// Sends attestationObject + clientDataJSON to /enroll
// Server extracts and stores the authenticator's credential public key

await biokey.authenticate(userId)
// Sends authenticatorData + clientDataJSON + signature to /verify
// Server cryptographically verifies the assertion signature
```

## API

### `new BioKeyClient(options?)`

| Option | Type | Default | Description |
|---|---|---|---|
| `rpId` | string | `location.hostname` | Relying party ID — must match the page's hostname |
| `rpName` | string | `'BioKey'` | Display name shown during enrollment |
| `serverUrl` | string | `null` | biokey-server base URL for server-side verification |

### `enroll(userId?)` → `Promise<Identity>`

Triggers the platform authenticator. Attempts PRF key derivation, falls back to rawId-HKDF. Stores identity in `localStorage`. If `serverUrl` + `userId` provided, sends `attestationObject` and `clientDataJSON` to `POST /enroll` so the server can store the credential public key for future assertion verification.

**userId requirements (when using a server):**
- Must be a hex string of at least 32 characters (128-bit minimum entropy)
- Must be lowercase hex: `/^[0-9a-f]{32,}$/`
- Generate once: `crypto.randomUUID().replace(/-/g, '')`

Returns:
```ts
{
  publicKey:    string   // 64-char hex identity key
  credentialId: string   // hex WebAuthn credential ID
  deviceId:     string   // 16-char hex device fingerprint
  enrolledAt:   number   // Unix timestamp (ms)
  method:       'prf' | 'rawid'
}
```

### `authenticate(userId?)` → `Promise<AuthResult>`

Triggers the platform authenticator. Re-derives the identity key and asserts it matches the locally stored `publicKey`. If `serverUrl` + `userId` provided, fetches a challenge from `GET /challenge/:userId` then sends `authenticatorData`, `clientDataJSON`, and `signature` to `POST /verify` for full cryptographic assertion verification.

Returns:
```ts
{
  verified:  true
  publicKey: string
  method:    'prf' | 'rawid'
}
```

### `getIdentity()` → `Identity | null`

Returns the stored identity from `localStorage`, or `null` if not enrolled.

### `clearIdentity()`

Removes the stored identity from `localStorage`.

## Security model

When used with a server, authentication passes two independent checks:

1. **Client-side** — the re-derived key must match the stored `publicKey`
2. **Server-side** — the WebAuthn assertion signature is verified against the credential public key stored at enrollment

Both must pass. A forged or replayed request fails at the server's signature check.

## Requirements

- HTTPS or localhost
- Chrome 100+ / Safari 18+ / Firefox 119+
- Platform authenticator (fingerprint sensor, Face ID, Windows Hello)

## License

MIT
