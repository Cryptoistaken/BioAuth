# biokey-js

Browser SDK for the BioKey protocol. Drop-in WebAuthn fingerprint identity — wraps enrollment, authentication, key derivation, and optional server sync.

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
// → { publicKey, credentialId, deviceId, enrolledAt }

const result = await biokey.authenticate()
// → { verified: true, publicKey }
```

### With server

```js
const biokey = new BioKeyClient({
	serverUrl: 'https://your-biokey-server.railway.app'
})

await biokey.enroll('user-123')
await biokey.authenticate('user-123')
```

## API

### `new BioKeyClient(options?)`

| Option | Type | Default | Description |
|---|---|---|---|
| `rpId` | string | `location.hostname` | Relying party ID (must match domain) |
| `rpName` | string | `'BioKey'` | Display name shown during enrollment |
| `serverUrl` | string | `null` | biokey-server URL for cross-device identity |

### `enroll(userId?)` → `Promise<Identity>`

Triggers fingerprint scanner, derives identity key, stores locally.

### `authenticate(userId?)` → `Promise<{ verified, publicKey }>`

Triggers fingerprint scanner, verifies locally. If `serverUrl` + `userId` provided, verifies with server.

### `getIdentity()` → `Identity | null`

Returns stored identity from localStorage.

### `clearIdentity()`

Removes stored identity.

## Requirements

- HTTPS or localhost
- Chrome 100+ / Safari 16+ / Firefox 119+
- Device with platform authenticator (fingerprint, Face ID, Windows Hello)
