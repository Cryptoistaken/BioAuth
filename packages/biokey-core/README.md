# biokey-core

Core library for the BioKey protocol. Fingerprint-derived cryptographic identity — no passwords, no vendor lock-in, no biometric data on any server.

## Install

```bash
bun add biokey-core
```

## Usage

```js
import { BioKey } from 'biokey-core'

const biokey = new BioKey()

// Enroll — triggers fingerprint scanner, derives identity key
const identity = await biokey.enroll()
// → {
//     publicKey:         string   // 64-char hex identity key
//     credentialId:      string   // hex WebAuthn credential ID
//     enrolledAt:        number   // Unix timestamp (ms)
//     method:            'prf' | 'rawid'
//     attestationObject: string   // base64url — pass to server /enroll
//     clientDataJSON:    string   // base64url — pass to server /enroll
//   }

// Authenticate — re-derives key and verifies it matches enrolled identity
const result = await biokey.authenticate(identity)
// → {
//     verified:          true
//     publicKey:         string
//     method:            'prf' | 'rawid'
//     authenticatorData: string   // base64url — pass to server /verify
//     clientDataJSON:    string   // base64url — pass to server /verify
//     signature:         string   // base64url — pass to server /verify
//   }
```

## How it works

**V2 — PRF (preferred, hardware-backed secret)**
```
Fingerprint scan
  → WebAuthn PRF extension (salt: "biokey-prf-v2-salt")
    → 256-bit hardware secret (never leaves authenticator)
      → publicKey = your identity
```

**V1 — rawId + HKDF (fallback for platforms without PRF)**
```
Fingerprint scan
  → WebAuthn credential (rawId)
    → HKDF-SHA256 (salt: "biokey-v1-salt", info: "biokey-identity-seed")
      → 256-bit identity seed
        → publicKey = your identity
```

The library automatically attempts V2 (PRF) first and falls back to V1. The `method` field in the return value tells you which path was used.

## Key derivation methods

| Method | `method` value | Security | Platform support |
|---|---|---|---|
| WebAuthn PRF extension | `'prf'` | Hardware-backed secret | Android Chrome, Safari 18+, Edge |
| rawId + HKDF-SHA256 | `'rawid'` | Credential ID as IKM | All WebAuthn platforms |

## API

### `new BioKey(options?)`

| Option | Type | Default | Description |
|---|---|---|---|
| `rpId` | string | `location.hostname` | Relying party ID — must match the page's hostname |
| `rpName` | string | `'BioKey'` | Display name shown to the user during enrollment |

### `enroll()` → `Promise<EnrollResult>`

Triggers the platform authenticator (fingerprint scanner). Attempts PRF key derivation first, falls back to rawId-HKDF. Returns the identity object plus raw attestation bytes for server enrollment.

### `authenticate(identity)` → `Promise<AuthResult>`

Re-derives the identity key using the same method as enrollment and asserts it matches the stored `publicKey`. Returns raw assertion bytes for server verification.

## Requirements

- HTTPS or localhost
- Chrome 100+ / Safari 18+ / Firefox 119+
- Platform authenticator (fingerprint sensor, Face ID, Windows Hello)

## License

MIT
