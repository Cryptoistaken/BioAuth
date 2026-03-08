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

const identity = await biokey.enroll()
// → { publicKey, credentialId, enrolledAt }

const result = await biokey.authenticate(identity)
// → { verified: true, publicKey }
```

## How it works

1. `enroll()` triggers the device fingerprint scanner via WebAuthn
2. The credential's `rawId` is passed through HKDF-SHA256
3. A 256-bit identity seed is derived — this is your public key
4. Nothing biometric is stored anywhere

## Requirements

- HTTPS or localhost
- Chrome 100+ (Ed25519 support)
- Platform authenticator (device fingerprint sensor)

## License

MIT
