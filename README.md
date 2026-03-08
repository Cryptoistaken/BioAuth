# BioKey

> Your fingerprint. Your identity. No middleman.

An open-source protocol and library that lets your fingerprint be your identity. No password. No device vendor lock-in. No biometric data stored on any server. Ever.

## Structure

```
B.O/
├── spec/                   Phase 4 — open protocol specification
│   └── BIOKEY-PROTOCOL.md
├── docs/                   Phase 3 — docs site (Vite, dark, Geist)
├── test-app/               Phase 0 — test surface (Vite, vanilla JS)
└── packages/
    ├── biokey-core/        Phase 1 — WebAuthn + HKDF primitives
    ├── biokey-server/      Phase 2 — Bun + Hono + SQLite auth server
    ├── biokey-js/          Phase 3 — browser SDK
    └── biokey-react/       Phase 3 — useBioKey() React hook
```

## Quick Start

### Test App (Phase 0)
```bash
cd test-app
bun install && bun run dev
```
Deploy for mobile testing:
```bash
bun run build && vercel deploy
```

### Auth Server (Phase 2)
```bash
cd packages/biokey-server
bun install && bun run dev
```
Endpoints: `GET /challenge` · `POST /enroll` · `POST /verify`

### Browser SDK (Phase 3)
```js
import { BioKeyClient } from 'biokey-js'

const biokey = new BioKeyClient({ serverUrl: 'https://...' })
const identity = await biokey.enroll('user-123')
const result = await biokey.authenticate('user-123')
```

### React Hook (Phase 3)
```jsx
import { useBioKey } from 'biokey-react'

const { isEnrolled, enroll, authenticate, identity, status } = useBioKey()
```

## Protocol

See [`spec/BIOKEY-PROTOCOL.md`](./spec/BIOKEY-PROTOCOL.md) for the full open protocol specification — key derivation standard, enrollment/authentication flows, server API, and identity format.

## How It Works

**V2 — PRF (preferred, hardware-backed secret)**
```
Fingerprint scan
  → WebAuthn PRF extension (salt: "biokey-prf-v2-salt")
    → 256-bit hardware secret (never leaves authenticator)
      → public key = your identity
```

**V1 — rawId + HKDF (fallback for platforms without PRF)**
```
Fingerprint scan
  → WebAuthn credential (rawId)
    → HKDF-SHA256 (salt: "biokey-v1-salt", info: "biokey-identity-seed")
      → 256-bit identity seed
        → public key = your identity
```

The library automatically attempts V2 (PRF) first and falls back to V1. No biometric data ever leaves the device. The server stores only public keys.

## Roadmap

- [x] Phase 0 — Test surface (tested on iQOO Z9 Turbo, Android Chrome)
- [x] Phase 1 — biokey-core library
- [x] Phase 2 — Auth server (Bun + Hono + SQLite, Railway-ready)
- [x] Phase 3 — biokey-js SDK + biokey-react hook + docs site
- [x] Phase 4 — Open protocol specification
- [x] Phase 5 — V2 key derivation via WebAuthn PRF extension (hardware-backed secret, rawId-HKDF fallback)

## License

MIT — packages
CC0 — protocol specification
