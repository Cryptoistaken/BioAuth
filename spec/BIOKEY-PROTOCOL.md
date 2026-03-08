# BioKey Protocol Specification
**Version:** 0.2.0 (Draft)
**Status:** Work in Progress
**License:** CC0 1.0 Universal (Public Domain)

---

## Abstract

BioKey is an open protocol for deriving a stable cryptographic identity from a biometric signal captured via a platform authenticator. It enables passwordless authentication without storing biometric data on any server, and without delegating identity custody to a device vendor (Apple, Google, Microsoft, etc.).

This document defines the enrollment handshake, key derivation standard, authentication flow, and challenge/response format. Any implementation that conforms to this specification is BioKey-compatible.

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Terminology](#2-terminology)
3. [Security Model](#3-security-model)
4. [Key Derivation Standard](#4-key-derivation-standard)
5. [Enrollment Flow](#5-enrollment-flow)
6. [Authentication Flow](#6-authentication-flow)
7. [Challenge Format](#7-challenge-format)
8. [Server API](#8-server-api)
9. [Identity Format](#9-identity-format)
10. [Known Limitations](#10-known-limitations)
11. [Versioning](#11-versioning)

---

## 1. Motivation

Existing authentication systems fail in one or more of the following ways:

- **Passwords** are weak, reused, and constantly breached.
- **Passkeys (WebAuthn/FIDO2)** improve UX but store keys in vendor clouds (iCloud Keychain, Google Password Manager). The user does not own their identity — the vendor does.
- **On-device biometrics** unlock a device-local key. The identity is bound to the device. Replacing or losing the device requires re-enrollment through a vendor-controlled flow.

BioKey solves this by deriving the cryptographic identity *from the biometric authentication event itself*, deterministically, on the client. The server stores only a public key. No biometric data ever leaves the device.

---

## 2. Terminology

| Term | Definition |
|---|---|
| **Identity Key** | A 256-bit value derived from the enrollment credential. Serves as the user's public identity. |
| **Credential** | A WebAuthn `PublicKeyCredential` returned by `navigator.credentials.create()` or `.get()`. |
| **rawId** | The raw byte identifier of a WebAuthn credential. Used as V1 HKDF keying material. |
| **PRF** | WebAuthn pseudo-random function extension (defined in WebAuthn Level 3). Produces a hardware-backed deterministic secret output per credential. |
| **rpId** | Relying Party ID. Must match the hostname of the origin. |
| **Challenge** | A 32-byte random nonce issued by the server. Used once. Expires after 5 minutes. |
| **Enrollment** | The process of registering a biometric and deriving an Identity Key. |
| **Authentication** | The process of proving possession of the enrolled biometric to obtain a verified session. |
| **Platform Authenticator** | A biometric sensor built into the device (fingerprint, Face ID, Windows Hello). |
| **method** | Either `prf` (V2, preferred) or `rawid` (V1, fallback). Recorded at enrollment and stored with the identity. |

---

## 3. Security Model

### What BioKey protects against

- Credential theft via server breach (server holds only public keys)
- Vendor lock-in (no iCloud/Google dependency)
- Replay attacks (challenges are single-use, time-limited)
- Cross-origin abuse (rpId is bound to the domain)

### What BioKey does NOT protect against

- Compromised device (if the device is owned, the platform authenticator is owned)
- PIN fallback (WebAuthn permits PIN as authenticator fallback; the OS controls this)
- Cross-sensor attacks (V1/V2 — same identity across different hardware sensors is not guaranteed)
- Biometric compromise (fingerprints are irrevocable; liveness detection is recommended)

### Trust boundaries

```
┌─────────────────────────────────────────┐
│  TRUSTED (on device)                   │
│  - Platform authenticator              │
│  - WebAuthn API + PRF extension        │
│  - HKDF derivation (V1 fallback only)  │
│  - Identity Key storage (localStorage) │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│  UNTRUSTED (server-side)               │
│  - Only public keys stored             │
│  - Challenge issuance and verification │
│  - No biometric data, ever             │
└─────────────────────────────────────────┘
```

---

## 4. Key Derivation Standard

BioKey v0.2 defines two derivation paths. Implementations MUST attempt V2 first and fall back to V1 if the platform does not support the PRF extension.

### V2 — WebAuthn PRF Extension (Preferred)

The WebAuthn PRF extension (defined in WebAuthn Level 3) allows a platform authenticator to produce a deterministic, hardware-backed symmetric key tied to a passkey. The output is secret and never exposed outside the authenticator.

#### Enrollment (`navigator.credentials.create`)

Pass the PRF extension with a fixed salt in the `eval` field:

```js
extensions: {
  prf: { eval: { first: PRF_SALT } }
}
```

If the authenticator supports PRF, `credential.getClientExtensionResults().prf.results.first` contains a 32-byte `ArrayBuffer`. This is the Identity Key.

#### Authentication (`navigator.credentials.get`)

Pass the PRF extension via `evalByCredential`, keyed by the stored `credentialId`:

```js
extensions: {
  prf: {
    evalByCredential: {
      [credentialId]: { first: PRF_SALT }
    }
  }
}
```

The authenticator re-derives the same 32-byte secret. The client MUST compare it against the stored `publicKey` and reject if they differ.

#### PRF Salt

| Parameter | Value |
|---|---|
| `PRF_SALT` | UTF-8 encoding of `"biokey-prf-v2-salt"` |

The salt is version-locked. Changing it produces a different Identity Key.

---

### V1 — rawId + HKDF (Fallback)

> **Security note:** `rawId` is a credential *identifier*, not a secret value. It may be observed by the server during enrollment and authentication. The V1 derivation path provides a stable identity seed for environments without PRF support, but it does not carry the same security guarantees as V2. Prefer V2 wherever available.

#### Algorithm

HKDF as defined in [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869), using SHA-256.

#### Parameters

| Parameter | Value |
|---|---|
| Hash | SHA-256 |
| IKM (Input Keying Material) | `credential.rawId` bytes |
| Salt | UTF-8 encoding of `"biokey-v1-salt"` |
| Info | UTF-8 encoding of `"biokey-identity-seed"` |
| L (Output Length) | 32 bytes (256 bits) |

#### Output

A 32-byte (256-bit) value, hex-encoded as a 64-character lowercase string.

#### Reference implementation

```js
async function deriveKey(rawId) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', rawId, { name: 'HKDF' }, false, ['deriveBits']
  )
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('biokey-v1-salt'),
      info: new TextEncoder().encode('biokey-identity-seed')
    },
    keyMaterial,
    256
  )
  return new Uint8Array(bits)
}
```

---

## 5. Enrollment Flow

```
Client                                    Server
  |                                          |
  |-- navigator.credentials.create() -----> |  (platform authenticator + PRF attempted)
  |<-- PublicKeyCredential -----------------|
  |                                          |
  |  IF prf.results.first present:           |
  |    publicKey = hex(prf.results.first)    |
  |    method = 'prf'                        |
  |  ELSE:                                   |
  |    publicKey = hex(HKDF(rawId))          |
  |    method = 'rawid'                      |
  |                                          |
  |-- POST /enroll ------------------------->|
  |   { userId, publicKey, deviceId, method }|
  |<-- { ok: true, userId, publicKey, method}|
```

### Steps

1. Client generates a random 32-byte challenge and 16-byte userId.
2. Client calls `navigator.credentials.create()` with:
   - `authenticatorAttachment: 'platform'`
   - `userVerification: 'required'`
   - `rp.id` set to the current hostname
   - `extensions.prf.eval.first` set to `PRF_SALT`
3. Platform authenticator is triggered. User provides biometric.
4. If `prf.results.first` is present: Identity Key = `hex(prf.results.first)`, `method = 'prf'`.
5. Otherwise: Identity Key = `hex(HKDF(rawId))`, `method = 'rawid'`.
6. Client stores `{ credentialId, publicKey, deviceId, enrolledAt, method }` locally.
7. If a server is present: client sends `POST /enroll` (see §8).

---

## 6. Authentication Flow

```
Client                                    Server
  |                                          |
  |-- GET /challenge ------------------------>|
  |<-- { challenge: hex(32 bytes) } ---------|
  |                                          |
  |-- navigator.credentials.get() ---------> |  (PRF evalByCredential attempted)
  |<-- PublicKeyCredential -----------------|
  |                                          |
  |  IF prf.results.first present:           |
  |    derivedKey = hex(prf.results.first)   |
  |    assert derivedKey === stored.publicKey |
  |  ELSE:                                   |
  |    derivedKey = hex(HKDF(assertion.rawId))|
  |    assert derivedKey === stored.publicKey |
  |                                          |
  |-- POST /verify -------------------------->|
  |   { userId, challenge }                  |
  |<-- { verified: true, publicKey, method } |
```

### Steps

1. Client fetches a fresh challenge from `GET /challenge`.
2. Client calls `navigator.credentials.get()` with stored `credentialId` and `extensions.prf.evalByCredential`.
3. Platform authenticator is triggered. User provides biometric.
4. Client re-derives Identity Key (PRF or rawId-HKDF) and compares against stored `publicKey`. Rejects on mismatch.
5. Client sends `POST /verify` with `userId` and challenge hex.
6. Server validates challenge (single-use, 5-minute TTL) and returns `{ verified: true, publicKey, method }`.

### Offline / local-only authentication

If no server is configured, the client may authenticate locally by verifying the re-derived key matches the stored `publicKey`. No challenge verification is performed. Suitable for local device unlock only.

---

## 7. Challenge Format

### Issuance

- 32 bytes, cryptographically random
- Hex-encoded (64 lowercase hex characters)
- Stored server-side with creation timestamp
- Expires: 5 minutes from issuance
- Single-use: deleted on first verification attempt

### Request / Response

```
GET /challenge
→ { "challenge": "a3f1c29e...d4" }
```

---

## 8. Server API

All endpoints accept and return `application/json`.

### POST /enroll

Register a new identity.

**Request body:**
```json
{
  "userId": "string",
  "publicKey": "64-char hex string",
  "deviceId": "16-char hex string",
  "method": "prf" | "rawid"
}
```

**Response (200):**
```json
{
  "ok": true,
  "userId": "string",
  "publicKey": "64-char hex string",
  "method": "prf" | "rawid"
}
```

---

### GET /challenge

**Response (200):**
```json
{ "challenge": "64-char hex string" }
```

---

### POST /verify

**Request body:**
```json
{
  "userId": "string",
  "challenge": "64-char hex string"
}
```

**Response (200):**
```json
{
  "verified": true,
  "publicKey": "64-char hex string",
  "userId": "string",
  "method": "prf" | "rawid"
}
```

**Response (401):** Invalid or expired challenge.
**Response (404):** Unknown userId.

---

## 9. Identity Format

```ts
{
  publicKey:    string   // 64-char hex — derived Identity Key
  credentialId: string   // hex-encoded WebAuthn credential rawId
  deviceId:     string   // 16-char hex — deterministic device fingerprint
  enrolledAt:   number   // Unix timestamp (ms)
  method:       'prf' | 'rawid'  // derivation method used at enrollment
}
```

---

## 10. Known Limitations

### Cross-sensor variance
Different hardware sensors produce different `rawId` values and PRF outputs for the same finger. Each device enrollment produces a distinct Identity Key. The server may link multiple public keys to one user account.

### PIN fallback
WebAuthn permits the device PIN as a fallback authenticator. BioKey cannot enforce biometric-only via the WebAuthn API alone.

**V3 goal:** Native Android app using `BiometricPrompt` with `BIOMETRIC_STRONG` to block PIN fallback.

### PRF platform support (as of 2025)
PRF is well-supported on Android (Chrome). macOS and iOS support is available in Safari 18+ but remains inconsistent. The V1 rawId-HKDF fallback ensures BioKey works across all platforms while PRF coverage matures.

### Irrevocable biometric
A fingerprint cannot be changed if compromised. Implementations should consider multi-finger enrollment, liveness detection, and server-side revocation via public key deletion.

---

## 11. Versioning

| Version | Derivation | Salt / Info | Status |
|---|---|---|---|
| v0 | rawId → HKDF | `biokey-v0-salt` / `biokey-identity-key` | Deprecated |
| v1 | rawId → HKDF | `biokey-v1-salt` / `biokey-identity-seed` | Fallback only |
| v2 | PRF extension | `biokey-prf-v2-salt` | Current (preferred) |

---

## Authors

BioKey Protocol — open standard, not owned by any company.
Originated by Md Ratul Islam, 2025.

---

*This specification is released into the public domain under CC0 1.0.*
*No permission required to implement, fork, or build upon it.*
