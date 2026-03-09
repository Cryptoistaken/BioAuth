// ─── webauthn.js ──────────────────────────────────────────────────────────────
// Server-side WebAuthn assertion verification.
//
// Handles:
//   extractCredentialPublicKey(attestationObject) → hex string
//   verifyAssertionSignature(credentialPublicKeyHex, authData, clientDataJSON, signature) → bool
//
// Supports ES256 (-7) and RS256 (-257) credential algorithms.
// No external dependencies — uses Bun's built-in crypto (Web Crypto API).

// ─── CBOR minimal decoder ─────────────────────────────────────────────────────
// Only handles the subset of CBOR used in WebAuthn attestation objects and
// COSE keys. Not a general-purpose CBOR implementation.

function cborDecode(buf, offset = 0) {
	const b = buf[offset]
	const major = b >> 5
	const info = b & 0x1f
	offset++

	function readLen(info, offset) {
		if (info < 24) return { len: info, offset }
		if (info === 24) return { len: buf[offset], offset: offset + 1 }
		if (info === 25) return { len: (buf[offset] << 8) | buf[offset + 1], offset: offset + 2 }
		if (info === 26) return { len: (buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3], offset: offset + 4 }
		throw new Error(`CBOR: unsupported length info ${info}`)
	}

	if (major === 0) { // unsigned int
		const r = readLen(info, offset)
		return { value: r.len, offset: r.offset }
	}

	if (major === 1) { // negative int
		const r = readLen(info, offset)
		return { value: -1 - r.len, offset: r.offset }
	}

	if (major === 2) { // byte string
		const r = readLen(info, offset)
		return { value: buf.slice(r.offset, r.offset + r.len), offset: r.offset + r.len }
	}

	if (major === 3) { // text string
		const r = readLen(info, offset)
		const text = Buffer.from(buf.slice(r.offset, r.offset + r.len)).toString('utf8')
		return { value: text, offset: r.offset + r.len }
	}

	if (major === 4) { // array
		const r = readLen(info, offset)
		const arr = []
		offset = r.offset
		for (let i = 0; i < r.len; i++) {
			const item = cborDecode(buf, offset)
			arr.push(item.value)
			offset = item.offset
		}
		return { value: arr, offset }
	}

	if (major === 5) { // map
		const r = readLen(info, offset)
		const map = {}
		offset = r.offset
		for (let i = 0; i < r.len; i++) {
			const k = cborDecode(buf, offset)
			offset = k.offset
			const v = cborDecode(buf, offset)
			offset = v.offset
			map[k.value] = v.value
		}
		return { value: map, offset }
	}

	throw new Error(`CBOR: unsupported major type ${major}`)
}

// ─── Extract credential public key from attestationObject ─────────────────────
// attestationObject is CBOR-encoded: { fmt, attStmt, authData }
// authData layout:
//   [0..32]   rpIdHash (32 bytes)
//   [32]      flags (1 byte)
//   [33..36]  signCount (4 bytes)
//   [37..52]  aaguid (16 bytes) — only if AT flag set
//   [53..54]  credIdLen (2 bytes)
//   [55..]    credId (credIdLen bytes)
//   [...]     credentialPublicKey (COSE CBOR)
// Returns hex string of the raw COSE public key bytes.

export function extractCredentialPublicKey(attObjBuf) {
	const decoded = cborDecode(attObjBuf)
	const authData = Buffer.from(decoded.value.authData)

	// flags byte: bit 6 (0x40) = AT (attested credential data included)
	const flags = authData[32]
	if (!(flags & 0x40)) throw new Error('AT flag not set — no credential data in authData')

	// skip rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) = 53 bytes
	// then credIdLen (2 bytes)
	const credIdLen = (authData[53] << 8) | authData[54]
	const credPubKeyOffset = 55 + credIdLen

	// The rest is the COSE-encoded credential public key
	const coseKeyBytes = authData.slice(credPubKeyOffset)
	return Buffer.from(coseKeyBytes).toString('hex')
}

// ─── Verify assertion signature ───────────────────────────────────────────────
// WebAuthn assertion signature covers: authData || SHA-256(clientDataJSON)
// The signature algorithm is determined by the COSE key type stored at enrollment.
//
// COSE key map keys used here:
//   1  = kty  (2 = EC2, 3 = RSA)
//   3  = alg  (-7 = ES256, -257 = RS256)
//  -1  = crv or n  (EC curve or RSA modulus)
//  -2  = x   (EC x coordinate)
//  -3  = y   (EC y coordinate)
//  -2  = e   (RSA public exponent, same key as EC x — differentiated by kty)

export async function verifyAssertionSignature(credentialPublicKeyHex, authDataBuf, clientDataJSONBuf, sigBuf) {
	const coseKeyBuf = Buffer.from(credentialPublicKeyHex, 'hex')
	const coseKey = cborDecode(coseKeyBuf).value

	const kty = coseKey[1]
	const alg = coseKey[3]

	// Hash clientDataJSON
	const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataJSONBuf)

	// Build the signed data: authData || hash(clientDataJSON)
	const signedData = Buffer.concat([authDataBuf, Buffer.from(clientDataHash)])

	if (kty === 2 && alg === -7) {
		// EC2 / ES256
		const x = coseKey[-2]
		const y = coseKey[-3]

		const jwk = {
			kty: 'EC',
			crv: 'P-256',
			x: Buffer.from(x).toString('base64url'),
			y: Buffer.from(y).toString('base64url'),
		}

		const key = await crypto.subtle.importKey(
			'jwk', jwk,
			{ name: 'ECDSA', namedCurve: 'P-256' },
			false, ['verify']
		)

		return crypto.subtle.verify(
			{ name: 'ECDSA', hash: 'SHA-256' },
			key,
			sigBuf,
			signedData
		)
	}

	if (kty === 3 && alg === -257) {
		// RSA / RS256
		const n = coseKey[-1]
		const e = coseKey[-2]

		const jwk = {
			kty: 'RSA',
			alg: 'RS256',
			n: Buffer.from(n).toString('base64url'),
			e: Buffer.from(e).toString('base64url'),
		}

		const key = await crypto.subtle.importKey(
			'jwk', jwk,
			{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
			false, ['verify']
		)

		return crypto.subtle.verify(
			{ name: 'RSASSA-PKCS1-v1_5' },
			key,
			sigBuf,
			signedData
		)
	}

	throw new Error(`Unsupported COSE key type: kty=${kty}, alg=${alg}`)
}
