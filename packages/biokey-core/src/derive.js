export function bufToHex(buf) {
	return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('')
}

export function hexToBuf(hex) {
	return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16))).buffer
}

// ─── V1 fallback: rawId → HKDF ───────────────────────────────────────────────
// NOTE: rawId is a credential identifier, not a secret. This path is a
// best-effort approach for environments that do not support the PRF extension.
// Use deriveKeyPRF() wherever possible.

export async function deriveKey(rawId) {
	const keyMaterial = await crypto.subtle.importKey(
		'raw',
		rawId,
		{ name: 'HKDF' },
		false,
		['deriveBits']
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

// ─── V2: WebAuthn PRF extension → identity key ────────────────────────────────
// The PRF extension lets the platform authenticator produce a deterministic
// 32-byte output that is hardware-backed and secret — the rawId never needs
// to serve as keying material.
//
// evalByCredential requires the credential to already exist; use the simpler
// eval form during enrollment (create), evalByCredential during authentication
// (get). Both are handled by the callers in enroll.js / authenticate.js.

export const PRF_SALT = new TextEncoder().encode('biokey-prf-v2-salt')

export function isPRFSupported(credential) {
	return !!(
		credential?.getClientExtensionResults?.()?.prf?.enabled ||
		credential?.getClientExtensionResults?.()?.prf?.results?.first
	)
}

export function extractPRFOutput(credential) {
	const first = credential?.getClientExtensionResults?.()?.prf?.results?.first
	if (!first) return null
	return new Uint8Array(first)
}
