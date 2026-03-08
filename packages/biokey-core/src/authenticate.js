import { deriveKey, extractPRFOutput, hexToBuf, bufToHex, PRF_SALT } from './derive.js'

// ─── PRF authentication ───────────────────────────────────────────────────────
// During get(), the PRF extension uses evalByCredential to re-derive the same
// secret that was produced at enrollment — no storage of the secret is needed.
// If the platform does not support PRF, we fall back to V1 (rawId-HKDF) and
// verify the re-derived key matches the stored publicKey.

export async function authenticate(identity, rpId) {
	if (!identity?.credentialId) throw new Error('No enrolled identity provided.')

	const challenge = crypto.getRandomValues(new Uint8Array(32))
	const credId = hexToBuf(identity.credentialId)

	const assertion = await navigator.credentials.get({
		publicKey: {
			challenge,
			rpId,
			allowCredentials: [{ id: credId, type: 'public-key' }],
			userVerification: 'required',
			extensions: {
				prf: {
					evalByCredential: {
						[identity.credentialId]: { first: PRF_SALT }
					}
				}
			},
			timeout: 60000
		}
	})

	if (!assertion) throw new Error('Authentication failed — no assertion returned.')

	const prfOutput = extractPRFOutput(assertion)

	if (prfOutput) {
		// PRF path — re-derive and verify against stored publicKey
		const derivedKey = bufToHex(prfOutput)
		if (identity.method === 'prf' && derivedKey !== identity.publicKey) {
			throw new Error('PRF key mismatch — identity verification failed.')
		}
		return { verified: true, publicKey: derivedKey, method: 'prf' }
	}

	// V1 fallback — rawId-HKDF re-derivation
	// The assertion rawId should match the enrolled credentialId, so re-derive
	// and compare as a best-effort integrity check.
	const seed = await deriveKey(assertion.rawId)
	const derivedKey = bufToHex(seed)

	if (identity.method === 'rawid' && derivedKey !== identity.publicKey) {
		throw new Error('Key mismatch — identity verification failed.')
	}

	return { verified: true, publicKey: identity.publicKey, method: 'rawid' }
}
