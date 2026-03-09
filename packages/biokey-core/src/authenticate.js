import { deriveKey, extractPRFOutput, hexToBuf, bufToHex, PRF_SALT } from './derive.js'

function bufToBase64url(buf) {
	const bytes = new Uint8Array(buf)
	let str = ''
	for (const b of bytes) str += String.fromCharCode(b)
	return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function authenticate(identity, rpId) {
	if (!identity?.credentialId) throw new Error('No enrolled identity provided.')

	const challenge = crypto.getRandomValues(new Uint8Array(32))

	const assertion = await navigator.credentials.get({
		publicKey: {
			challenge,
			rpId,
			allowCredentials: [{ id: hexToBuf(identity.credentialId), type: 'public-key' }],
			userVerification: 'required',
			extensions: { prf: { evalByCredential: { [identity.credentialId]: { first: PRF_SALT } } } },
			timeout: 60000
		}
	})

	if (!assertion) throw new Error('Authentication failed — no assertion returned.')

	const prfOutput = extractPRFOutput(assertion)

	if (prfOutput) {
		const derivedKey = bufToHex(prfOutput)
		if (identity.method === 'prf' && derivedKey !== identity.publicKey) {
			throw new Error('PRF key mismatch — identity verification failed.')
		}
		return {
			verified: true,
			publicKey: derivedKey,
			method: 'prf',
			// Raw assertion bytes — pass to server /verify for signature verification
			authenticatorData: bufToBase64url(assertion.response.authenticatorData),
			clientDataJSON: bufToBase64url(assertion.response.clientDataJSON),
			signature: bufToBase64url(assertion.response.signature)
		}
	}

	// V1 fallback
	const seed = await deriveKey(assertion.rawId)
	const derivedKey = bufToHex(seed)
	if (identity.method === 'rawid' && derivedKey !== identity.publicKey) {
		throw new Error('Key mismatch — identity verification failed.')
	}

	return {
		verified: true,
		publicKey: identity.publicKey,
		method: 'rawid',
		authenticatorData: bufToBase64url(assertion.response.authenticatorData),
		clientDataJSON: bufToBase64url(assertion.response.clientDataJSON),
		signature: bufToBase64url(assertion.response.signature)
	}
}
