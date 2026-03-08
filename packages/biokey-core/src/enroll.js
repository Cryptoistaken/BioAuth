import { deriveKey, extractPRFOutput, bufToHex, PRF_SALT } from './derive.js'

// ─── PRF enrollment ───────────────────────────────────────────────────────────
// Passes the PRF extension with an eval salt during credential creation.
// If the platform supports PRF, the authenticator returns a 32-byte secret
// (results.first) that is deterministic and hardware-backed.
// Falls back to rawId-HKDF (V1) if PRF is unavailable.

export async function enroll(rpId, rpName = 'BioKey') {
	const challenge = crypto.getRandomValues(new Uint8Array(32))
	const userId = crypto.getRandomValues(new Uint8Array(16))

	const credential = await navigator.credentials.create({
		publicKey: {
			challenge,
			rp: { name: rpName, id: rpId },
			user: {
				id: userId,
				name: 'biokey-user',
				displayName: 'BioKey User'
			},
			pubKeyCredParams: [
				{ alg: -7, type: 'public-key' },
				{ alg: -8, type: 'public-key' },
				{ alg: -257, type: 'public-key' }
			],
			authenticatorSelection: {
				authenticatorAttachment: 'platform',
				userVerification: 'required',
				residentKey: 'preferred'
			},
			extensions: {
				prf: { eval: { first: PRF_SALT } }
			},
			timeout: 60000
		}
	})

	const prfOutput = extractPRFOutput(credential)
	let publicKey, method

	if (prfOutput) {
		// PRF path — hardware-backed secret output, never touches rawId as keying material
		publicKey = bufToHex(prfOutput)
		method = 'prf'
	} else {
		// V1 fallback — rawId-HKDF
		const seed = await deriveKey(credential.rawId)
		publicKey = bufToHex(seed)
		method = 'rawid'
	}

	const credentialId = bufToHex(credential.rawId)

	return { publicKey, credentialId, enrolledAt: Date.now(), method }
}
