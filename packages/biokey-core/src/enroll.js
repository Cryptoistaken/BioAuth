import { deriveKey, extractPRFOutput, bufToHex, PRF_SALT } from './derive.js'

function bufToBase64url(buf) {
	const bytes = new Uint8Array(buf)
	let str = ''
	for (const b of bytes) str += String.fromCharCode(b)
	return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function enroll(rpId, rpName = 'BioKey') {
	const challenge = crypto.getRandomValues(new Uint8Array(32))
	const userId = crypto.getRandomValues(new Uint8Array(16))

	const credential = await navigator.credentials.create({
		publicKey: {
			challenge,
			rp: { name: rpName, id: rpId },
			user: { id: userId, name: 'biokey-user', displayName: 'BioKey User' },
			pubKeyCredParams: [
				{ alg: -7, type: 'public-key' },
				{ alg: -8, type: 'public-key' },
				{ alg: -257, type: 'public-key' }
			],
			authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
			extensions: { prf: { eval: { first: PRF_SALT } } },
			timeout: 60000
		}
	})

	const prfOutput = extractPRFOutput(credential)
	let publicKey, method

	if (prfOutput) {
		publicKey = bufToHex(prfOutput)
		method = 'prf'
	} else {
		const seed = await deriveKey(credential.rawId)
		publicKey = bufToHex(seed)
		method = 'rawid'
	}

	return {
		publicKey,
		credentialId: bufToHex(credential.rawId),
		enrolledAt: Date.now(),
		method,
		// Raw attestation bytes — pass to server /enroll for credential public key extraction
		attestationObject: bufToBase64url(credential.response.attestationObject),
		clientDataJSON: bufToBase64url(credential.response.clientDataJSON)
	}
}
