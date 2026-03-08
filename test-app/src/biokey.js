const STORAGE_KEY = 'biokey_v0'

function bufToHex(buf) {
	return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('')
}

function hexToBuf(hex) {
	return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16))).buffer
}

async function deriveIdentityKey(rawId) {
	const keyMaterial = await crypto.subtle.importKey(
		'raw',
		rawId,
		{ name: 'HKDF' },
		false,
		['deriveBits']
	)
	return crypto.subtle.deriveBits(
		{
			name: 'HKDF',
			hash: 'SHA-256',
			salt: new TextEncoder().encode('biokey-v0-salt'),
			info: new TextEncoder().encode('biokey-identity-key')
		},
		keyMaterial,
		256
	)
}

export async function enroll() {
	const challenge = crypto.getRandomValues(new Uint8Array(32))
	const userId = crypto.getRandomValues(new Uint8Array(16))

	const credential = await navigator.credentials.create({
		publicKey: {
			challenge,
			rp: {
				name: 'BioKey',
				id: location.hostname
			},
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
			timeout: 60000
		}
	})

	const identityBits = await deriveIdentityKey(credential.rawId)
	const publicKey = bufToHex(identityBits)
	const credentialId = bufToHex(credential.rawId)

	localStorage.setItem(STORAGE_KEY, JSON.stringify({ credentialId, publicKey }))

	return { publicKey, credentialId }
}

export async function authenticate() {
	const stored = JSON.parse(localStorage.getItem(STORAGE_KEY))
	if (!stored) throw new Error('No enrolled credential. Enroll first.')

	const challenge = crypto.getRandomValues(new Uint8Array(32))

	await navigator.credentials.get({
		publicKey: {
			challenge,
			rpId: location.hostname,
			allowCredentials: [{
				id: hexToBuf(stored.credentialId),
				type: 'public-key'
			}],
			userVerification: 'required',
			timeout: 60000
		}
	})

	return { verified: true, publicKey: stored.publicKey }
}

export function getIdentity() {
	const raw = localStorage.getItem(STORAGE_KEY)
	return raw ? JSON.parse(raw) : null
}

export function clearIdentity() {
	localStorage.removeItem(STORAGE_KEY)
}
