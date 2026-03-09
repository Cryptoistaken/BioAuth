const STORAGE_PREFIX = 'biokey:'

function bufToHex(buf) {
	return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('')
}

function hexToBuf(hex) {
	return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16))).buffer
}

function bufToBase64url(buf) {
	return btoa(String.fromCharCode(...new Uint8Array(buf)))
		.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const PRF_SALT = new TextEncoder().encode('biokey-prf-v2-salt')

async function deriveKeyRawId(rawId) {
	const keyMaterial = await crypto.subtle.importKey(
		'raw', rawId, { name: 'HKDF' }, false, ['deriveBits']
	)
	const bits = await crypto.subtle.deriveBits(
		{ name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode('biokey-v1-salt'), info: new TextEncoder().encode('biokey-identity-seed') },
		keyMaterial, 256
	)
	return new Uint8Array(bits)
}

function extractPRFOutput(credential) {
	const first = credential?.getClientExtensionResults?.()?.prf?.results?.first
	return first ? new Uint8Array(first) : null
}

async function getDeviceId() {
	const raw = [navigator.userAgent, navigator.language, screen.width, screen.height, Intl.DateTimeFormat().resolvedOptions().timeZone].join('|')
	const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw))
	return bufToHex(buf).slice(0, 16)
}

export class BioKeyClient {
	constructor(options = {}) {
		this.rpId = options.rpId ?? location.hostname
		this.rpName = options.rpName ?? 'BioKey'
		this.serverUrl = options.serverUrl ?? null
		this.storageKey = STORAGE_PREFIX + this.rpId
	}

	getIdentity() {
		const raw = localStorage.getItem(this.storageKey)
		return raw ? JSON.parse(raw) : null
	}

	clearIdentity() {
		localStorage.removeItem(this.storageKey)
	}

	async enroll(userId) {
		const challenge = crypto.getRandomValues(new Uint8Array(32))
		const uid = userId ? new TextEncoder().encode(userId) : crypto.getRandomValues(new Uint8Array(16))

		const credential = await navigator.credentials.create({
			publicKey: {
				challenge,
				rp: { name: this.rpName, id: this.rpId },
				user: { id: uid, name: 'biokey-user', displayName: 'BioKey User' },
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
			const seed = await deriveKeyRawId(credential.rawId)
			publicKey = bufToHex(seed)
			method = 'rawid'
		}

		const credentialId = bufToHex(credential.rawId)
		const did = await getDeviceId()
		const identity = { publicKey, credentialId, deviceId: did, enrolledAt: Date.now(), method }
		localStorage.setItem(this.storageKey, JSON.stringify(identity))

		if (this.serverUrl && userId) {
			await fetch(`${this.serverUrl}/enroll`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					userId,
					publicKey,
					deviceId: did,
					method,
					attestationObject: bufToBase64url(credential.response.attestationObject),
					clientDataJSON: bufToBase64url(credential.response.clientDataJSON)
				})
			}).catch(() => {})
		}

		return identity
	}

	async authenticate(userId) {
		const identity = this.getIdentity()
		if (!identity) throw new Error('No enrolled credential. Call enroll() first.')

		let challengeHex, challengeBuf

		if (this.serverUrl && userId) {
			// Challenge is now scoped to userId — prevents anonymous challenge flooding
			const res = await fetch(`${this.serverUrl}/challenge/${userId}`)
			const data = await res.json()
			challengeHex = data.challenge
			challengeBuf = hexToBuf(challengeHex)
		} else {
			const raw = crypto.getRandomValues(new Uint8Array(32))
			challengeHex = bufToHex(raw)
			challengeBuf = raw.buffer
		}

		const assertion = await navigator.credentials.get({
			publicKey: {
				challenge: challengeBuf,
				rpId: this.rpId,
				allowCredentials: [{ id: hexToBuf(identity.credentialId), type: 'public-key' }],
				userVerification: 'required',
				extensions: { prf: { evalByCredential: { [identity.credentialId]: { first: PRF_SALT } } } },
				timeout: 60000
			}
		})

		const prfOutput = extractPRFOutput(assertion)
		let derivedKey, method

		if (prfOutput) {
			derivedKey = bufToHex(prfOutput)
			method = 'prf'
			if (identity.method === 'prf' && derivedKey !== identity.publicKey) {
				throw new Error('PRF key mismatch — identity verification failed.')
			}
		} else {
			const seed = await deriveKeyRawId(assertion.rawId)
			derivedKey = bufToHex(seed)
			method = 'rawid'
			if (identity.method === 'rawid' && derivedKey !== identity.publicKey) {
				throw new Error('Key mismatch — identity verification failed.')
			}
		}

		if (this.serverUrl && userId) {
			await this._serverVerify(userId, challengeHex, assertion, identity.publicKey)
		}

		return { verified: true, publicKey: derivedKey, method }
	}

	async _serverVerify(userId, challengeHex, assertion, expectedKey) {
		const res = await fetch(`${this.serverUrl}/verify`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				userId,
				challenge: challengeHex,
				authenticatorData: bufToBase64url(assertion.response.authenticatorData),
				clientDataJSON: bufToBase64url(assertion.response.clientDataJSON),
				signature: bufToBase64url(assertion.response.signature)
			})
		})
		const data = await res.json()
		if (!data.verified) throw new Error('Server verification failed.')
		if (data.publicKey !== expectedKey) throw new Error('Server public key mismatch.')
		return data
	}
}
