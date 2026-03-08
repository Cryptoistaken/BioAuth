const STORAGE_PREFIX = 'biokey:'

function bufToHex(buf) {
	return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('')
}

function hexToBuf(hex) {
	return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16))).buffer
}

const PRF_SALT = new TextEncoder().encode('biokey-prf-v2-salt')

// ─── V1 fallback ──────────────────────────────────────────────────────────────
async function deriveKeyRawId(rawId) {
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
		keyMaterial, 256
	)
	return new Uint8Array(bits)
}

function extractPRFOutput(credential) {
	const first = credential?.getClientExtensionResults?.()?.prf?.results?.first
	return first ? new Uint8Array(first) : null
}

async function deviceId() {
	const raw = [
		navigator.userAgent,
		navigator.language,
		screen.width,
		screen.height,
		Intl.DateTimeFormat().resolvedOptions().timeZone
	].join('|')
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

	// ─── enroll ───────────────────────────────────────────────────────────────
	// Attempts PRF enrollment first. Falls back to rawId-HKDF (V1) if the
	// platform authenticator does not support the PRF extension.
	// Returns { publicKey, credentialId, deviceId, enrolledAt, method }
	async enroll(userId) {
		const challenge = crypto.getRandomValues(new Uint8Array(32))
		const uid = userId
			? new TextEncoder().encode(userId)
			: crypto.getRandomValues(new Uint8Array(16))

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
			publicKey = bufToHex(prfOutput)
			method = 'prf'
		} else {
			const seed = await deriveKeyRawId(credential.rawId)
			publicKey = bufToHex(seed)
			method = 'rawid'
		}

		const credentialId = bufToHex(credential.rawId)
		const did = await deviceId()
		const identity = { publicKey, credentialId, deviceId: did, enrolledAt: Date.now(), method }

		localStorage.setItem(this.storageKey, JSON.stringify(identity))

		if (this.serverUrl && userId) {
			await fetch(`${this.serverUrl}/enroll`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ userId, publicKey, deviceId: did, method })
			}).catch(() => {})
		}

		return identity
	}

	// ─── authenticate ─────────────────────────────────────────────────────────
	// If PRF was used at enrollment, re-derives the key via PRF and validates
	// it matches the stored publicKey. Falls back to rawId-HKDF V1 if needed.
	async authenticate(userId) {
		const identity = this.getIdentity()
		if (!identity) throw new Error('No enrolled credential. Call enroll() first.')

		let challenge

		if (this.serverUrl && userId) {
			const res = await fetch(`${this.serverUrl}/challenge`)
			const data = await res.json()
			challenge = hexToBuf(data.challenge)
		} else {
			challenge = crypto.getRandomValues(new Uint8Array(32))
		}

		const challengeBuf = challenge instanceof ArrayBuffer ? challenge : challenge.buffer

		const assertion = await navigator.credentials.get({
			publicKey: {
				challenge: challengeBuf,
				rpId: this.rpId,
				allowCredentials: [{ id: hexToBuf(identity.credentialId), type: 'public-key' }],
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

		const prfOutput = extractPRFOutput(assertion)

		if (prfOutput) {
			const derivedKey = bufToHex(prfOutput)
			if (identity.method === 'prf' && derivedKey !== identity.publicKey) {
				throw new Error('PRF key mismatch — identity verification failed.')
			}
			if (this.serverUrl && userId) {
				await this._serverVerify(userId, challengeBuf, identity.publicKey)
			}
			return { verified: true, publicKey: derivedKey, method: 'prf' }
		}

		// V1 fallback
		const seed = await deriveKeyRawId(assertion.rawId)
		const derivedKey = bufToHex(seed)
		if (identity.method === 'rawid' && derivedKey !== identity.publicKey) {
			throw new Error('Key mismatch — identity verification failed.')
		}
		if (this.serverUrl && userId) {
			await this._serverVerify(userId, challengeBuf, identity.publicKey)
		}
		return { verified: true, publicKey: identity.publicKey, method: 'rawid' }
	}

	async _serverVerify(userId, challengeBuf, expectedKey) {
		const challengeHex = bufToHex(challengeBuf)
		const res = await fetch(`${this.serverUrl}/verify`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ userId, challenge: challengeHex })
		})
		const data = await res.json()
		if (!data.verified) throw new Error('Server verification failed.')
		if (data.publicKey !== expectedKey) throw new Error('Server public key mismatch.')
	}
}
