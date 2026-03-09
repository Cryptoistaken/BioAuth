import { saveIdentity } from '../db.js'
import { extractCredentialPublicKey } from '../webauthn.js'

export function enrollRoute(app) {
	app.post('/enroll', async (c) => {
		const body = await c.req.json().catch(() => null)

		if (!body?.userId || !body?.publicKey || !body?.deviceId || !body?.attestationObject || !body?.clientDataJSON) {
			return c.json({ error: 'Missing required fields' }, 400)
		}

		const { userId, publicKey, deviceId, method = 'rawid', attestationObject, clientDataJSON } = body

		// userId must be a hex string of at least 32 chars (128-bit entropy minimum)
		// This prevents predictable or guessable userIds entirely
		if (typeof userId !== 'string' || userId.length < 32 || !/^[0-9a-f]+$/i.test(userId)) {
			return c.json({ error: 'userId must be a lowercase hex string of at least 32 characters' }, 400)
		}

		if (typeof publicKey !== 'string' || publicKey.length !== 64) {
			return c.json({ error: 'Invalid publicKey format' }, 400)
		}

		// Verify clientDataJSON type
		let clientData
		try {
			clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString())
		} catch {
			return c.json({ error: 'Invalid clientDataJSON' }, 400)
		}

		if (clientData.type !== 'webauthn.create') {
			return c.json({ error: 'Invalid clientData type' }, 400)
		}

		// Extract the authenticator's credential public key from attestationObject
		let credentialPublicKey
		try {
			credentialPublicKey = extractCredentialPublicKey(Buffer.from(attestationObject, 'base64url'))
		} catch (err) {
			return c.json({ error: 'Failed to parse attestationObject', detail: err.message }, 400)
		}

		try {
			saveIdentity(userId, publicKey, credentialPublicKey, deviceId, method)
			return c.json({ ok: true, userId, publicKey, method })
		} catch (err) {
			return c.json({ error: 'Enrollment failed', detail: err.message }, 500)
		}
	})
}
