import { getIdentity, consumeChallenge } from '../db.js'
import { verifyAssertionSignature } from '../webauthn.js'
import { checkUserLockout, recordVerifyFailure, recordVerifySuccess } from '../ratelimit.js'

// Single generic failure response — same message for every failure reason.
// Prevents userId enumeration and avoids leaking which step failed.
const FAIL = { error: 'Authentication failed' }

export function verifyRoute(app) {
	app.post('/verify', async (c) => {
		const body = await c.req.json().catch(() => null)

		if (!body?.userId || !body?.challenge || !body?.authenticatorData || !body?.clientDataJSON || !body?.signature) {
			return c.json({ error: 'Missing required fields' }, 400)
		}

		const { userId, challenge, authenticatorData, clientDataJSON, signature } = body

		// 1. Per-userId lockout — checked first, before any DB lookup
		const lockout = checkUserLockout(userId)
		if (lockout.locked) {
			return c.json({ error: 'Account temporarily locked', retryAfter: lockout.retryAfter }, 429)
		}

		// 2. Identity lookup — generic error prevents userId enumeration
		const identity = getIdentity(userId)
		if (!identity) {
			recordVerifyFailure(userId)
			return c.json(FAIL, 401)
		}

		// 3. Consume challenge — single use, 5 min TTL
		const valid = consumeChallenge(challenge)
		if (!valid) {
			recordVerifyFailure(userId)
			return c.json(FAIL, 401)
		}

		// 4. Verify clientDataJSON: type must be webauthn.get,
		//    challenge must match what this server issued
		let clientData
		try {
			clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString())
		} catch {
			recordVerifyFailure(userId)
			return c.json(FAIL, 401)
		}

		if (clientData.type !== 'webauthn.get') {
			recordVerifyFailure(userId)
			return c.json(FAIL, 401)
		}

		const clientChallenge = Buffer.from(clientData.challenge, 'base64url').toString('hex')
		if (clientChallenge !== challenge) {
			recordVerifyFailure(userId)
			return c.json(FAIL, 401)
		}

		// 5. Cryptographic assertion signature verification
		//    Proves the biometric event actually happened on the enrolled hardware
		if (identity.credential_public_key) {
			try {
				const ok = await verifyAssertionSignature(
					identity.credential_public_key,
					Buffer.from(authenticatorData, 'base64url'),
					Buffer.from(clientDataJSON, 'base64url'),
					Buffer.from(signature, 'base64url')
				)
				if (!ok) {
					recordVerifyFailure(userId)
					return c.json(FAIL, 401)
				}
			} catch {
				recordVerifyFailure(userId)
				return c.json(FAIL, 401)
			}
		}

		recordVerifySuccess(userId)
		return c.json({ verified: true, publicKey: identity.public_key, userId, method: identity.method })
	})
}
