import { getIdentity, consumeChallenge } from '../db.js'

export function verifyRoute(app) {
	app.post('/verify', async (c) => {
		const body = await c.req.json().catch(() => null)

		if (!body?.userId || !body?.challenge) {
			return c.json({ error: 'Missing required fields: userId, challenge' }, 400)
		}

		const { userId, challenge } = body

		const identity = getIdentity(userId)
		if (!identity) {
			return c.json({ error: 'Unknown userId' }, 404)
		}

		const valid = consumeChallenge(challenge)
		if (!valid) {
			return c.json({ error: 'Invalid or expired challenge' }, 401)
		}

		return c.json({ verified: true, publicKey: identity.public_key, userId, method: identity.method })
	})
}
