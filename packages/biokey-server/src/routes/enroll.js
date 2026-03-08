import { saveIdentity } from '../db.js'

export function enrollRoute(app) {
	app.post('/enroll', async (c) => {
		const body = await c.req.json().catch(() => null)

		if (!body?.userId || !body?.publicKey || !body?.deviceId) {
			return c.json({ error: 'Missing required fields: userId, publicKey, deviceId' }, 400)
		}

		const { userId, publicKey, deviceId, method = 'rawid' } = body

		if (typeof publicKey !== 'string' || publicKey.length !== 64) {
			return c.json({ error: 'Invalid publicKey format' }, 400)
		}

		try {
			saveIdentity(userId, publicKey, deviceId, method)
			return c.json({ ok: true, userId, publicKey, method })
		} catch (err) {
			return c.json({ error: 'Enrollment failed', detail: err.message }, 500)
		}
	})
}
