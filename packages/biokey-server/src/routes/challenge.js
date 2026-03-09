import { saveChallenge, cleanOldChallenges } from '../db.js'
import { checkChallengeFlood } from '../ratelimit.js'

function randomHex(bytes) {
	return [...crypto.getRandomValues(new Uint8Array(bytes))]
		.map(b => b.toString(16).padStart(2, '0'))
		.join('')
}

export function challengeRoute(app) {
	// userId is required to issue a challenge — prevents anonymous flooding
	// and ties challenge flood protection to the identity, not the network.
	app.get('/challenge/:userId', (c) => {
		const userId = c.req.param('userId')

		if (!userId || userId.length < 32) {
			return c.json({ error: 'Valid userId required' }, 400)
		}

		// Cap outstanding challenges per userId
		const flood = checkChallengeFlood(userId)
		if (!flood.allowed) {
			return c.json({ error: 'Too many pending challenges for this userId' }, 429)
		}

		cleanOldChallenges()
		const challenge = randomHex(32)
		saveChallenge(challenge, userId)
		return c.json({ challenge })
	})
}
