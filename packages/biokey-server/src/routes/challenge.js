import { saveChallenge, cleanOldChallenges } from '../db.js'

function randomHex(bytes) {
	return [...crypto.getRandomValues(new Uint8Array(bytes))]
		.map(b => b.toString(16).padStart(2, '0'))
		.join('')
}

export function challengeRoute(app) {
	app.get('/challenge', (c) => {
		cleanOldChallenges()
		const challenge = randomHex(32)
		saveChallenge(challenge)
		return c.json({ challenge })
	})
}
