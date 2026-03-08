import { Database } from 'bun:sqlite'

const db = new Database('biokey.db')

db.run(`
	CREATE TABLE IF NOT EXISTS identities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL UNIQUE,
		public_key TEXT NOT NULL,
		device_id TEXT NOT NULL,
		method TEXT NOT NULL DEFAULT 'rawid',
		created_at INTEGER NOT NULL
	)
`)

db.run(`
	CREATE TABLE IF NOT EXISTS challenges (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		challenge TEXT NOT NULL UNIQUE,
		created_at INTEGER NOT NULL
	)
`)

export function saveIdentity(userId, publicKey, deviceId, method = 'rawid') {
	db.run(
		`INSERT OR REPLACE INTO identities (user_id, public_key, device_id, method, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		[userId, publicKey, deviceId, method, Date.now()]
	)
}

export function getIdentity(userId) {
	return db.query(`SELECT * FROM identities WHERE user_id = ?`).get(userId)
}

export function getIdentityByPublicKey(publicKey) {
	return db.query(`SELECT * FROM identities WHERE public_key = ?`).get(publicKey)
}

export function saveChallenge(challenge) {
	db.run(
		`INSERT INTO challenges (challenge, created_at) VALUES (?, ?)`,
		[challenge, Date.now()]
	)
}

export function consumeChallenge(challenge) {
	const row = db.query(`SELECT * FROM challenges WHERE challenge = ?`).get(challenge)
	if (!row) return false
	db.run(`DELETE FROM challenges WHERE challenge = ?`, [challenge])
	const age = Date.now() - row.created_at
	return age < 5 * 60 * 1000
}

export function cleanOldChallenges() {
	const cutoff = Date.now() - 5 * 60 * 1000
	db.run(`DELETE FROM challenges WHERE created_at < ?`, [cutoff])
}
