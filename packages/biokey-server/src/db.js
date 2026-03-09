import { Database } from 'bun:sqlite'

const db = new Database('biokey.db')

db.run(`
	CREATE TABLE IF NOT EXISTS identities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL UNIQUE,
		public_key TEXT NOT NULL,
		credential_public_key TEXT NOT NULL DEFAULT '',
		device_id TEXT NOT NULL,
		method TEXT NOT NULL DEFAULT 'rawid',
		created_at INTEGER NOT NULL
	)
`)

db.run(`
	CREATE TABLE IF NOT EXISTS challenges (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		challenge TEXT NOT NULL UNIQUE,
		user_id TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL
	)
`)

// Persisted lockout table — survives server restarts
db.run(`
	CREATE TABLE IF NOT EXISTS lockouts (
		user_id TEXT PRIMARY KEY,
		failures INTEGER NOT NULL DEFAULT 0,
		locked_until INTEGER NOT NULL DEFAULT 0,
		updated_at INTEGER NOT NULL
	)
`)

// ─── Identities ───────────────────────────────────────────────────────────────

export function saveIdentity(userId, publicKey, credentialPublicKey, deviceId, method = 'rawid') {
	db.run(
		`INSERT OR REPLACE INTO identities
		 (user_id, public_key, credential_public_key, device_id, method, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		[userId, publicKey, credentialPublicKey, deviceId, method, Date.now()]
	)
}

export function getIdentity(userId) {
	return db.query(`SELECT * FROM identities WHERE user_id = ?`).get(userId)
}

export function getIdentityByPublicKey(publicKey) {
	return db.query(`SELECT * FROM identities WHERE public_key = ?`).get(publicKey)
}

// ─── Challenges ───────────────────────────────────────────────────────────────

export function saveChallenge(challenge, userId = '') {
	db.run(
		`INSERT INTO challenges (challenge, user_id, created_at) VALUES (?, ?, ?)`,
		[challenge, userId, Date.now()]
	)
}

export function consumeChallenge(challenge) {
	const row = db.query(`SELECT * FROM challenges WHERE challenge = ?`).get(challenge)
	if (!row) return false
	db.run(`DELETE FROM challenges WHERE challenge = ?`, [challenge])
	return (Date.now() - row.created_at) < 5 * 60 * 1000
}

export function countPendingChallenges(userId) {
	const cutoff = Date.now() - 5 * 60 * 1000
	const row = db.query(
		`SELECT COUNT(*) as count FROM challenges WHERE user_id = ? AND created_at > ?`
	).get(userId, cutoff)
	return row?.count ?? 0
}

export function cleanOldChallenges() {
	db.run(`DELETE FROM challenges WHERE created_at < ?`, [Date.now() - 5 * 60 * 1000])
}

// ─── Lockouts ─────────────────────────────────────────────────────────────────

export function getLockout(userId) {
	return db.query(`SELECT * FROM lockouts WHERE user_id = ?`).get(userId)
}

export function saveLockout(userId, failures, lockedUntil) {
	db.run(
		`INSERT OR REPLACE INTO lockouts (user_id, failures, locked_until, updated_at)
		 VALUES (?, ?, ?, ?)`,
		[userId, failures, lockedUntil, Date.now()]
	)
}

export function clearLockout(userId) {
	db.run(`DELETE FROM lockouts WHERE user_id = ?`, [userId])
}
