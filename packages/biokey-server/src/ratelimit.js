// ─── ratelimit.js ─────────────────────────────────────────────────────────────
// Brute force protection for BioKey server — userId-based only, no IP tracking.
//
// Two layers:
//   1. Per-userId lockout  — temporary lockout after N consecutive verify failures
//   2. Per-userId challenge flood — max outstanding challenges per userId at once
//
// Lockout state is persisted to SQLite so it survives server restarts.
// Challenge flood state is in-memory (challenges themselves are in SQLite).

import { getLockout, saveLockout, clearLockout, countPendingChallenges } from './db.js'

const MAX_VERIFY_FAILURES = 5           // failures before lockout
const LOCKOUT_MS = 15 * 60 * 1000      // 15 minutes
const MAX_CHALLENGES_PER_USER = 3       // max outstanding challenges per userId

// ─── Per-userId lockout ───────────────────────────────────────────────────────

export function checkUserLockout(userId) {
	const entry = getLockout(userId)
	if (!entry) return { locked: false }

	if (Date.now() < entry.locked_until) {
		const retryAfter = Math.ceil((entry.locked_until - Date.now()) / 1000)
		return { locked: true, retryAfter }
	}

	// Expired — clean it up
	clearLockout(userId)
	return { locked: false }
}

export function recordVerifyFailure(userId) {
	const entry = getLockout(userId) ?? { failures: 0, locked_until: 0 }
	entry.failures++

	if (entry.failures >= MAX_VERIFY_FAILURES) {
		entry.locked_until = Date.now() + LOCKOUT_MS
		entry.failures = 0
	}

	saveLockout(userId, entry.failures, entry.locked_until)
}

export function recordVerifySuccess(userId) {
	clearLockout(userId)
}

// ─── Per-userId challenge flood ───────────────────────────────────────────────

export function checkChallengeFlood(userId) {
	const pending = countPendingChallenges(userId)
	return { allowed: pending < MAX_CHALLENGES_PER_USER }
}
