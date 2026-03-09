// convex/biokey.ts
// Internal queries and mutations — called by HTTP actions via ctx.runQuery / ctx.runMutation.
// Nothing here is exposed publicly. All public surface is in http.ts.

import { internalMutation, internalQuery } from "./_generated/server";
import { v } from "convex/values";

const CHALLENGE_TTL_MS = 5 * 60 * 1000;   // 5 minutes
const MAX_VERIFY_FAILURES = 5;
const LOCKOUT_MS = 15 * 60 * 1000;        // 15 minutes

// ─── Identities ──────────────────────────────────────────────────────────────

export const getIdentity = internalQuery({
	args: { userId: v.string() },
	handler: async (ctx, { userId }) => {
		return ctx.db
			.query("identities")
			.withIndex("by_userId", q => q.eq("userId", userId))
			.unique();
	},
});

export const saveIdentity = internalMutation({
	args: {
		userId:              v.string(),
		publicKey:           v.string(),
		credentialPublicKey: v.string(),
		deviceId:            v.string(),
		method:              v.union(v.literal("prf"), v.literal("rawid")),
	},
	handler: async (ctx, args) => {
		const existing = await ctx.db
			.query("identities")
			.withIndex("by_userId", q => q.eq("userId", args.userId))
			.unique();

		if (existing) {
			await ctx.db.patch(existing._id, {
				publicKey:           args.publicKey,
				credentialPublicKey: args.credentialPublicKey,
				deviceId:            args.deviceId,
				method:              args.method,
			});
		} else {
			await ctx.db.insert("identities", args);
		}
	},
});

// ─── Challenges ──────────────────────────────────────────────────────────────

export const countPendingChallenges = internalQuery({
	args: { userId: v.string() },
	handler: async (ctx, { userId }) => {
		const cutoff = Date.now() - CHALLENGE_TTL_MS;
		const rows = await ctx.db
			.query("challenges")
			.withIndex("by_userId", q => q.eq("userId", userId))
			.collect();
		return rows.filter(r => r.createdAt > cutoff).length;
	},
});

export const saveChallenge = internalMutation({
	args: { challenge: v.string(), userId: v.string() },
	handler: async (ctx, args) => {
		await ctx.db.insert("challenges", { ...args, createdAt: Date.now() });
	},
});

// consumeChallenge — deletes and returns validity in one mutation (atomic)
export const consumeChallenge = internalMutation({
	args: { challenge: v.string() },
	handler: async (ctx, { challenge }) => {
		const row = await ctx.db
			.query("challenges")
			.withIndex("by_challenge", q => q.eq("challenge", challenge))
			.unique();
		if (!row) return false;
		await ctx.db.delete(row._id);
		return (Date.now() - row.createdAt) < CHALLENGE_TTL_MS;
	},
});

export const cleanOldChallenges = internalMutation({
	args: {},
	handler: async (ctx) => {
		const cutoff = Date.now() - CHALLENGE_TTL_MS;
		const old = await ctx.db
			.query("challenges")
			.filter(q => q.lt(q.field("createdAt"), cutoff))
			.collect();
		await Promise.all(old.map(r => ctx.db.delete(r._id)));
	},
});

// ─── Lockouts ─────────────────────────────────────────────────────────────────

export const getLockout = internalQuery({
	args: { userId: v.string() },
	handler: async (ctx, { userId }) => {
		return ctx.db
			.query("lockouts")
			.withIndex("by_userId", q => q.eq("userId", userId))
			.unique();
	},
});

export const recordVerifyFailure = internalMutation({
	args: { userId: v.string() },
	handler: async (ctx, { userId }) => {
		const existing = await ctx.db
			.query("lockouts")
			.withIndex("by_userId", q => q.eq("userId", userId))
			.unique();

		const failures = (existing?.failures ?? 0) + 1;
		const lockedUntil = failures >= MAX_VERIFY_FAILURES
			? Date.now() + LOCKOUT_MS
			: 0;
		const updatedAt = Date.now();

		if (existing) {
			await ctx.db.patch(existing._id, {
				failures: failures >= MAX_VERIFY_FAILURES ? 0 : failures,
				lockedUntil,
				updatedAt,
			});
		} else {
			await ctx.db.insert("lockouts", {
				userId,
				failures: failures >= MAX_VERIFY_FAILURES ? 0 : failures,
				lockedUntil,
				updatedAt,
			});
		}
	},
});

export const recordVerifySuccess = internalMutation({
	args: { userId: v.string() },
	handler: async (ctx, { userId }) => {
		const existing = await ctx.db
			.query("lockouts")
			.withIndex("by_userId", q => q.eq("userId", userId))
			.unique();
		if (existing) await ctx.db.delete(existing._id);
	},
});
