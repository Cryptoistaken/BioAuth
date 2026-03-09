import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
	// Enrolled identities — one per userId
	identities: defineTable({
		userId:              v.string(), // hex, min 32 chars
		publicKey:           v.string(), // 64-char hex derived identity key
		credentialPublicKey: v.string(), // COSE hex — used for assertion verification
		deviceId:            v.string(), // 16-char hex device fingerprint
		method:              v.union(v.literal("prf"), v.literal("rawid")),
	}).index("by_userId", ["userId"]),

	// Pending authentication challenges — single-use, 5-min TTL
	challenges: defineTable({
		challenge: v.string(), // 64-char hex (32 random bytes)
		userId:    v.string(), // tied to a specific userId at issuance
		createdAt: v.number(), // Date.now() — used for TTL check
	})
		.index("by_challenge", ["challenge"])
		.index("by_userId",    ["userId"]),

	// Per-userId brute force lockout — persisted across restarts
	lockouts: defineTable({
		userId:      v.string(),
		failures:    v.number(),
		lockedUntil: v.number(), // 0 = not locked
		updatedAt:   v.number(),
	}).index("by_userId", ["userId"]),
});
