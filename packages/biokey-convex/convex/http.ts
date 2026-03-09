// convex/http.ts
// BioKey HTTP API — drop-in replacement for biokey-server.
// Endpoints are served at https://<deployment>.convex.site
//
//   GET  /challenge/:userId  → { challenge }
//   POST /enroll             → { ok, userId, publicKey, method }
//   POST /verify             → { verified, publicKey, userId, method }

import { httpRouter }  from "convex/server";
import { httpAction }  from "./_generated/server";
import { internal }    from "./_generated/api";
import {
	extractCredentialPublicKey,
	verifyAssertionSignature,
	base64urlToBytes,
	bytesToHex,
} from "./webauthn";

const http = httpRouter();

// ─── CORS helper ─────────────────────────────────────────────────────────────

function corsHeaders(origin: string | null) {
	return {
		"Access-Control-Allow-Origin":  origin ?? "*",
		"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
		"Access-Control-Allow-Headers": "Content-Type",
	};
}

function json(body: unknown, status = 200, origin: string | null = null) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", ...corsHeaders(origin) },
	});
}

// Preflight for all routes
http.route({
	pathPrefix: "/",
	method: "OPTIONS",
	handler: httpAction(async (_ctx, req) => {
		return new Response(null, {
			status: 204,
			headers: corsHeaders(req.headers.get("origin")),
		});
	}),
});

// ─── GET /challenge/:userId ───────────────────────────────────────────────────
// Convex doesn't support dynamic path segments, so we use pathPrefix
// and parse the userId from the URL manually.

http.route({
	pathPrefix: "/challenge/",
	method: "GET",
	handler: httpAction(async (ctx, req) => {
		const origin = req.headers.get("origin");
		const url = new URL(req.url);

		// Extract userId from path: /challenge/<userId>
		// Convex doesn't support dynamic path segments natively,
		// so we read it from the URL manually.
		const parts = url.pathname.split("/").filter(Boolean);
		const userId = parts[1]; // ["challenge", "<userId>"]

		if (!userId || userId.length < 32) {
			return json({ error: "Valid userId required (min 32 hex chars)" }, 400, origin);
		}

		// Flood protection — max 3 pending challenges per userId
		const pending = await ctx.runQuery(internal.biokey.countPendingChallenges, { userId });
		if (pending >= 3) {
			return json({ error: "Too many pending challenges for this userId" }, 429, origin);
		}

		// Generate challenge — 32 random bytes as hex
		// crypto.getRandomValues is available in actions (non-deterministic is fine here)
		const bytes = crypto.getRandomValues(new Uint8Array(32));
		const challenge = bytesToHex(bytes);

		await ctx.runMutation(internal.biokey.saveChallenge, { challenge, userId });
		await ctx.runMutation(internal.biokey.cleanOldChallenges, {});

		return json({ challenge }, 200, origin);
	}),
});

// ─── POST /enroll ─────────────────────────────────────────────────────────────

http.route({
	path: "/enroll",
	method: "POST",
	handler: httpAction(async (ctx, req) => {
		const origin = req.headers.get("origin");
		let body: Record<string, string>;

		try { body = await req.json(); }
		catch { return json({ error: "Invalid JSON body" }, 400, origin); }

		const { userId, publicKey, deviceId, attestationObject, clientDataJSON } = body;
		const method = body.method ?? "rawid";

		if (!userId || !publicKey || !deviceId || !attestationObject || !clientDataJSON) {
			return json({ error: "Missing required fields" }, 400, origin);
		}

		// userId: lowercase hex, min 32 chars (128-bit entropy)
		if (typeof userId !== "string" || userId.length < 32 || !/^[0-9a-f]+$/i.test(userId)) {
			return json({ error: "userId must be a hex string of at least 32 characters" }, 400, origin);
		}

		// publicKey: 64-char hex
		if (typeof publicKey !== "string" || publicKey.length !== 64) {
			return json({ error: "Invalid publicKey format" }, 400, origin);
		}

		// Verify clientData type = webauthn.create
		let clientData: Record<string, string>;
		try {
			const bytes = base64urlToBytes(clientDataJSON);
			clientData = JSON.parse(new TextDecoder().decode(bytes));
		} catch {
			return json({ error: "Invalid clientDataJSON" }, 400, origin);
		}

		if (clientData.type !== "webauthn.create") {
			return json({ error: "Invalid clientData type" }, 400, origin);
		}

		// Extract COSE credential public key from attestationObject
		let credentialPublicKey: string;
		try {
			credentialPublicKey = extractCredentialPublicKey(base64urlToBytes(attestationObject));
		} catch (err) {
			return json({ error: "Failed to parse attestationObject", detail: String(err) }, 400, origin);
		}

		try {
			await ctx.runMutation(internal.biokey.saveIdentity, {
				userId,
				publicKey,
				credentialPublicKey,
				deviceId,
				method: method === "prf" ? "prf" : "rawid",
			});
			return json({ ok: true, userId, publicKey, method }, 200, origin);
		} catch (err) {
			return json({ error: "Enrollment failed", detail: String(err) }, 500, origin);
		}
	}),
});

// ─── POST /verify ─────────────────────────────────────────────────────────────

const FAIL = { error: "Authentication failed" };

http.route({
	path: "/verify",
	method: "POST",
	handler: httpAction(async (ctx, req) => {
		const origin = req.headers.get("origin");
		let body: Record<string, string>;

		try { body = await req.json(); }
		catch { return json({ error: "Invalid JSON body" }, 400, origin); }

		const { userId, challenge, authenticatorData, clientDataJSON, signature } = body;

		if (!userId || !challenge || !authenticatorData || !clientDataJSON || !signature) {
			return json({ error: "Missing required fields" }, 400, origin);
		}

		// 1. Lockout check — before any DB identity lookup
		const lockout = await ctx.runQuery(internal.biokey.getLockout, { userId });
		if (lockout && lockout.lockedUntil > Date.now()) {
			const retryAfter = Math.ceil((lockout.lockedUntil - Date.now()) / 1000);
			return json({ error: "Account temporarily locked", retryAfter }, 429, origin);
		}

		// 2. Identity lookup — generic error to prevent enumeration
		const identity = await ctx.runQuery(internal.biokey.getIdentity, { userId });
		if (!identity) {
			await ctx.runMutation(internal.biokey.recordVerifyFailure, { userId });
			return json(FAIL, 401, origin);
		}

		// 3. Consume challenge — single-use, 5-min TTL (atomic delete+check)
		const validChallenge = await ctx.runMutation(internal.biokey.consumeChallenge, { challenge });
		if (!validChallenge) {
			await ctx.runMutation(internal.biokey.recordVerifyFailure, { userId });
			return json(FAIL, 401, origin);
		}

		// 4. Verify clientDataJSON: type = webauthn.get, challenge binding
		let clientData: Record<string, string>;
		try {
			const bytes = base64urlToBytes(clientDataJSON);
			clientData = JSON.parse(new TextDecoder().decode(bytes));
		} catch {
			await ctx.runMutation(internal.biokey.recordVerifyFailure, { userId });
			return json(FAIL, 401, origin);
		}

		if (clientData.type !== "webauthn.get") {
			await ctx.runMutation(internal.biokey.recordVerifyFailure, { userId });
			return json(FAIL, 401, origin);
		}

		// Challenge in clientDataJSON is base64url-encoded — decode and compare as hex
		const clientChallenge = bytesToHex(base64urlToBytes(clientData.challenge));
		if (clientChallenge !== challenge) {
			await ctx.runMutation(internal.biokey.recordVerifyFailure, { userId });
			return json(FAIL, 401, origin);
		}

		// 5. Cryptographic assertion signature verification
		try {
			const ok = await verifyAssertionSignature(
				identity.credentialPublicKey,
				base64urlToBytes(authenticatorData),
				base64urlToBytes(clientDataJSON),
				base64urlToBytes(signature),
			);
			if (!ok) {
				await ctx.runMutation(internal.biokey.recordVerifyFailure, { userId });
				return json(FAIL, 401, origin);
			}
		} catch {
			await ctx.runMutation(internal.biokey.recordVerifyFailure, { userId });
			return json(FAIL, 401, origin);
		}

		await ctx.runMutation(internal.biokey.recordVerifySuccess, { userId });
		return json({
			verified:  true,
			publicKey: identity.publicKey,
			userId,
			method:    identity.method,
		}, 200, origin);
	}),
});

export default http;
