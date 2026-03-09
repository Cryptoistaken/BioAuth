// convex/webauthn.ts
// WebAuthn assertion verification — Buffer-free, Web Crypto only.
// Compatible with Convex's default runtime (no Node.js required).
//
// Exports:
//   extractCredentialPublicKey(attObjBytes: Uint8Array) → hex string
//   verifyAssertionSignature(credPubKeyHex, authData, clientDataJSON, sig) → boolean

// ─── Uint8Array helpers ───────────────────────────────────────────────────────

export function hexToBytes(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

export function base64urlToBytes(b64: string): Uint8Array {
	// Pad to multiple of 4, convert to standard base64, then decode
	const padded = b64.replace(/-/g, "+").replace(/_/g, "/");
	const pad = (4 - (padded.length % 4)) % 4;
	const std = padded + "=".repeat(pad);
	const binary = atob(std);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

export function bytesToBase64url(bytes: Uint8Array): string {
	let binary = "";
	for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
	const total = arrays.reduce((n, a) => n + a.length, 0);
	const out = new Uint8Array(total);
	let offset = 0;
	for (const arr of arrays) { out.set(arr, offset); offset += arr.length; }
	return out;
}

// ─── Minimal CBOR decoder ────────────────────────────────────────────────────
// Handles major types 0–5 only — sufficient for WebAuthn attestation objects
// and COSE keys. Not a general-purpose CBOR implementation.

type CborValue = number | string | Uint8Array | CborValue[] | Record<number | string, CborValue>;

function cborDecode(buf: Uint8Array, offset = 0): { value: CborValue; offset: number } {
	const b = buf[offset];
	const major = b >> 5;
	const info = b & 0x1f;
	offset++;

	function readLen(info: number, offset: number): { len: number; offset: number } {
		if (info < 24)  return { len: info, offset };
		if (info === 24) return { len: buf[offset], offset: offset + 1 };
		if (info === 25) return { len: (buf[offset] << 8) | buf[offset + 1], offset: offset + 2 };
		if (info === 26) return {
			len: ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0,
			offset: offset + 4,
		};
		throw new Error(`CBOR: unsupported length info ${info}`);
	}

	if (major === 0) { const r = readLen(info, offset); return { value: r.len, offset: r.offset }; }
	if (major === 1) { const r = readLen(info, offset); return { value: -1 - r.len, offset: r.offset }; }

	if (major === 2) { // byte string → Uint8Array
		const r = readLen(info, offset);
		return { value: buf.slice(r.offset, r.offset + r.len), offset: r.offset + r.len };
	}

	if (major === 3) { // text string
		const r = readLen(info, offset);
		const text = new TextDecoder().decode(buf.slice(r.offset, r.offset + r.len));
		return { value: text, offset: r.offset + r.len };
	}

	if (major === 4) { // array
		const r = readLen(info, offset);
		const arr: CborValue[] = [];
		offset = r.offset;
		for (let i = 0; i < r.len; i++) {
			const item = cborDecode(buf, offset);
			arr.push(item.value);
			offset = item.offset;
		}
		return { value: arr, offset };
	}

	if (major === 5) { // map
		const r = readLen(info, offset);
		const map: Record<number | string, CborValue> = {};
		offset = r.offset;
		for (let i = 0; i < r.len; i++) {
			const k = cborDecode(buf, offset); offset = k.offset;
			const v = cborDecode(buf, offset); offset = v.offset;
			map[k.value as number | string] = v.value;
		}
		return { value: map, offset };
	}

	throw new Error(`CBOR: unsupported major type ${major}`);
}

// ─── Extract credential public key from attestationObject ────────────────────
// attestationObject: CBOR { fmt, attStmt, authData }
// authData layout:
//   [0..31]  rpIdHash     (32 bytes)
//   [32]     flags        (1 byte) — bit 6 (0x40) = AT flag
//   [33..36] signCount    (4 bytes)
//   [37..52] aaguid       (16 bytes)
//   [53..54] credIdLen    (2 bytes, big-endian)
//   [55..]   credId       (credIdLen bytes)
//   [...]    COSE key     (remainder)
// Returns the raw COSE key bytes as a hex string.

export function extractCredentialPublicKey(attObjBytes: Uint8Array): string {
	const decoded = cborDecode(attObjBytes).value as Record<string, CborValue>;
	const authData = decoded["authData"] as Uint8Array;

	const flags = authData[32];
	if (!(flags & 0x40)) throw new Error("AT flag not set — no credential data in authData");

	// skip rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) = 53 bytes
	const credIdLen = (authData[53] << 8) | authData[54];
	const coseKeyOffset = 55 + credIdLen;

	return bytesToHex(authData.slice(coseKeyOffset));
}

// ─── Verify WebAuthn assertion signature ─────────────────────────────────────
// Signed data = authData || SHA-256(clientDataJSON)
// Supports ES256 (kty=2, alg=-7) and RS256 (kty=3, alg=-257).

export async function verifyAssertionSignature(
	credentialPublicKeyHex: string,
	authDataBytes: Uint8Array,
	clientDataJSONBytes: Uint8Array,
	sigBytes: Uint8Array,
): Promise<boolean> {
	const coseKeyBytes = hexToBytes(credentialPublicKeyHex);
	const coseKey = cborDecode(coseKeyBytes).value as Record<number, CborValue>;

	const kty = coseKey[1] as number;
	const alg = coseKey[3] as number;

	// Build signed data: authData || SHA-256(clientDataJSON)
	const clientDataHash = new Uint8Array(
		await crypto.subtle.digest("SHA-256", clientDataJSONBytes)
	);
	const signedData = concatBytes(authDataBytes, clientDataHash);

	if (kty === 2 && alg === -7) {
		// EC2 / ES256 — P-256
		const x = coseKey[-2] as Uint8Array;
		const y = coseKey[-3] as Uint8Array;

		const key = await crypto.subtle.importKey(
			"jwk",
			{
				kty: "EC", crv: "P-256",
				x: bytesToBase64url(x),
				y: bytesToBase64url(y),
			},
			{ name: "ECDSA", namedCurve: "P-256" },
			false, ["verify"]
		);

		return crypto.subtle.verify(
			{ name: "ECDSA", hash: "SHA-256" },
			key, sigBytes, signedData
		);
	}

	if (kty === 3 && alg === -257) {
		// RSA / RS256
		const n = coseKey[-1] as Uint8Array;
		const e = coseKey[-2] as Uint8Array;

		const key = await crypto.subtle.importKey(
			"jwk",
			{
				kty: "RSA", alg: "RS256",
				n: bytesToBase64url(n),
				e: bytesToBase64url(e),
			},
			{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
			false, ["verify"]
		);

		return crypto.subtle.verify(
			{ name: "RSASSA-PKCS1-v1_5" },
			key, sigBytes, signedData
		);
	}

	throw new Error(`Unsupported COSE key: kty=${kty}, alg=${alg}`);
}
