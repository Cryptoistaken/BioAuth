# biokey-react

React hook for BioKey. One hook for fingerprint enrollment and authentication with full server-side assertion verification.

## Install

```bash
bun add biokey-react
```

## Usage

```jsx
import { useBioKey } from 'biokey-react'

// userId must be a hex string of at least 32 characters — generate once and persist it
const USER_ID = 'a3f1c29e847d0b5f6a2e91c47d3b8f0e'

export function LoginButton() {
	const {
		identity,
		status,
		error,
		method,
		isEnrolled,
		isLoading,
		enroll,
		authenticate,
		reset
	} = useBioKey({
		serverUrl: 'https://your-biokey-server.railway.app'
	})

	if (!isEnrolled) {
		return (
			<button onClick={() => enroll(USER_ID)} disabled={isLoading}>
				{isLoading ? 'Scanning...' : 'Enroll Fingerprint'}
			</button>
		)
	}

	return (
		<div>
			<p>Identity: {identity.publicKey.slice(0, 16)}...</p>
			<p>Method: {method}</p>
			<button onClick={() => authenticate(USER_ID)} disabled={isLoading}>
				{isLoading ? 'Verifying...' : 'Authenticate'}
			</button>
			<button onClick={reset}>Reset</button>
			{error && <p style={{ color: 'red' }}>{error}</p>}
		</div>
	)
}
```

## Hook options

| Option | Type | Default | Description |
|---|---|---|---|
| `rpId` | string | `location.hostname` | Relying party ID — must match the page's hostname |
| `rpName` | string | `'BioKey'` | Display name shown during enrollment |
| `serverUrl` | string | `null` | biokey-server base URL for server-side verification |

## Hook return values

| Value | Type | Description |
|---|---|---|
| `identity` | `object \| null` | Stored identity: `{ publicKey, credentialId, deviceId, enrolledAt, method }` |
| `status` | `string` | `idle` / `enrolling` / `enrolled` / `authenticating` / `authenticated` / `error` |
| `error` | `string \| null` | Error message if last action failed, `null` otherwise |
| `method` | `'prf' \| 'rawid' \| null` | Key derivation method used at enrollment |
| `isEnrolled` | `boolean` | `true` if an identity is stored in localStorage |
| `isLoading` | `boolean` | `true` while enrolling or authenticating |
| `enroll(userId?)` | `function` | Start enrollment — triggers fingerprint scanner |
| `authenticate(userId?)` | `function` | Start authentication — triggers fingerprint scanner |
| `reset()` | `function` | Clear stored identity from localStorage |

## userId requirements

When using a server, `userId` must be a lowercase hex string of at least 32 characters (128-bit entropy minimum). The server rejects shorter or non-hex values.

```js
// Generate once, store in your app's config or user record
const userId = crypto.randomUUID().replace(/-/g, '')
// → "a3f1c29e847d0b5f6a2e91c47d3b8f0e"
```

## Status flow

```
idle
  → enrolling   (enroll() called)
    → enrolled  (success)
    → error     (scanner cancelled or failed)

enrolled
  → authenticating  (authenticate() called)
    → authenticated (success)
    → error         (mismatch, lockout, or server rejection)
```

## Requirements

- React 18+
- HTTPS or localhost
- Platform authenticator (fingerprint sensor, Face ID, Windows Hello)

## License

MIT
