# biokey-react

React hook for BioKey. One hook for fingerprint enrollment and authentication.

## Install

```bash
bun add biokey-react
```

## Usage

```jsx
import { useBioKey } from 'biokey-react'

export function LoginButton() {
	const { identity, status, error, isEnrolled, isLoading, enroll, authenticate, reset } = useBioKey({
		serverUrl: 'https://your-biokey-server.railway.app'
	})

	if (!isEnrolled) {
		return (
			<button onClick={() => enroll('user-123')} disabled={isLoading}>
				{isLoading ? 'Scanning...' : 'Enroll Fingerprint'}
			</button>
		)
	}

	return (
		<div>
			<p>Identity: {identity.publicKey.slice(0, 16)}...</p>
			<button onClick={() => authenticate('user-123')} disabled={isLoading}>
				{isLoading ? 'Verifying...' : 'Authenticate'}
			</button>
			<button onClick={reset}>Reset</button>
			{error && <p style={{ color: 'red' }}>{error}</p>}
		</div>
	)
}
```

## Hook Return Values

| Value | Type | Description |
|---|---|---|
| `identity` | `object \| null` | Stored identity (publicKey, credentialId, deviceId, enrolledAt) |
| `status` | `string` | `idle` / `enrolling` / `enrolled` / `authenticating` / `authenticated` / `error` |
| `error` | `string \| null` | Error message if last action failed |
| `isEnrolled` | `boolean` | Whether an identity is stored |
| `isLoading` | `boolean` | True while enrolling or authenticating |
| `enroll(userId?)` | `function` | Start enrollment |
| `authenticate(userId?)` | `function` | Start authentication |
| `reset()` | `function` | Clear stored identity |

## Requirements

- React 18+
- HTTPS or localhost
- Platform authenticator (fingerprint sensor)
