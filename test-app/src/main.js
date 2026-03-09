import { BioKeyClient } from 'biokey-js'

// ─── Stable userId ────────────────────────────────────────────────────────────
// Generated once per browser, persisted in localStorage.
// Must be a hex string of at least 32 chars (128-bit entropy) — server enforces this.
function getOrCreateUserId() {
	const key = 'biokey_test_userid'
	const existing = localStorage.getItem(key)
	if (existing) return existing
	const bytes = crypto.getRandomValues(new Uint8Array(16))
	const hex = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('')
	localStorage.setItem(key, hex)
	return hex
}

const USER_ID = getOrCreateUserId()

// ─── BioKeyClient ─────────────────────────────────────────────────────────────
// __SERVER_URL__ is injected by vite.config.js at build time.
// Points to the live Convex deployment by default.
// Override with VITE_SERVER_URL env var to switch backends.
const biokey = new BioKeyClient({ serverUrl: __SERVER_URL__ })

// ─── DOM refs ─────────────────────────────────────────────────────────────────
const enrollBtn  = document.getElementById('enroll-btn')
const authBtn    = document.getElementById('auth-btn')
const resetBtn   = document.getElementById('reset-btn')
const statusEl   = document.getElementById('status')
const keyDisplay = document.getElementById('key-display')
const keyValue   = document.getElementById('key-value')
const stateEl    = document.getElementById('state')
const methodEl   = document.getElementById('method-badge')
const serverEl   = document.getElementById('server-badge')

function formatKey(hex) {
	return hex.match(/.{8}/g).join(' ')
}

function setStatus(type, message) {
	statusEl.className = `status ${type}`
	statusEl.textContent = message
	statusEl.style.display = 'block'
}

function hideStatus() {
	statusEl.style.display = 'none'
}

function updateUI() {
	const identity = biokey.getIdentity()
	if (identity) {
		stateEl.textContent  = 'Enrolled'
		stateEl.className    = 'state enrolled'
		keyDisplay.style.display = 'block'
		keyValue.textContent = formatKey(identity.publicKey)
		methodEl.textContent = identity.method === 'prf' ? 'PRF ✓' : 'rawId'
		methodEl.className   = `badge ${identity.method === 'prf' ? 'badge-prf' : 'badge-rawid'}`
		methodEl.style.display = 'inline-block'
		serverEl.textContent = 'Convex'
		serverEl.style.display = 'inline-block'
		enrollBtn.disabled   = true
		enrollBtn.textContent = 'Already Enrolled'
		authBtn.disabled     = false
		resetBtn.style.display = 'inline-block'
	} else {
		stateEl.textContent  = 'Not Enrolled'
		stateEl.className    = 'state'
		keyDisplay.style.display = 'none'
		methodEl.style.display   = 'none'
		serverEl.style.display   = 'none'
		enrollBtn.disabled   = false
		enrollBtn.textContent = 'Enroll Fingerprint'
		authBtn.disabled     = true
		resetBtn.style.display = 'none'
	}
}

// ─── Event listeners ──────────────────────────────────────────────────────────

enrollBtn.addEventListener('click', async () => {
	enrollBtn.disabled = true
	enrollBtn.textContent = 'Waiting for fingerprint...'
	hideStatus()

	try {
		const identity = await biokey.enroll(USER_ID)
		const label = identity.method === 'prf' ? 'PRF (hardware-backed)' : 'rawId (HKDF fallback)'
		setStatus('success', `✓ Enrolled via ${label}. Identity key derived and synced to Convex.`)
		updateUI()
	} catch (err) {
		setStatus('error', `✗ ${err.message}`)
		enrollBtn.disabled = false
		enrollBtn.textContent = 'Enroll Fingerprint'
	}
})

authBtn.addEventListener('click', async () => {
	authBtn.disabled = true
	authBtn.textContent = 'Waiting for fingerprint...'
	hideStatus()

	try {
		const result = await biokey.authenticate(USER_ID)
		setStatus('success', `✓ Authenticated. Server signature verified. Method: ${result.method}`)
	} catch (err) {
		setStatus('error', `✗ ${err.message}`)
	} finally {
		authBtn.disabled = false
		authBtn.textContent = 'Authenticate'
	}
})

resetBtn.addEventListener('click', () => {
	biokey.clearIdentity()
	hideStatus()
	updateUI()
})

updateUI()
